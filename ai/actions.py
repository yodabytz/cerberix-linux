"""
Cerberix AI — Automated Response Actions

Executes defensive responses when threats are detected:
- Dynamic nftables blocklist management
- Rate limiting escalation
- Alert logging
- Threat event persistence
"""

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict
from typing import Optional


# IPs that must never be blocked (gateway, DNS, loopback)
_SAFELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

# Max auto-blocks per hour to prevent runaway blocking
_MAX_BLOCKS_PER_HOUR = 50


def _validate_ipv4(ip: str) -> bool:
    """Strict IPv4 validation — no shell metacharacters possible."""
    if not isinstance(ip, str):
        return False
    if not re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))


def _validate_domain(domain: str) -> bool:
    """Strict domain validation."""
    if not isinstance(domain, str) or len(domain) > 253:
        return False
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain))


def _nft_run(args: list[str], timeout: int = 5) -> subprocess.CompletedProcess:
    """Run nft command safely — never uses shell=True."""
    return subprocess.run(
        ["nft"] + args,
        capture_output=True, text=True, timeout=timeout,
    )


@dataclass
class BlockEntry:
    ip: str
    reason: str
    severity: str
    blocked_at: float
    expires_at: float  # 0 = permanent
    detector: str


class ActionEngine:
    """Manages automated threat responses."""

    def __init__(
        self,
        auto_block: bool = True,
        block_duration: int = 3600,
        data_dir: str = "/var/lib/cerberix/ai",
        log_dir: str = "/var/log/cerberix",
    ):
        self.auto_block = auto_block
        self.block_duration = block_duration
        self.data_dir = data_dir
        self.log_dir = log_dir

        self._blocked: dict[str, BlockEntry] = {}
        self._nft_set_initialized = False
        self._block_timestamps: list[float] = []  # Rate limiting

        # Build safelist from env
        self._safelist = set(_SAFELIST)
        lan_ip = os.environ.get("CERBERIX_LAN_IP", "192.168.1.1")
        wg_ip = os.environ.get("CERBERIX_WG_SERVER_IP", "10.100.0.1")
        for ip in [lan_ip, wg_ip, "1.1.1.1", "1.0.0.1"]:
            self._safelist.add(ip)

        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

        self._load_blocklist()
        self._init_nft_set()

    def _init_nft_set(self):
        """Create the nftables dynamic blocklist set and chain."""
        nft_commands = [
            ["add", "table", "inet", "cerberix_ai"],
            ["add", "set", "inet", "cerberix_ai", "blocklist",
             "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
            ["add", "chain", "inet", "cerberix_ai", "ai_block",
             "{", "type", "filter", "hook", "input", "priority", "-5", ";",
             "policy", "accept", ";", "}"],
        ]

        for args in nft_commands:
            try:
                _nft_run(args)
            except (subprocess.SubprocessError, OSError):
                pass

        # Add rules via nft -f to handle complex syntax
        ruleset = (
            'add rule inet cerberix_ai ai_block '
            'ip saddr @blocklist log prefix "[CERBERIX AI BLOCK] " drop\n'
            'add chain inet cerberix_ai ai_block_fwd '
            '{ type filter hook forward priority -5; policy accept; }\n'
            'add rule inet cerberix_ai ai_block_fwd '
            'ip saddr @blocklist log prefix "[CERBERIX AI BLOCK FWD] " drop\n'
        )
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.nft', delete=False) as f:
                f.write(ruleset)
                tmp_path = f.name
            _nft_run(["-f", tmp_path])
            os.unlink(tmp_path)
        except (subprocess.SubprocessError, OSError):
            pass

        self._nft_set_initialized = True

    def block_ip(
        self,
        ip: str,
        reason: str,
        severity: str = "high",
        detector: str = "unknown",
        duration: Optional[int] = None,
    ) -> bool:
        """Add an IP to the dynamic blocklist."""
        # Validate IP
        if not _validate_ipv4(ip):
            self._log_event("block_rejected", ip, f"Invalid IP: {ip}", severity, detector)
            return False

        # Check safelist
        if ip in self._safelist:
            self._log_event("block_rejected", ip, f"Safelisted IP: {ip}", severity, detector)
            return False

        if not self.auto_block:
            self._log_event("block_skipped", ip, reason, severity, detector)
            return False

        if ip in self._blocked:
            return False

        # Rate limit: max N blocks per hour
        now = time.time()
        self._block_timestamps = [t for t in self._block_timestamps if now - t < 3600]
        if len(self._block_timestamps) >= _MAX_BLOCKS_PER_HOUR:
            self._log_event("block_rate_limited", ip, reason, severity, detector)
            return False

        dur = duration if duration is not None else self.block_duration
        if dur < 0:
            dur = self.block_duration
        expires = time.time() + dur if dur > 0 else 0

        entry = BlockEntry(
            ip=ip, reason=reason, severity=severity,
            blocked_at=time.time(), expires_at=expires, detector=detector,
        )

        # Add to nftables — safe argument list, no shell
        nft_args = ["add", "element", "inet", "cerberix_ai", "blocklist",
                     "{", ip]
        if dur > 0:
            nft_args.extend(["timeout", f"{dur}s"])
        nft_args.append("}")

        try:
            result = _nft_run(nft_args)
            if result.returncode != 0:
                self._log_event(
                    "block_failed", ip, reason, severity, detector,
                    extra={"error": result.stderr.strip()},
                )
                return False
        except (subprocess.SubprocessError, OSError) as e:
            self._log_event(
                "block_failed", ip, reason, severity, detector,
                extra={"error": str(e)},
            )
            return False

        self._blocked[ip] = entry
        self._block_timestamps.append(now)
        self._save_blocklist()
        self._log_event("blocked", ip, reason, severity, detector)
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the dynamic blocklist."""
        if not _validate_ipv4(ip):
            return False

        try:
            _nft_run(["delete", "element", "inet", "cerberix_ai", "blocklist",
                       "{", ip, "}"])
        except (subprocess.SubprocessError, OSError):
            pass

        if ip in self._blocked:
            entry = self._blocked.pop(ip)
            self._save_blocklist()
            self._log_event(
                "unblocked", ip, entry.reason, entry.severity, entry.detector
            )
            return True
        return False

    def expire_blocks(self):
        """Remove expired blocks."""
        now = time.time()
        expired = [
            ip for ip, entry in self._blocked.items()
            if entry.expires_at > 0 and entry.expires_at <= now
        ]
        for ip in expired:
            self.unblock_ip(ip)

    def get_blocklist(self) -> list[dict]:
        """Return current blocklist."""
        return [asdict(entry) for entry in self._blocked.values()]

    def block_domain(self, domain: str, reason: str, detector: str = "dga"):
        """Block a domain via dnsmasq (sinkhole to 0.0.0.0)."""
        if not _validate_domain(domain):
            return

        block_file = "/etc/cerberix/dnsmasq.d/ai-blocked.conf"
        line = f"address=/{domain}/0.0.0.0\n"

        try:
            if os.path.exists(block_file):
                with open(block_file) as f:
                    if line in f.read():
                        return

            with open(block_file, "a") as f:
                f.write(f"# Blocked by AI ({detector}): {reason}\n")
                f.write(line)

            subprocess.run(
                ["killall", "-HUP", "dnsmasq"],
                capture_output=True, timeout=5,
            )

            self._log_event("domain_blocked", domain, reason, "high", detector)
        except OSError:
            pass

    def _log_event(
        self,
        action: str,
        target: str,
        reason: str,
        severity: str,
        detector: str,
        extra: Optional[dict] = None,
    ):
        """Log a threat response event."""
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "epoch": time.time(),
            "action": action,
            "target": target,
            "reason": reason,
            "severity": severity,
            "detector": detector,
        }
        if extra:
            event.update(extra)

        log_path = os.path.join(self.log_dir, "ai-threats.log")
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError:
            pass

    def _save_blocklist(self):
        """Atomic write to prevent corruption."""
        path = os.path.join(self.data_dir, "blocklist.json")
        try:
            data = {ip: asdict(entry) for ip, entry in self._blocked.items()}
            tmp_path = path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            os.rename(tmp_path, path)
        except OSError:
            pass

    def _load_blocklist(self):
        path = os.path.join(self.data_dir, "blocklist.json")
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            for ip, entry_data in data.items():
                if not _validate_ipv4(ip):
                    continue
                entry = BlockEntry(**entry_data)
                if entry.expires_at > 0 and entry.expires_at <= time.time():
                    continue
                self._blocked[ip] = entry
                # Re-add to nftables
                remaining = (
                    int(entry.expires_at - time.time())
                    if entry.expires_at > 0
                    else 0
                )
                nft_args = ["add", "element", "inet", "cerberix_ai", "blocklist",
                            "{", ip]
                if remaining > 0:
                    nft_args.extend(["timeout", f"{remaining}s"])
                nft_args.append("}")
                try:
                    _nft_run(nft_args)
                except (subprocess.SubprocessError, OSError):
                    pass
        except (OSError, json.JSONDecodeError, TypeError):
            pass
