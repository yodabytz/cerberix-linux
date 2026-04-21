"""
Cerberix AI — Main Threat Detection Engine

Orchestrates all detectors, log parsing, auto-response, and Claude analysis.
Runs as a background daemon within the Cerberix appliance.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ai.config import AIConfig
from ai.log_parser import LogParser
from ai.actions import ActionEngine
from ai.claude_analyzer import ClaudeAnalyzer
from ai.detectors.portscan import PortScanDetector
from ai.detectors.bruteforce import BruteForceDetector
from ai.detectors.dga import DGADetector
from ai.detectors.dns_tunnel import DNSTunnelDetector
from ai.detectors.anomaly import TrafficAnomalyDetector, TrafficSnapshot
from ai.monitors.bandwidth import BandwidthMonitor
from ai.monitors.arp_watch import ARPWatcher
from ai.monitors.suricata import SuricataMonitor
from ai.notifications import NotificationEngine
from ai.daily_report import DailyReportGenerator

# ── Logging ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[cerberix-ai] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cerberix-ai")


class CerberixAIEngine:
    """
    Main engine that ties everything together.

    Pipeline:
        Log files → Parser → Detectors → Alerts → Actions
                                                  → Claude (periodic/critical)
    """

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self._running = False
        self._lock = threading.Lock()

        # ── Initialize components ───────────────────────────
        self.parser = LogParser()

        self.portscan = PortScanDetector(
            threshold=self.config.portscan_threshold,
            window_sec=self.config.portscan_window_sec,
        )
        self.bruteforce = BruteForceDetector(
            threshold=self.config.bruteforce_threshold,
            window_sec=self.config.bruteforce_window_sec,
        )
        self.dga = DGADetector(
            entropy_threshold=self.config.dga_entropy_threshold,
        )
        self.dns_tunnel = DNSTunnelDetector()
        self.anomaly = TrafficAnomalyDetector(
            std_threshold=self.config.anomaly_std_threshold,
            data_dir=self.config.data_dir,
        )

        self.actions = ActionEngine(
            auto_block=self.config.auto_block_enabled,
            block_duration=self.config.auto_block_duration,
            data_dir=self.config.data_dir,
            log_dir=self.config.log_dir,
        )

        self.claude = ClaudeAnalyzer(
            api_key=self.config.claude_api_key,
            model=self.config.claude_model,
            log_dir=self.config.log_dir,
        )

        # ── System monitors ─────────────────────────────────
        self.bandwidth = BandwidthMonitor(data_dir=self.config.data_dir)
        self.arp_watch = ARPWatcher(data_dir=self.config.data_dir)
        self.suricata = SuricataMonitor(data_dir=self.config.data_dir)
        self.notifications = NotificationEngine()
        self.daily_report = DailyReportGenerator(
            claude_analyzer=self.claude,
            notification_engine=self.notifications,
        )

        # ── State tracking ──────────────────────────────────
        self._fw_log_pos = 0
        self._dns_log_pos = 0
        self._stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "ips_blocked": 0,
            "domains_blocked": 0,
            "claude_analyses": 0,
            "start_time": 0.0,
        }

        os.makedirs(self.config.data_dir, exist_ok=True)

    def start(self):
        """Start the AI engine."""
        self._running = True
        self._stats["start_time"] = time.time()

        log.info("=" * 50)
        log.info("Cerberix AI Threat Engine starting")
        log.info(f"  Claude API: {'enabled' if self.claude.available else 'disabled (local only)'}")
        log.info(f"  Auto-block: {'enabled' if self.config.auto_block_enabled else 'disabled'}")
        log.info(f"  Block duration: {self.config.auto_block_duration}s")
        log.info(f"  Analysis interval: {self.config.analysis_interval_sec}s")
        log.info(f"  Detectors: portscan, bruteforce, dga, dns_tunnel, anomaly")
        log.info(f"  Monitors: bandwidth, arp_watch")
        log.info("=" * 50)

        # Signal handling
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Start system monitors
        self.bandwidth.start()
        self.arp_watch.start()
        self.suricata.start()
        log.info("  Started monitor: bandwidth")
        log.info("  Started monitor: arp_watch")
        log.info("  Started monitor: suricata")

        # Start worker threads
        threads = [
            threading.Thread(
                target=self._firewall_log_watcher,
                name="fw-watcher",
                daemon=True,
            ),
            threading.Thread(
                target=self._dns_log_watcher,
                name="dns-watcher",
                daemon=True,
            ),
            threading.Thread(
                target=self._traffic_monitor,
                name="traffic-monitor",
                daemon=True,
            ),
            threading.Thread(
                target=self._maintenance_loop,
                name="maintenance",
                daemon=True,
            ),
            threading.Thread(
                target=self._remote_log_watcher,
                name="remote-watcher",
                daemon=True,
            ),
        ]

        if self.claude.available:
            threads.append(
                threading.Thread(
                    target=self._claude_analysis_loop,
                    name="claude-analyzer",
                    daemon=True,
                )
            )

        for t in threads:
            t.start()
            log.info(f"  Started thread: {t.name}")

        # Main loop — keep alive
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        self.stop()

    def stop(self):
        """Stop the engine gracefully."""
        log.info("Shutting down Cerberix AI Engine...")
        self._running = False
        self._save_stats()
        log.info("AI Engine stopped.")

    def _handle_signal(self, signum, frame):
        self._running = False

    # ── Log Watchers ────────────────────────────────────────

    def _firewall_log_watcher(self):
        """Tail the firewall log and feed events to detectors."""
        log_path = self.config.firewall_log
        log.info(f"Watching firewall log: {log_path}")

        while self._running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(5)
                    continue

                with open(log_path) as f:
                    f.seek(self._fw_log_pos)

                    while self._running:
                        line = f.readline()
                        if not line:
                            self._fw_log_pos = f.tell()
                            time.sleep(0.5)
                            # Check for file rotation
                            try:
                                if os.path.getsize(log_path) < self._fw_log_pos:
                                    self._fw_log_pos = 0
                                    break
                            except OSError:
                                break
                            continue

                        self._process_firewall_line(line)

            except OSError as e:
                log.warning(f"Firewall log error: {e}")
                time.sleep(5)

    def _dns_log_watcher(self):
        """Tail the DNS log and feed events to detectors."""
        log_path = self.config.dns_log
        log.info(f"Watching DNS log: {log_path}")

        while self._running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(5)
                    continue

                with open(log_path) as f:
                    f.seek(self._dns_log_pos)

                    while self._running:
                        line = f.readline()
                        if not line:
                            self._dns_log_pos = f.tell()
                            time.sleep(0.5)
                            try:
                                if os.path.getsize(log_path) < self._dns_log_pos:
                                    self._dns_log_pos = 0
                                    break
                            except OSError:
                                break
                            continue

                        self._process_dns_line(line)

            except OSError as e:
                log.warning(f"DNS log error: {e}")
                time.sleep(5)

    def _process_firewall_line(self, line: str):
        """Process a single firewall log line through all relevant detectors."""
        event = self.parser.parse_firewall_line(line)
        if not event:
            return

        self._stats["events_processed"] += 1

        # ── Port Scan Detection ─────────────────────────────
        ps_event = self.parser.firewall_to_portscan(event)
        ps_alert = self.portscan.ingest(ps_event)
        if ps_alert:
            self._handle_alert("portscan", asdict(ps_alert))

        # ── Brute Force Detection ───────────────────────────
        bf_event = self.parser.firewall_to_bruteforce(event)
        bf_alert = self.bruteforce.ingest(bf_event)
        if bf_alert:
            self._handle_alert("bruteforce", asdict(bf_alert))

    def _process_dns_line(self, line: str):
        """Process a single DNS log line through DNS detectors."""
        dns_event = self.parser.parse_dns_line(line)
        if not dns_event:
            return

        self._stats["events_processed"] += 1

        # ── DGA Detection ───────────────────────────────────
        dga_alert = self.dga.analyze(dns_event.domain, dns_event.client_ip)
        if dga_alert:
            self._handle_alert("dga", asdict(dga_alert))

        # ── DNS Tunneling Detection ─────────────────────────
        tunnel_alert = self.dns_tunnel.ingest(dns_event)
        if tunnel_alert:
            self._handle_alert("dns_tunnel", asdict(tunnel_alert))

    # ── Traffic Monitor ─────────────────────────────────────

    def _traffic_monitor(self):
        """Collect traffic stats and feed to anomaly detector."""
        log.info("Traffic anomaly monitor started")

        while self._running:
            try:
                snapshot = self._collect_traffic_snapshot()
                if snapshot:
                    alerts = self.anomaly.ingest(snapshot)
                    for alert in alerts:
                        self._handle_alert("anomaly", asdict(alert))
            except Exception as e:
                log.warning(f"Traffic monitor error: {e}")

            time.sleep(self.config.analysis_interval_sec)

    def _collect_traffic_snapshot(self) -> Optional[TrafficSnapshot]:
        """Collect current traffic metrics from system."""
        try:
            # Connection count from conntrack
            conn_count = 0
            try:
                result = subprocess.run(
                    ["cat", "/proc/sys/net/netfilter/nf_conntrack_count"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    conn_count = int(result.stdout.strip())
            except (subprocess.SubprocessError, ValueError):
                pass

            # Interface bytes from /proc/net/dev
            bytes_total = 0
            try:
                with open("/proc/net/dev") as f:
                    for devline in f:
                        if self.config.wan_interface in devline:
                            parts = devline.split()
                            bytes_total = int(parts[1]) + int(parts[9])
            except (OSError, IndexError, ValueError):
                pass

            # nftables counter for dropped packets
            dropped = 0
            try:
                result = subprocess.run(
                    ["nft", "list", "ruleset"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    import re
                    drops = re.findall(
                        r"packets (\d+) bytes \d+.*drop",
                        result.stdout,
                    )
                    dropped = sum(int(d) for d in drops)
            except (subprocess.SubprocessError, ValueError):
                pass

            return TrafficSnapshot(
                timestamp=time.time(),
                connections_per_sec=float(conn_count),
                bytes_per_sec=float(bytes_total),
                unique_src_ips=0,  # Populated from conntrack in production
                unique_dst_ports=0,
                dropped_packets=dropped,
                dns_queries_per_sec=0.0,
            )

        except Exception:
            return None

    # ── Alert Handling ──────────────────────────────────────

    def _handle_alert(self, detector: str, alert: dict):
        """Central alert handler — log, respond, notify, and buffer for Claude."""
        self._stats["alerts_generated"] += 1
        alert["detector"] = detector
        alert["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        severity = alert.get("severity", "medium")
        description = alert.get("description", "Unknown alert")

        # Always log to threat log with all fields
        import json as _json
        src_ip = alert.get("src_ip") or alert.get("client_ip") or ""
        threat_entry = {
            "timestamp": alert["timestamp"],
            "epoch": time.time(),
            "action": "alert",
            "target": src_ip,
            "server": alert.get("server", ""),
            "server_ip": alert.get("server_ip", ""),
            "domain": alert.get("domain", ""),
            "reason": description,
            "severity": severity,
            "detector": detector,
        }
        try:
            with open(os.path.join(self.config.log_dir, "ai-threats.log"), "a") as f:
                f.write(_json.dumps(threat_entry) + "\n")
        except OSError:
            pass

        # Send notification
        self.notifications.notify(alert)

        log.warning(f"[{severity.upper()}] [{detector}] {description}")

        # ── Auto-response ───────────────────────────────────
        src_ip = alert.get("src_ip") or alert.get("client_ip")

        if src_ip and severity in ("critical", "high"):
            blocked = self.actions.block_ip(
                ip=src_ip,
                reason=description,
                severity=severity,
                detector=detector,
            )
            if blocked:
                self._stats["ips_blocked"] += 1
                log.warning(f"AUTO-BLOCKED: {src_ip} ({detector}: {description})")

        # Block DGA domains
        if detector == "dga" and alert.get("domain"):
            self.actions.block_domain(
                domain=alert["domain"],
                reason=description,
                detector=detector,
            )
            self._stats["domains_blocked"] += 1
            log.warning(f"DOMAIN SINKHOLED: {alert['domain']}")

        # Buffer for Claude analysis
        if self.claude.available:
            self.claude.buffer_event(alert)

            # Immediate Claude analysis for critical alerts
            if severity == "critical":
                result = self.claude.analyze_threat(
                    [alert],
                    context=self._get_network_context(),
                )
                if result:
                    self._stats["claude_analyses"] += 1
                    self._execute_claude_recommendations(result)

    def _execute_claude_recommendations(self, analysis: dict):
        """Execute recommendations from Claude analysis with validation."""
        recommendations = analysis.get("recommendations", [])
        assessment = analysis.get("threat_assessment", "unknown")

        if assessment == "false_positive":
            log.info(f"Claude says false positive: {analysis.get('summary')}")
            return

        # Rate limit: max 5 Claude-recommended actions per analysis
        max_actions = 5
        executed = 0

        for rec in recommendations:
            if executed >= max_actions:
                log.warning("Claude recommendation limit reached — skipping remaining")
                break

            action = rec.get("action")
            target = rec.get("target")
            reason = rec.get("reason", "Claude recommendation")

            if not action or not target:
                continue

            # Sanitize reason (prevent log injection)
            reason = reason[:200].replace("\n", " ").replace("\r", "")

            if action == "block_ip":
                # block_ip now validates internally (safelist, format check)
                blocked = self.actions.block_ip(
                    ip=target, reason=reason,
                    severity=assessment, detector="claude",
                )
                if blocked:
                    executed += 1
            elif action == "block_domain":
                # block_domain now validates internally
                self.actions.block_domain(
                    domain=target, reason=reason, detector="claude",
                )
                executed += 1
            elif action in ("add_rule", "rate_limit", "monitor"):
                # These are NEVER auto-executed — log only for human review
                log.info(f"Claude suggests ({action}): {target} — {reason}")
            else:
                log.warning(f"Unknown Claude action ignored: {action}")
                continue

            log.info(f"Claude recommendation: {action} -> {target} ({reason})")

    # ── Claude Periodic Analysis ────────────────────────────

    def _claude_analysis_loop(self):
        """Periodic deep analysis via Claude."""
        log.info(
            f"Claude deep analysis loop started "
            f"(interval: {self.config.deep_analysis_interval}s)"
        )

        while self._running:
            time.sleep(self.config.deep_analysis_interval)

            if not self._running:
                break

            result = self.claude.analyze_periodic(
                interval_sec=self.config.deep_analysis_interval,
            )
            if result:
                self._stats["claude_analyses"] += 1
                log.info(
                    f"Claude periodic analysis: {result.get('summary', 'N/A')}"
                )
                self._execute_claude_recommendations(result)

    # ── Remote Host Log Watcher ──────────────────────────────

    def _remote_log_watcher(self):
        """Watch aggregated syslog from remote hosts for attacks."""
        import re
        log_path = "/var/log/cerberix/hosts/remote.log"
        log.info(f"Watching remote host logs: {log_path}")

        # Patterns that indicate attacks
        patterns = [
            (re.compile(r'Invalid user (\S+) from ([\d.]+)'), "ssh_invalid_user", "high"),
            (re.compile(r'Failed password for .* from ([\d.]+)'), "ssh_failed_password", "high"),
            (re.compile(r'authentication failed.*rhost=([\d.]+)'), "auth_failed", "high"),
            (re.compile(r'NOQUEUE: reject.*from.*\[([\d.]+)\]'), "smtp_reject", "medium"),
            (re.compile(r'warning:.*\[([\d.]+)\]: SASL .* authentication failed'), "smtp_auth_failed", "high"),
            (re.compile(r'auth failed.*rip=([\d.]+)'), "imap_auth_failed", "high"),
            (re.compile(r'Connection closed by .*invalid user .* ([\d.]+)'), "ssh_invalid_close", "medium"),
            # ModSecurity WAF alerts
            (re.compile(r'ModSecurity:.*\[client ([\d.]+)\]'), "modsec_alert", "high"),
            (re.compile(r'client: ([\d.]+).*ModSecurity'), "modsec_block", "high"),
            (re.compile(r'"([\d.]+)".*\[id "(\d+)"'), "modsec_rule", "medium"),
        ]

        # Extract hostname from syslog line: "2026-... hostname service[pid]: ..."
        hostname_re = re.compile(r'^\S+\s+(\S+)\s+')

        # Map hostnames to display names and IPs
        host_ip_map = {
            "mail": "50.21.187.13",
            "vibrixmedia": "54.39.90.215",
        }
        host_display_map = {
            "mail": "quantumbytz.com",
            "vibrixmedia": "vibrixmedia.com",
        }

        file_pos = 0
        while self._running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(5)
                    continue

                with open(log_path) as f:
                    f.seek(file_pos)
                    while self._running:
                        line = f.readline()
                        if not line:
                            file_pos = f.tell()
                            try:
                                if os.path.getsize(log_path) < file_pos:
                                    file_pos = 0
                                    break
                            except OSError:
                                break
                            time.sleep(0.5)
                            continue

                        self._stats["events_processed"] += 1

                        for pattern, detector, severity in patterns:
                            match = pattern.search(line)
                            if match:
                                ip = match.group(match.lastindex)

                                # Extract which server was attacked
                                host_match = hostname_re.search(line)
                                raw_host = host_match.group(1) if host_match else "unknown"
                                server_name = host_display_map.get(raw_host, raw_host)
                                server_ip = host_ip_map.get(raw_host, raw_host)

                                # Try to extract target domain from log line
                                domain = ""
                                domain_match = re.search(r'host:\s*(\S+)', line, re.IGNORECASE)
                                if domain_match:
                                    domain = domain_match.group(1)

                                alert = {
                                    "src_ip": ip,
                                    "severity": severity,
                                    "server": server_name,
                                    "server_ip": server_ip,
                                    "domain": domain,
                                    "description": (
                                        f"[{server_name}/{server_ip}]"
                                        f"{' ('+domain+')' if domain else ''} "
                                        f"{line.strip()[:100]}"
                                    ),
                                }
                                self._handle_alert(f"remote_{detector}", alert)
                                break

            except OSError as e:
                log.warning(f"Remote log error: {e}")
                time.sleep(5)

    # ── Maintenance ─────────────────────────────────────────

    def _maintenance_loop(self):
        """Periodic cleanup and stats reporting."""
        while self._running:
            time.sleep(60)

            # Cleanup detector state
            self.portscan.cleanup()
            self.bruteforce.cleanup()
            self.dns_tunnel.cleanup()

            # Expire old blocks
            self.actions.expire_blocks()

            # Log stats every 5 minutes
            uptime = time.time() - self._stats["start_time"]
            if int(uptime) % 300 < 60:
                self._log_stats()

            # Generate daily report at midnight (check every minute)
            current_hour = time.strftime("%H:%M")
            if current_hour == "00:00":
                try:
                    self.daily_report.generate()
                except Exception as e:
                    log.warning(f"Daily report failed: {e}")

    def _log_stats(self):
        uptime = time.time() - self._stats["start_time"]
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        log.info(
            f"Stats: uptime={hours}h{minutes}m "
            f"events={self._stats['events_processed']} "
            f"alerts={self._stats['alerts_generated']} "
            f"blocked_ips={self._stats['ips_blocked']} "
            f"blocked_domains={self._stats['domains_blocked']} "
            f"claude_analyses={self._stats['claude_analyses']}"
        )

    def _save_stats(self):
        path = os.path.join(self.config.data_dir, "engine_stats.json")
        try:
            with open(path, "w") as f:
                json.dump(self._stats, f, indent=2)
        except OSError:
            pass

    def _get_network_context(self) -> dict:
        """Get current network context for Claude analysis."""
        return {
            "wan_interface": self.config.wan_interface,
            "lan_interface": self.config.lan_interface,
            "lan_subnet": self.config.lan_subnet,
            "active_blocks": len(self.actions.get_blocklist()),
            "uptime_sec": time.time() - self._stats["start_time"],
            "total_events": self._stats["events_processed"],
        }


# ── Entry point ─────────────────────────────────────────────
def main():
    config = AIConfig()

    if not config.claude_enabled:
        log.info("AI engine disabled via CERBERIX_AI_ENABLED=false")
        # Still run — just without Claude
        log.info("Running in local-only mode (all detectors active)")

    engine = CerberixAIEngine(config)
    engine.start()


if __name__ == "__main__":
    main()
