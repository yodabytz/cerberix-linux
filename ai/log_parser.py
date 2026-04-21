"""
Cerberix AI — Log Parser

Parses nftables firewall logs and dnsmasq logs into structured events
for the detection engine.
"""

import re
import time
from dataclasses import dataclass
from typing import Optional

from ai.detectors.portscan import PortScanEvent
from ai.detectors.bruteforce import BruteForceEvent
from ai.detectors.dns_tunnel import DNSQueryEvent


# ── nftables log patterns ───────────────────────────────────
# Example: [CERBERIX DROP IN] IN=eth0 OUT= MAC=... SRC=10.0.0.5 DST=192.168.1.1
#          LEN=40 ... PROTO=TCP SPT=54321 DPT=22 ...
NFT_LOG_RE = re.compile(
    r"\[CERBERIX (?P<action>\w+)(?:\s+\w+)?\]\s+"
    r".*?SRC=(?P<src_ip>[\d.]+)\s+"
    r".*?DST=(?P<dst_ip>[\d.]+)\s+"
    r".*?PROTO=(?P<proto>\w+)\s+"
    r".*?SPT=(?P<spt>\d+)\s+"
    r".*?DPT=(?P<dpt>\d+)"
)

# Simpler pattern for kernel-style log
NFT_LOG_SIMPLE_RE = re.compile(
    r"SRC=(?P<src_ip>[\d.]+).*?"
    r"DST=(?P<dst_ip>[\d.]+).*?"
    r"PROTO=(?P<proto>\w+).*?"
    r"(?:SPT=(?P<spt>\d+))?.*?"
    r"(?:DPT=(?P<dpt>\d+))?"
)

# ── dnsmasq log patterns ───────────────────────────────────
# Example: query[A] google.com from 192.168.1.50
DNSMASQ_QUERY_RE = re.compile(
    r"query\[(?P<qtype>[A-Z]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>[\d.]+)"
)

# Example: reply google.com is 142.250.80.46
DNSMASQ_REPLY_RE = re.compile(
    r"reply\s+(?P<domain>\S+)\s+is\s+(?P<answer>\S+)"
)

# Example: forwarded google.com to 1.1.1.1
DNSMASQ_FWD_RE = re.compile(
    r"forwarded\s+(?P<domain>\S+)\s+to\s+(?P<upstream>[\d.]+)"
)


@dataclass
class ParsedFirewallEvent:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    action: str
    timestamp: float
    raw_line: str


class LogParser:
    """Parses firewall and DNS logs into detection-ready events."""

    def parse_firewall_line(self, line: str) -> Optional[ParsedFirewallEvent]:
        """Parse a single nftables log line."""
        match = NFT_LOG_RE.search(line)
        if not match:
            match = NFT_LOG_SIMPLE_RE.search(line)
            if not match:
                return None

        groups = match.groupdict()
        action = groups.get("action", "DROP")

        try:
            return ParsedFirewallEvent(
                src_ip=groups["src_ip"],
                dst_ip=groups["dst_ip"],
                src_port=int(groups.get("spt") or 0),
                dst_port=int(groups.get("dpt") or 0),
                protocol=groups.get("proto", "TCP"),
                action=action.lower(),
                timestamp=time.time(),
                raw_line=line.strip(),
            )
        except (KeyError, ValueError):
            return None

    def firewall_to_portscan(
        self, event: ParsedFirewallEvent
    ) -> PortScanEvent:
        """Convert firewall event to port scan event."""
        return PortScanEvent(
            src_ip=event.src_ip,
            dst_port=event.dst_port,
            timestamp=event.timestamp,
            interface="",
        )

    def firewall_to_bruteforce(
        self, event: ParsedFirewallEvent
    ) -> BruteForceEvent:
        """Convert firewall event to brute force event."""
        return BruteForceEvent(
            src_ip=event.src_ip,
            dst_port=event.dst_port,
            timestamp=event.timestamp,
            action=event.action,
        )

    def parse_dns_line(self, line: str) -> Optional[DNSQueryEvent]:
        """Parse a dnsmasq log line into a DNS query event."""
        match = DNSMASQ_QUERY_RE.search(line)
        if not match:
            return None

        return DNSQueryEvent(
            domain=match.group("domain"),
            query_type=match.group("qtype"),
            client_ip=match.group("client"),
            timestamp=time.time(),
        )
