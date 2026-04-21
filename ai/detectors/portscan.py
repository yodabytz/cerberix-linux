"""
Cerberix AI — Port Scan Detector

Detects hosts probing multiple ports within a time window.
Uses a sliding window of connection events per source IP.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortScanEvent:
    src_ip: str
    dst_port: int
    timestamp: float
    interface: str = ""


@dataclass
class PortScanAlert:
    src_ip: str
    ports_hit: list
    port_count: int
    window_sec: int
    first_seen: float
    last_seen: float
    severity: str = "high"
    description: str = ""


class PortScanDetector:
    """
    Tracks distinct destination ports per source IP within a sliding window.
    Fires an alert when the count exceeds the threshold.
    """

    def __init__(self, threshold: int = 15, window_sec: int = 60):
        self.threshold = threshold
        self.window_sec = window_sec
        # {src_ip: [(timestamp, dst_port), ...]}
        self._events: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # Track IPs already alerted to avoid spam
        self._alerted: dict[str, float] = {}
        # Cooldown: don't re-alert same IP within this period
        self._cooldown_sec = 300

    def ingest(self, event: PortScanEvent) -> Optional[PortScanAlert]:
        """Ingest a connection event and return alert if threshold crossed."""
        now = event.timestamp
        src = event.src_ip

        # Skip if recently alerted
        if src in self._alerted:
            if now - self._alerted[src] < self._cooldown_sec:
                return None

        # Add event
        self._events[src].append((now, event.dst_port))

        # Prune old events outside window
        cutoff = now - self.window_sec
        self._events[src] = [
            (ts, port) for ts, port in self._events[src] if ts > cutoff
        ]

        # Count distinct ports
        ports = set(port for _, port in self._events[src])

        if len(ports) >= self.threshold:
            self._alerted[src] = now
            timestamps = [ts for ts, _ in self._events[src]]
            alert = PortScanAlert(
                src_ip=src,
                ports_hit=sorted(ports),
                port_count=len(ports),
                window_sec=self.window_sec,
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                severity="high" if len(ports) > self.threshold * 2 else "medium",
                description=(
                    f"Port scan detected from {src}: "
                    f"{len(ports)} distinct ports in {self.window_sec}s"
                ),
            )
            # Clear events for this IP after alert
            self._events[src] = []
            return alert

        return None

    def cleanup(self):
        """Remove stale entries to prevent memory growth."""
        now = time.time()
        cutoff = now - self.window_sec * 2
        stale_ips = [
            ip for ip, events in self._events.items()
            if not events or events[-1][0] < cutoff
        ]
        for ip in stale_ips:
            del self._events[ip]

        stale_alerts = [
            ip for ip, ts in self._alerted.items()
            if now - ts > self._cooldown_sec
        ]
        for ip in stale_alerts:
            del self._alerted[ip]
