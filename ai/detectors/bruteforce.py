"""
Cerberix AI — Brute Force Detector

Detects repeated connection attempts to the same port from a single source,
indicating password brute force or service enumeration.
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


@dataclass
class BruteForceEvent:
    src_ip: str
    dst_port: int
    timestamp: float
    action: str = "drop"  # "drop" or "reject" from firewall log


@dataclass
class BruteForceAlert:
    src_ip: str
    dst_port: int
    attempt_count: int
    window_sec: int
    first_seen: float
    last_seen: float
    severity: str = "high"
    description: str = ""


class BruteForceDetector:
    """
    Tracks repeated blocked connections to the same port from a single source.
    """

    def __init__(self, threshold: int = 10, window_sec: int = 120):
        self.threshold = threshold
        self.window_sec = window_sec
        # {(src_ip, dst_port): [timestamps]}
        self._events: dict[tuple[str, int], list[float]] = defaultdict(list)
        self._alerted: dict[tuple[str, int], float] = {}
        self._cooldown_sec = 600

    def ingest(self, event: BruteForceEvent) -> Optional[BruteForceAlert]:
        """Ingest a blocked connection event."""
        now = event.timestamp
        key = (event.src_ip, event.dst_port)

        if key in self._alerted:
            if now - self._alerted[key] < self._cooldown_sec:
                return None

        self._events[key].append(now)

        # Prune outside window
        cutoff = now - self.window_sec
        self._events[key] = [ts for ts in self._events[key] if ts > cutoff]

        count = len(self._events[key])

        if count >= self.threshold:
            self._alerted[key] = now
            port_name = self._port_service(event.dst_port)
            alert = BruteForceAlert(
                src_ip=event.src_ip,
                dst_port=event.dst_port,
                attempt_count=count,
                window_sec=self.window_sec,
                first_seen=self._events[key][0],
                last_seen=self._events[key][-1],
                severity="critical" if event.dst_port == 22 else "high",
                description=(
                    f"Brute force detected from {event.src_ip} → "
                    f"port {event.dst_port} ({port_name}): "
                    f"{count} attempts in {self.window_sec}s"
                ),
            )
            self._events[key] = []
            return alert

        return None

    @staticmethod
    def _port_service(port: int) -> str:
        services = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
            443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        return services.get(port, "unknown")

    def cleanup(self):
        now = time.time()
        cutoff = now - self.window_sec * 2
        stale = [
            k for k, events in self._events.items()
            if not events or events[-1] < cutoff
        ]
        for k in stale:
            del self._events[k]
        stale_alerts = [
            k for k, ts in self._alerted.items()
            if now - ts > self._cooldown_sec
        ]
        for k in stale_alerts:
            del self._alerted[k]
