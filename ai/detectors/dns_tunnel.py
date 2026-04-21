"""
Cerberix AI — DNS Tunneling Detector

Detects DNS-based data exfiltration by analyzing:
1. Query length (long subdomain labels = encoded data)
2. Query frequency per domain (rapid queries to same domain)
3. TXT/NULL/MX record type abuse
4. Subdomain entropy patterns
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


@dataclass
class DNSQueryEvent:
    domain: str
    query_type: str  # A, AAAA, TXT, MX, NULL, CNAME
    client_ip: str
    timestamp: float
    response_size: int = 0


@dataclass
class DNSTunnelAlert:
    domain: str
    client_ip: str
    indicators: list
    score: float
    severity: str
    description: str


class DNSTunnelDetector:
    """
    Scores DNS traffic for tunneling characteristics.
    """

    def __init__(self, window_sec: int = 120):
        self.window_sec = window_sec
        # {base_domain: [DNSQueryEvent]}
        self._queries: dict[str, list[DNSQueryEvent]] = defaultdict(list)
        self._alerted: dict[str, float] = {}
        self._cooldown_sec = 600

        # Suspicious record types (commonly abused for tunneling)
        self._suspicious_types = {"TXT", "NULL", "MX", "CNAME"}

    def ingest(self, event: DNSQueryEvent) -> Optional[DNSTunnelAlert]:
        """Analyze a DNS query for tunneling indicators."""
        base_domain = self._extract_base_domain(event.domain)

        if base_domain in self._alerted:
            if event.timestamp - self._alerted[base_domain] < self._cooldown_sec:
                return None

        self._queries[base_domain].append(event)

        # Prune old
        cutoff = event.timestamp - self.window_sec
        self._queries[base_domain] = [
            q for q in self._queries[base_domain] if q.timestamp > cutoff
        ]

        queries = self._queries[base_domain]
        if len(queries) < 5:
            return None

        # ── Score indicators ────────────────────────────────
        indicators = []
        score = 0.0

        # 1. High query frequency to same base domain
        qps = len(queries) / self.window_sec
        if qps > 1.0:
            indicators.append(f"high_frequency={qps:.1f}qps")
            score += min(qps / 5.0, 0.3)

        # 2. Long subdomain labels (encoded data)
        avg_label_len = sum(
            len(q.domain) - len(base_domain) for q in queries
        ) / len(queries)
        if avg_label_len > 30:
            indicators.append(f"long_labels={avg_label_len:.0f}chars")
            score += min(avg_label_len / 100.0, 0.3)

        # 3. Suspicious record types
        type_counts = defaultdict(int)
        for q in queries:
            type_counts[q.query_type] += 1
        suspicious_ratio = sum(
            type_counts.get(t, 0) for t in self._suspicious_types
        ) / len(queries)
        if suspicious_ratio > 0.3:
            indicators.append(f"suspicious_types={suspicious_ratio:.0%}")
            score += suspicious_ratio * 0.2

        # 4. Many unique subdomains (each carries payload)
        unique_subdomains = set(q.domain for q in queries)
        uniqueness = len(unique_subdomains) / len(queries) if queries else 0
        if uniqueness > 0.8 and len(unique_subdomains) > 10:
            indicators.append(f"unique_ratio={uniqueness:.0%}")
            score += uniqueness * 0.2

        # ── Alert threshold ─────────────────────────────────
        if score >= 0.5 and len(indicators) >= 2:
            self._alerted[base_domain] = event.timestamp

            return DNSTunnelAlert(
                domain=base_domain,
                client_ip=event.client_ip,
                indicators=indicators,
                score=round(score, 3),
                severity="critical" if score > 0.75 else "high",
                description=(
                    f"DNS tunneling suspected: {base_domain} from "
                    f"{event.client_ip} ({', '.join(indicators)})"
                ),
            )

        return None

    @staticmethod
    def _extract_base_domain(domain: str) -> str:
        """Extract the base (registered) domain."""
        parts = domain.lower().strip().rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def cleanup(self):
        now = time.time()
        cutoff = now - self.window_sec * 2
        stale = [
            d for d, queries in self._queries.items()
            if not queries or queries[-1].timestamp < cutoff
        ]
        for d in stale:
            del self._queries[d]
        stale_alerts = [
            d for d, ts in self._alerted.items()
            if now - ts > self._cooldown_sec
        ]
        for d in stale_alerts:
            del self._alerted[d]
