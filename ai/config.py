"""
Cerberix AI — Configuration
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AIConfig:
    """AI engine configuration — all values overridable via environment."""

    # ── Claude API ──────────────────────────────────────────
    claude_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("CERBERIX_AI_API_KEY")
    )
    claude_model: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_MODEL", "claude-sonnet-4-6"
        )
    )
    claude_enabled: bool = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_ENABLED", "true"
        ).lower() == "true"
    )

    # ── Detection Thresholds ────────────────────────────────
    # Port scan: connections from single IP to N distinct ports in window
    portscan_threshold: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_PORTSCAN_THRESHOLD", "15")
        )
    )
    portscan_window_sec: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_PORTSCAN_WINDOW", "60")
        )
    )

    # Brute force: failed connections from single IP in window
    bruteforce_threshold: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_BRUTEFORCE_THRESHOLD", "10")
        )
    )
    bruteforce_window_sec: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_BRUTEFORCE_WINDOW", "120")
        )
    )

    # DGA detection: entropy threshold for suspicious domains
    dga_entropy_threshold: float = field(
        default_factory=lambda: float(
            os.environ.get("CERBERIX_AI_DGA_ENTROPY", "3.5")
        )
    )

    # Traffic anomaly: standard deviations from baseline
    anomaly_std_threshold: float = field(
        default_factory=lambda: float(
            os.environ.get("CERBERIX_AI_ANOMALY_STD", "3.0")
        )
    )

    # ── Auto-Response ───────────────────────────────────────
    auto_block_enabled: bool = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_AUTO_BLOCK", "true"
        ).lower() == "true"
    )
    # How long to auto-block an IP (seconds), 0 = permanent
    auto_block_duration: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_BLOCK_DURATION", "3600")
        )
    )

    # ── Paths ───────────────────────────────────────────────
    log_dir: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_LOG_DIR", "/var/log/cerberix"
        )
    )
    data_dir: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_DATA_DIR", "/var/lib/cerberix/ai"
        )
    )
    firewall_log: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_FW_LOG", "/var/log/cerberix/firewall.log"
        )
    )
    dns_log: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_AI_DNS_LOG", "/var/log/cerberix/dnsmasq.log"
        )
    )

    # ── Engine ──────────────────────────────────────────────
    analysis_interval_sec: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_INTERVAL", "30")
        )
    )
    # Max events to buffer before forced analysis
    max_event_buffer: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_MAX_BUFFER", "1000")
        )
    )
    # How often to call Claude for deep analysis (seconds)
    deep_analysis_interval: int = field(
        default_factory=lambda: int(
            os.environ.get("CERBERIX_AI_DEEP_INTERVAL", "300")
        )
    )

    # ── Network ─────────────────────────────────────────────
    wan_interface: str = field(
        default_factory=lambda: os.environ.get("CERBERIX_WAN_IF", "eth0")
    )
    lan_interface: str = field(
        default_factory=lambda: os.environ.get("CERBERIX_LAN_IF", "eth1")
    )
    lan_subnet: str = field(
        default_factory=lambda: os.environ.get(
            "CERBERIX_LAN_SUBNET", "192.168.1.0/24"
        )
    )
