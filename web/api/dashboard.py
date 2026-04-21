"""
Cerberix Web API — Dashboard
Aggregated stats for the main dashboard view.
"""

import json
import os
import subprocess
import time

DATA_DIR = "/var/lib/cerberix/ai"
LOG_DIR = "/var/log/cerberix"


def get_dashboard():
    """Return aggregated dashboard data."""
    stats = _read_json(f"{DATA_DIR}/engine_stats.json", {})
    blocklist = _read_json(f"{DATA_DIR}/blocklist.json", {})
    baseline = _read_json(f"{DATA_DIR}/traffic_baseline.json", [])

    # Count today's threats
    threats_today = 0
    threat_types = {}
    threats_log = f"{LOG_DIR}/ai-threats.log"
    today = time.strftime("%Y-%m-%d")
    recent_threats = []
    if os.path.exists(threats_log):
        try:
            with open(threats_log) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        ts = entry.get("timestamp", "")
                        if ts.startswith(today):
                            threats_today += 1
                        detector = entry.get("detector", "unknown")
                        threat_types[detector] = threat_types.get(detector, 0) + 1
                        recent_threats.append(entry)
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass

    # Connection count
    conn_count = 0
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            conn_count = int(f.read().strip())
    except (OSError, ValueError):
        pass

    # DNS queries (count lines with "query" in dnsmasq log)
    dns_queries = 0
    dns_log = f"{LOG_DIR}/dnsmasq.log"
    if os.path.exists(dns_log):
        try:
            result = subprocess.run(
                ["grep", "-c", "query\\[", dns_log],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                dns_queries = int(result.stdout.strip())
        except (subprocess.SubprocessError, ValueError):
            pass

    # Traffic timeline from bandwidth history
    traffic_timeline = []
    bw_history = _read_json(f"{DATA_DIR}/bandwidth_history.json", [])
    for entry in bw_history[-120:]:
        total_rx = 0
        total_tx = 0
        for iface_data in (entry.get("interfaces") or {}).values():
            rx = iface_data.get("rx_bps", 0)
            tx = iface_data.get("tx_bps", 0)
            # Fall back to packet rate if bps is 0
            if rx == 0:
                rx = iface_data.get("rx_pps", 0) * 100
            if tx == 0:
                tx = iface_data.get("tx_pps", 0) * 100
            total_rx += rx
            total_tx += tx
        traffic_timeline.append({
            "timestamp": entry.get("timestamp", 0),
            "rx_bps": total_rx,
            "tx_bps": total_tx,
            "connections": conn_count,
            "dropped": baseline[-1].get("dropped_packets", 0) if baseline else 0,
        })

    # Uptime
    uptime_sec = 0
    if stats.get("start_time"):
        uptime_sec = int(time.time() - stats["start_time"])

    return {
        "stats": {
            "threats_today": threats_today,
            "blocked_ips": len(blocklist),
            "connections": conn_count,
            "dns_queries": dns_queries,
            "events_processed": stats.get("events_processed", 0),
            "alerts_total": stats.get("alerts_generated", 0),
            "uptime_sec": uptime_sec,
        },
        "threat_types": threat_types,
        "traffic_timeline": traffic_timeline,
        "recent_threats": recent_threats[-10:][::-1],
        "blocked_list": [
            {"ip": ip, **data}
            for ip, data in list(blocklist.items())[:20]
        ],
    }


def _read_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default
