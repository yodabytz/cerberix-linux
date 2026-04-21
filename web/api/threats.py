"""
Cerberix Web API — AI Threats & Blocklist
"""

import json
import os
import subprocess
import re

DATA_DIR = "/var/lib/cerberix/ai"
LOG_DIR = "/var/log/cerberix"


def get_recent(limit: int = 50):
    """Get recent threat alerts."""
    threats = []
    log_path = f"{LOG_DIR}/ai-threats.log"
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                for line in f:
                    try:
                        threats.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
    return {"threats": threats[-limit:][::-1]}


def get_stats():
    """Get AI engine stats."""
    stats = _read_json(f"{DATA_DIR}/engine_stats.json", {})
    # Check if engine is running
    running = False
    try:
        result = subprocess.run(
            ["pgrep", "-f", "ai.engine"],
            capture_output=True, timeout=5,
        )
        running = result.returncode == 0
    except subprocess.SubprocessError:
        pass

    stats["running"] = running
    return stats


def get_blocklist():
    """Get current blocklist."""
    bl = _read_json(f"{DATA_DIR}/blocklist.json", {})
    entries = []
    for ip, data in bl.items():
        entries.append({"ip": ip, **data})
    return {"blocklist": entries}


def unblock_ip(ip: str):
    """Unblock an IP address."""
    if not _validate_ip(ip):
        return {"success": False, "error": "Invalid IP"}

    # Remove from nftables
    try:
        subprocess.run(
            ["nft", "delete", "element", "inet", "cerberix_ai", "blocklist",
             "{", ip, "}"],
            capture_output=True, timeout=5,
        )
    except subprocess.SubprocessError:
        pass

    # Remove from JSON
    bl = _read_json(f"{DATA_DIR}/blocklist.json", {})
    if ip in bl:
        del bl[ip]
        try:
            with open(f"{DATA_DIR}/blocklist.json", "w") as f:
                json.dump(bl, f, indent=2)
        except OSError:
            pass

    return {"success": True}


def get_timeline():
    """Get threat timeline data for charting."""
    threats = []
    log_path = f"{LOG_DIR}/ai-threats.log"
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        threats.append({
                            "timestamp": entry.get("epoch", 0),
                            "severity": entry.get("severity", "unknown"),
                            "detector": entry.get("detector", "unknown"),
                        })
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
    return {"timeline": threats[-200:]}


def get_analysis():
    """Get Claude analysis log."""
    entries = []
    log_path = f"{LOG_DIR}/ai-analysis.log"
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                for line in f:
                    try:
                        entries.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
    return {"analyses": entries[-20:][::-1]}


def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def _validate_ip(ip: str) -> bool:
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and all(
        0 <= int(o) <= 255 for o in ip.split('.')
    )
