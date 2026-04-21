"""
Cerberix Web API — QoS / Traffic Shaping

Traffic prioritization using tc (traffic control).
Priority queues for VoIP/video, bandwidth limits per host/service.
"""

import json
import logging
import os
import re
import subprocess
import time

log = logging.getLogger("cerberix-web")

QOS_CONF = "/etc/cerberix/qos.conf"


def _load_config() -> dict:
    if not os.path.exists(QOS_CONF):
        return {
            "enabled": False,
            "wan_interface": "eth0",
            "upload_mbps": 100,
            "download_mbps": 100,
            "rules": [],
        }
    try:
        with open(QOS_CONF) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "wan_interface": "eth0", "upload_mbps": 100, "download_mbps": 100, "rules": []}


def _save_config(config: dict):
    os.makedirs(os.path.dirname(QOS_CONF), exist_ok=True)
    with open(QOS_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(QOS_CONF, 0o600)


def _run(cmd: list, timeout: int = 10) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.SubprocessError as e:
        return False, str(e)


def _clear_qos(interface: str):
    """Remove all tc qdisc from interface."""
    _run(["tc", "qdisc", "del", "dev", interface, "root"], timeout=5)
    _run(["tc", "qdisc", "del", "dev", interface, "ingress"], timeout=5)


def _apply_qos(config: dict):
    """Apply QoS rules using tc HTB qdisc."""
    if not config.get("enabled"):
        _clear_qos(config.get("wan_interface", "eth0"))
        return

    iface = config.get("wan_interface", "eth0")
    upload_kbps = config.get("upload_mbps", 100) * 1000
    download_kbps = config.get("download_mbps", 100) * 1000

    # Clear existing
    _clear_qos(iface)

    # Create HTB root qdisc for egress (upload)
    _run(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:",
          "htb", "default", "40"])

    # Root class — total bandwidth
    _run(["tc", "class", "add", "dev", iface, "parent", "1:",
          "classid", "1:1", "htb", "rate", f"{upload_kbps}kbit",
          "ceil", f"{upload_kbps}kbit"])

    # Priority classes:
    # 1:10 — Highest (VoIP, DNS) — 30% guaranteed, can burst to 100%
    # 1:20 — High (SSH, VPN, gaming) — 25% guaranteed
    # 1:30 — Normal (HTTP, HTTPS) — 25% guaranteed
    # 1:40 — Low (bulk, P2P) — 20% guaranteed

    classes = [
        ("1:10", "highest", 30),
        ("1:20", "high", 25),
        ("1:30", "normal", 25),
        ("1:40", "low", 20),
    ]

    for classid, name, pct in classes:
        rate = int(upload_kbps * pct / 100)
        _run(["tc", "class", "add", "dev", iface, "parent", "1:1",
              "classid", classid, "htb",
              "rate", f"{rate}kbit", "ceil", f"{upload_kbps}kbit",
              "prio", str(classes.index((classid, name, pct)))])
        # Add SFQ for fairness within each class
        _run(["tc", "qdisc", "add", "dev", iface, "parent", classid,
              "handle", f"{classid.split(':')[1]}0:", "sfq", "perturb", "10"])

    # Default classification rules
    # VoIP (SIP/RTP) → highest
    _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
          "protocol", "ip", "prio", "1", "u32",
          "match", "ip", "dport", "5060", "0xffff", "flowid", "1:10"])
    # DNS → highest
    _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
          "protocol", "ip", "prio", "1", "u32",
          "match", "ip", "dport", "53", "0xffff", "flowid", "1:10"])
    # SSH → high
    _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
          "protocol", "ip", "prio", "2", "u32",
          "match", "ip", "dport", "22", "0xffff", "flowid", "1:20"])
    # HTTPS → normal
    _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
          "protocol", "ip", "prio", "3", "u32",
          "match", "ip", "dport", "443", "0xffff", "flowid", "1:30"])
    # HTTP → normal
    _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
          "protocol", "ip", "prio", "3", "u32",
          "match", "ip", "dport", "80", "0xffff", "flowid", "1:30"])

    # Apply custom rules
    for rule in config.get("rules", []):
        _apply_custom_rule(iface, rule)

    log.info(f"QoS applied on {iface}: {upload_kbps}kbit up, {download_kbps}kbit down")


def _apply_custom_rule(iface: str, rule: dict):
    """Apply a custom QoS rule."""
    priority_map = {"highest": "1:10", "high": "1:20", "normal": "1:30", "low": "1:40"}
    flowid = priority_map.get(rule.get("priority", "normal"), "1:30")
    rule_type = rule.get("type", "")

    if rule_type == "port" and rule.get("port"):
        port = str(rule["port"])
        proto = rule.get("protocol", "tcp")
        _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
              "protocol", "ip", "prio", "5", "u32",
              "match", "ip", "dport", port, "0xffff", "flowid", flowid])
    elif rule_type == "ip" and rule.get("ip"):
        ip = rule["ip"]
        _run(["tc", "filter", "add", "dev", iface, "parent", "1:",
              "protocol", "ip", "prio", "5", "u32",
              "match", "ip", "dst", ip, "flowid", flowid])


def _get_tc_stats(interface: str) -> list:
    """Get current tc class statistics."""
    stats = []
    ok, output = _run(["tc", "-s", "class", "show", "dev", interface])
    if not ok:
        return stats

    current = None
    for line in output.splitlines():
        class_match = re.match(r'class htb (\S+)', line)
        if class_match:
            if current:
                stats.append(current)
            current = {"classid": class_match.group(1), "sent_bytes": 0, "sent_packets": 0, "rate": ""}
        if current:
            rate_match = re.search(r'rate (\S+)', line)
            if rate_match and "rate" in line and "ceil" not in line:
                current["rate"] = rate_match.group(1)
            sent_match = re.search(r'Sent (\d+) bytes (\d+) pkt', line)
            if sent_match:
                current["sent_bytes"] = int(sent_match.group(1))
                current["sent_packets"] = int(sent_match.group(2))
    if current:
        stats.append(current)

    return stats


# ── API Functions ────────────────────────────────────────────

def get_status():
    """Get QoS configuration and current stats."""
    config = _load_config()
    iface = config.get("wan_interface", "eth0")
    tc_stats = _get_tc_stats(iface) if config.get("enabled") else []

    priority_names = {"1:1": "Root", "1:10": "Highest (VoIP/DNS)",
                      "1:20": "High (SSH/VPN)", "1:30": "Normal (Web)",
                      "1:40": "Low (Bulk/P2P)"}

    for s in tc_stats:
        s["name"] = priority_names.get(s["classid"], s["classid"])

    return {
        "enabled": config.get("enabled", False),
        "wan_interface": iface,
        "upload_mbps": config.get("upload_mbps", 100),
        "download_mbps": config.get("download_mbps", 100),
        "rules": config.get("rules", []),
        "tc_stats": tc_stats,
    }


def toggle_qos(enabled: bool):
    """Enable or disable QoS."""
    config = _load_config()
    config["enabled"] = enabled
    _save_config(config)
    _apply_qos(config)
    return {"success": True, "enabled": enabled}


def update_bandwidth(upload_mbps: int, download_mbps: int):
    """Update bandwidth limits."""
    if upload_mbps < 1 or download_mbps < 1:
        return {"success": False, "error": "Bandwidth must be at least 1 Mbps"}
    config = _load_config()
    config["upload_mbps"] = upload_mbps
    config["download_mbps"] = download_mbps
    _save_config(config)
    if config.get("enabled"):
        _apply_qos(config)
    return {"success": True}


def add_rule(rule: dict):
    """Add a custom QoS rule."""
    rule_type = rule.get("type", "")
    if rule_type not in ("port", "ip"):
        return {"success": False, "error": "Rule type must be 'port' or 'ip'"}

    priority = rule.get("priority", "normal")
    if priority not in ("highest", "high", "normal", "low"):
        return {"success": False, "error": "Priority must be highest/high/normal/low"}

    if rule_type == "port":
        port = rule.get("port")
        if not port or not isinstance(port, int) or port < 1 or port > 65535:
            return {"success": False, "error": "Invalid port number"}
    elif rule_type == "ip":
        ip = rule.get("ip", "")
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip):
            return {"success": False, "error": "Invalid IP address"}

    new_rule = {
        "type": rule_type,
        "name": rule.get("name", ""),
        "priority": priority,
        "port": rule.get("port"),
        "protocol": rule.get("protocol", "tcp"),
        "ip": rule.get("ip", ""),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    config = _load_config()
    config.setdefault("rules", []).append(new_rule)
    _save_config(config)

    if config.get("enabled"):
        _apply_qos(config)

    return {"success": True}


def delete_rule(index: int):
    """Delete a QoS rule by index."""
    config = _load_config()
    rules = config.get("rules", [])
    if index < 0 or index >= len(rules):
        return {"success": False, "error": "Invalid rule index"}
    rules.pop(index)
    config["rules"] = rules
    _save_config(config)

    if config.get("enabled"):
        _apply_qos(config)

    return {"success": True}
