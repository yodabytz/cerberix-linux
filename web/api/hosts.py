"""
Cerberix Web API — Monitored Hosts
Shows servers on the LAN that Cerberix is protecting.
"""

import subprocess
import os
import json
import time


# Known hosts on the Cerberix LAN
MANAGED_HOSTS = [
    {
        "name": "heros.quantumbytz.com",
        "ip": "192.168.1.10",
        "role": "Web Server",
        "services": ["Nginx", "PHP 8.3", "MariaDB"],
        "icon": "web",
    },
    {
        "name": "post.quantumbytz.com",
        "ip": "192.168.1.20",
        "role": "Git + Database",
        "services": ["Gitea", "PostgreSQL", "SSH"],
        "icon": "git",
    },
]


def get_hosts():
    """Get all monitored hosts with live status."""
    hosts = []
    for host in MANAGED_HOSTS:
        info = dict(host)
        info["status"] = _check_host(host["ip"])
        info["threats"] = _count_threats(host["ip"])
        info["connections"] = _count_connections(host["ip"])
        hosts.append(info)
    return {"hosts": hosts}


def _check_host(ip: str) -> str:
    """Check if host is reachable."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=3,
        )
        return "online" if result.returncode == 0 else "offline"
    except subprocess.SubprocessError:
        return "unknown"


def _count_threats(ip: str) -> int:
    """Count threats related to this host."""
    count = 0
    log_path = "/var/log/cerberix/ai-threats.log"
    if os.path.exists(log_path):
        try:
            result = subprocess.run(
                ["grep", "-c", ip, log_path],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                count = int(result.stdout.strip())
        except (subprocess.SubprocessError, ValueError):
            pass
    return count


def _count_connections(ip: str) -> int:
    """Count active connections to/from this host."""
    try:
        result = subprocess.run(
            ["grep", "-c", ip, "/proc/net/nf_conntrack"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except (subprocess.SubprocessError, ValueError):
        pass
    return 0


def get_host_detail(ip: str):
    """Get detailed info for a specific host."""
    host = None
    for h in MANAGED_HOSTS:
        if h["ip"] == ip:
            host = dict(h)
            break
    if not host:
        return {"error": "Host not found"}

    host["status"] = _check_host(ip)
    host["threats"] = _count_threats(ip)
    host["connections"] = _count_connections(ip)

    # Get Suricata alerts for this host
    alerts = []
    eve_path = "/var/log/cerberix/suricata/eve.json"
    if os.path.exists(eve_path):
        try:
            result = subprocess.run(
                ["grep", ip, eve_path],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines()[-20:]:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        a = event.get("alert", {})
                        alerts.append({
                            "timestamp": event.get("timestamp", "")[:19],
                            "signature": a.get("signature", ""),
                            "severity": a.get("severity", 3),
                        })
                except json.JSONDecodeError:
                    pass
        except subprocess.SubprocessError:
            pass

    host["alerts"] = alerts
    return host
