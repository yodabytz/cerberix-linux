"""
Cerberix Web API — System Information
"""

import os
import subprocess


def get_info():
    """Get system information."""
    # Version
    version = ""
    try:
        with open("/etc/cerberix-release") as f:
            version = f.read().strip()
    except OSError:
        version = "Unknown"

    # Uptime
    uptime = 0
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except (OSError, ValueError):
        pass

    # Memory
    mem = {"total": 0, "used": 0, "free": 0, "pct": 0}
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
            mem["total"] = meminfo.get("MemTotal", 0)
            mem["free"] = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            mem["used"] = mem["total"] - mem["free"]
            mem["pct"] = round(mem["used"] / mem["total"] * 100, 1) if mem["total"] else 0
    except (OSError, ValueError):
        pass

    # CPU load
    load = [0, 0, 0]
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            load = [float(parts[0]), float(parts[1]), float(parts[2])]
    except (OSError, ValueError, IndexError):
        pass

    # Disk
    disk = {"total": 0, "used": 0, "pct": 0}
    try:
        st = os.statvfs("/")
        disk["total"] = st.f_blocks * st.f_frsize
        disk["used"] = (st.f_blocks - st.f_bfree) * st.f_frsize
        disk["pct"] = round(disk["used"] / disk["total"] * 100, 1) if disk["total"] else 0
    except OSError:
        pass

    return {
        "version": version,
        "uptime_sec": uptime,
        "memory": mem,
        "cpu_load": load,
        "disk": disk,
        "hostname": os.uname().nodename,
    }


def get_services():
    """Check status of key services."""
    services = []
    checks = [
        ("dnsmasq", ["pgrep", "-x", "dnsmasq"]),
        ("syslog-ng", ["pgrep", "-x", "syslog-ng"]),
        ("ai-engine", ["pgrep", "-f", "ai.engine"]),
        ("web-panel", ["pgrep", "-f", "web.server"]),
    ]
    for name, cmd in checks:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            services.append({"name": name, "running": result.returncode == 0})
        except subprocess.SubprocessError:
            services.append({"name": name, "running": False})
    return {"services": services}


def get_logs(log_name: str, lines: int = 100):
    """Get tail of a log file."""
    allowed = {
        "firewall": "/var/log/cerberix/firewall.log",
        "dnsmasq": "/var/log/cerberix/dnsmasq.log",
        "ai-threats": "/var/log/cerberix/ai-threats.log",
        "ai-analysis": "/var/log/cerberix/ai-analysis.log",
        "cerberix": "/var/log/cerberix/cerberix.log",
        "webui-audit": "/var/log/cerberix/webui-audit.log",
    }
    path = allowed.get(log_name)
    if not path:
        return {"error": "Unknown log file", "lines": []}
    if not os.path.exists(path):
        return {"lines": [], "file": log_name}
    try:
        with open(path) as f:
            all_lines = f.readlines()
        return {"lines": [l.rstrip() for l in all_lines[-lines:]], "file": log_name}
    except OSError:
        return {"lines": [], "file": log_name, "error": "Read error"}
