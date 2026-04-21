"""
Cerberix Web API — Network Information
"""

import os
import re
import subprocess
import threading
import time

# Cached health status — updated in background, never blocks API
_health_cache = {"wan": False, "lan": False, "last_check": 0}
_health_lock = threading.Lock()
_health_thread_started = False


def get_interfaces():
    """Get WAN/LAN interface details."""
    interfaces = []
    # Read detected interface mapping
    wan_if = "eth0"
    lan_if = "eth1"
    env_file = "/var/run/cerberix/interfaces.env"
    if os.path.exists(env_file):
        try:
            with open(env_file) as f:
                for line in f:
                    if line.startswith("WAN_IF="):
                        wan_if = line.strip().split("=", 1)[1]
                    elif line.startswith("LAN_IF="):
                        lan_if = line.strip().split("=", 1)[1]
        except OSError:
            pass

    _start_health_thread()

    for iface, role in [(wan_if, "WAN"), (lan_if, "LAN")]:
        info = _get_interface_info(iface)
        info["role"] = role
        with _health_lock:
            info["healthy"] = _health_cache["wan"] if role == "WAN" else _health_cache["lan"]
        interfaces.append(info)

    return {"interfaces": interfaces}


def get_dhcp_leases():
    """Get DHCP lease table."""
    leases = []
    lease_file = "/var/lib/cerberix/dnsmasq.leases"
    if os.path.exists(lease_file):
        try:
            with open(lease_file) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        leases.append({
                            "expires": int(parts[0]) if parts[0] != "0" else 0,
                            "mac": parts[1],
                            "ip": parts[2],
                            "hostname": parts[3] if parts[3] != "*" else "",
                        })
        except OSError:
            pass
    return {"leases": leases}


def get_routes():
    """Get routing table."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route"],
            capture_output=True, text=True, timeout=5,
        )
        routes = []
        for line in result.stdout.strip().splitlines():
            routes.append(line.strip())
        return {"routes": routes}
    except subprocess.SubprocessError:
        return {"routes": []}


def get_arp():
    """Get ARP neighbor table."""
    try:
        result = subprocess.run(
            ["ip", "neigh"],
            capture_output=True, text=True, timeout=5,
        )
        neighbors = []
        for line in result.stdout.strip().splitlines():
            if line.strip():
                neighbors.append(line.strip())
        return {"neighbors": neighbors}
    except subprocess.SubprocessError:
        return {"neighbors": []}


def get_conntrack():
    """Get connection tracking stats."""
    count = 0
    max_ct = 0
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            count = int(f.read().strip())
    except (OSError, ValueError):
        pass
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            max_ct = int(f.read().strip())
    except (OSError, ValueError):
        pass
    return {"count": count, "max": max_ct, "usage_pct": round(count / max_ct * 100, 1) if max_ct else 0}


def _get_interface_info(iface: str) -> dict:
    """Get detailed info for an interface."""
    info = {"name": iface, "ip": "", "mac": "", "state": "down", "rx_bytes": 0, "tx_bytes": 0}
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            ip_match = re.search(r'inet\s+([\d.]+/\d+)', line)
            if ip_match:
                info["ip"] = ip_match.group(1)
            if "UP" in line:
                info["state"] = "up"
    except subprocess.SubprocessError:
        pass

    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        mac_match = re.search(r'link/ether\s+([\da-f:]+)', result.stdout)
        if mac_match:
            info["mac"] = mac_match.group(1)
        if "UP" in result.stdout:
            info["state"] = "up"
    except subprocess.SubprocessError:
        pass

    # Read TX/RX from /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    parts = line.split()
                    info["rx_bytes"] = int(parts[1])
                    info["tx_bytes"] = int(parts[9])
    except (OSError, IndexError, ValueError):
        pass

    return info


def _start_health_thread():
    """Start background health checker (runs every 15 seconds)."""
    global _health_thread_started
    if _health_thread_started:
        return
    _health_thread_started = True

    def _loop():
        while True:
            wan = _check_wan_health()
            lan = _check_lan_health()
            with _health_lock:
                _health_cache["wan"] = wan
                _health_cache["lan"] = lan
                _health_cache["last_check"] = time.time()
            time.sleep(15)

    t = threading.Thread(target=_loop, daemon=True, name="health-check")
    t.start()


def _check_wan_health() -> bool:
    """Check if WAN has internet connectivity (ping + DNS)."""
    # Try DNS resolution first (faster than ping)
    try:
        result = subprocess.run(
            ["nslookup", "cloudflare.com", "1.1.1.1"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0:
            return True
    except subprocess.SubprocessError:
        pass
    # Fallback: ping
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "1.1.1.1"],
            capture_output=True, timeout=4,
        )
        return result.returncode == 0
    except subprocess.SubprocessError:
        return False


def _check_lan_health() -> bool:
    """Check if LAN has active clients (DHCP leases or ARP entries)."""
    # Check for DHCP leases
    lease_file = "/var/lib/cerberix/dnsmasq.leases"
    if os.path.exists(lease_file):
        try:
            with open(lease_file) as f:
                if f.read().strip():
                    return True
        except OSError:
            pass
    # Check for ARP neighbors on LAN
    try:
        result = subprocess.run(
            ["ip", "neigh"],
            capture_output=True, text=True, timeout=3,
        )
        # Any REACHABLE or STALE neighbor means clients are present
        for line in result.stdout.splitlines():
            if "REACHABLE" in line or "STALE" in line or "DELAY" in line:
                return True
    except subprocess.SubprocessError:
        pass
    return False
