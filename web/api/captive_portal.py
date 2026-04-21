"""
Cerberix Web API — Captive Portal

Guest network login with terms of service, time limits, bandwidth caps.
Uses nftables to redirect unauthenticated guests to a login page.
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import time
import threading

log = logging.getLogger("cerberix-web")

PORTAL_CONF = "/etc/cerberix/captive-portal.conf"
PORTAL_CLIENTS = "/var/lib/cerberix/captive-clients.json"
PORTAL_PAGE = "/opt/cerberix/web/templates/captive.html"


def _load_config() -> dict:
    if not os.path.exists(PORTAL_CONF):
        return {
            "enabled": False,
            "interface": "eth1",
            "portal_port": 8080,
            "session_timeout_minutes": 60,
            "bandwidth_limit_mbps": 10,
            "require_password": False,
            "password_hash": "",
            "terms": "By connecting, you agree to acceptable use policies. No illegal activity, excessive bandwidth, or network abuse.",
            "title": "Cerberix Guest Network",
            "redirect_url": "",
        }
    try:
        with open(PORTAL_CONF) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "interface": "eth1"}


def _save_config(config: dict):
    os.makedirs(os.path.dirname(PORTAL_CONF), exist_ok=True)
    with open(PORTAL_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(PORTAL_CONF, 0o600)


def _load_clients() -> dict:
    if not os.path.exists(PORTAL_CLIENTS):
        return {"clients": {}}
    try:
        with open(PORTAL_CLIENTS) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"clients": {}}


def _save_clients(data: dict):
    os.makedirs(os.path.dirname(PORTAL_CLIENTS), exist_ok=True)
    with open(PORTAL_CLIENTS, "w") as f:
        json.dump(data, f, indent=2)


def _run(cmd: list, timeout: int = 10) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.SubprocessError as e:
        return False, str(e)


def _apply_portal_rules(config: dict):
    """Set up nftables rules for captive portal redirect."""
    iface = config.get("interface", "eth1")

    if not config.get("enabled"):
        # Remove portal rules
        _run(["nft", "delete", "table", "ip", "cerberix_portal"])
        return

    # Create portal table
    _run(["nft", "delete", "table", "ip", "cerberix_portal"])
    _run(["nft", "add", "table", "ip", "cerberix_portal"])

    # Create set for authenticated clients
    _run(["nft", "add", "set", "ip", "cerberix_portal", "authenticated",
          "{ type ipv4_addr; timeout 1h; }"])

    # Prerouting chain — redirect unauthenticated HTTP to portal
    _run(["nft", "add", "chain", "ip", "cerberix_portal", "prerouting",
          "{ type nat hook prerouting priority -100; }"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "prerouting",
          f"iifname {iface}", "ip", "saddr", "@authenticated", "accept"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "prerouting",
          f"iifname {iface}", "tcp", "dport", "80",
          "redirect", "to", f":{config.get('portal_port', 8080)}"])

    # Forward chain — block non-authenticated from internet
    _run(["nft", "add", "chain", "ip", "cerberix_portal", "forward",
          "{ type filter hook forward priority -50; }"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "forward",
          f"iifname {iface}", "ip", "saddr", "@authenticated", "accept"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "forward",
          f"iifname {iface}", "tcp", "dport", "{ 53, 67, 68 }", "accept"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "forward",
          f"iifname {iface}", "udp", "dport", "{ 53, 67, 68 }", "accept"])
    _run(["nft", "add", "rule", "ip", "cerberix_portal", "forward",
          f"iifname {iface}", "drop"])

    # Add currently authenticated clients
    clients = _load_clients()
    now = time.time()
    timeout = config.get("session_timeout_minutes", 60) * 60
    for ip, info in clients.get("clients", {}).items():
        if now - info.get("auth_time", 0) < timeout:
            _run(["nft", "add", "element", "ip", "cerberix_portal",
                  "authenticated", "{", ip, "}"])


def _cleanup_expired():
    """Remove expired client sessions."""
    config = _load_config()
    timeout = config.get("session_timeout_minutes", 60) * 60
    clients = _load_clients()
    now = time.time()
    expired = []

    for ip, info in list(clients.get("clients", {}).items()):
        if now - info.get("auth_time", 0) >= timeout:
            expired.append(ip)
            _run(["nft", "delete", "element", "ip", "cerberix_portal",
                  "authenticated", "{", ip, "}"])

    for ip in expired:
        del clients["clients"][ip]

    if expired:
        _save_clients(clients)
        log.info(f"Captive portal: expired {len(expired)} sessions")


# ── API Functions ────────────────────────────────────────────

def get_status():
    """Get captive portal status."""
    config = _load_config()
    clients = _load_clients()
    now = time.time()
    timeout = config.get("session_timeout_minutes", 60) * 60

    active_clients = []
    for ip, info in clients.get("clients", {}).items():
        remaining = timeout - (now - info.get("auth_time", 0))
        if remaining > 0:
            active_clients.append({
                "ip": ip,
                "auth_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["auth_time"])),
                "remaining_minutes": int(remaining / 60),
                "mac": info.get("mac", ""),
            })

    return {
        "enabled": config.get("enabled", False),
        "interface": config.get("interface", "eth1"),
        "session_timeout_minutes": config.get("session_timeout_minutes", 60),
        "bandwidth_limit_mbps": config.get("bandwidth_limit_mbps", 10),
        "require_password": config.get("require_password", False),
        "title": config.get("title", "Cerberix Guest Network"),
        "terms": config.get("terms", ""),
        "active_clients": active_clients,
        "total_clients_today": len(clients.get("clients", {})),
    }


def toggle_portal(enabled: bool):
    """Enable or disable the captive portal."""
    config = _load_config()
    config["enabled"] = enabled
    _save_config(config)
    _apply_portal_rules(config)
    return {"success": True, "enabled": enabled}


def update_config(updates: dict):
    """Update captive portal configuration."""
    config = _load_config()

    for key in ["interface", "session_timeout_minutes", "bandwidth_limit_mbps",
                "require_password", "title", "terms", "redirect_url", "portal_port"]:
        if key in updates:
            config[key] = updates[key]

    if "password" in updates and updates["password"]:
        config["password_hash"] = hashlib.sha256(updates["password"].encode()).hexdigest()

    _save_config(config)
    if config.get("enabled"):
        _apply_portal_rules(config)

    return {"success": True}


def authorize_client(ip: str, mac: str = ""):
    """Authorize a client to access the network."""
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return {"success": False, "error": "Invalid IP"}

    clients = _load_clients()
    clients.setdefault("clients", {})[ip] = {
        "auth_time": time.time(),
        "mac": mac,
    }
    _save_clients(clients)

    # Add to nftables authenticated set
    _run(["nft", "add", "element", "ip", "cerberix_portal",
          "authenticated", "{", ip, "}"])

    return {"success": True}


def deauthorize_client(ip: str):
    """Remove a client's authorization."""
    clients = _load_clients()
    if ip in clients.get("clients", {}):
        del clients["clients"][ip]
        _save_clients(clients)

    _run(["nft", "delete", "element", "ip", "cerberix_portal",
          "authenticated", "{", ip, "}"])

    return {"success": True}


def disconnect_all():
    """Disconnect all clients."""
    _save_clients({"clients": {}})
    config = _load_config()
    if config.get("enabled"):
        _apply_portal_rules(config)
    return {"success": True}
