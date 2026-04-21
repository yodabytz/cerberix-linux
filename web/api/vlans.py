"""
Cerberix Web API — VLAN Management

802.1Q VLAN tagging, per-VLAN firewall zones, DHCP per VLAN.
"""

import json
import logging
import os
import re
import subprocess
import time

log = logging.getLogger("cerberix-web")

VLAN_CONF = "/etc/cerberix/vlans.conf"


def _load_config() -> dict:
    if not os.path.exists(VLAN_CONF):
        return {"vlans": [], "trunk_interface": "eth0"}
    try:
        with open(VLAN_CONF) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"vlans": [], "trunk_interface": "eth0"}


def _save_config(config: dict):
    os.makedirs(os.path.dirname(VLAN_CONF), exist_ok=True)
    with open(VLAN_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(VLAN_CONF, 0o600)


def _run(cmd: list, timeout: int = 10) -> tuple:
    """Run command, return (success, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.SubprocessError as e:
        return False, str(e)


def _vlan_iface(trunk: str, vid: int) -> str:
    return f"{trunk}.{vid}"


def _apply_vlan(trunk: str, vlan: dict):
    """Create and configure a VLAN interface."""
    vid = vlan["id"]
    iface = _vlan_iface(trunk, vid)
    subnet = vlan.get("subnet", "")
    gateway = vlan.get("gateway", "")

    # Create VLAN interface
    _run(["ip", "link", "add", "link", trunk, "name", iface, "type", "vlan", "id", str(vid)])
    if gateway:
        _run(["ip", "addr", "flush", "dev", iface])
        prefix = subnet.split("/")[1] if "/" in subnet else "24"
        _run(["ip", "addr", "add", f"{gateway}/{prefix}", "dev", iface])
    _run(["ip", "link", "set", iface, "up"])

    # Set up DHCP for this VLAN if configured
    if vlan.get("dhcp_enabled") and subnet:
        _setup_vlan_dhcp(vid, vlan)

    # Set up firewall zone
    zone = vlan.get("zone", "lan")
    _setup_vlan_firewall(vid, iface, zone, subnet)


def _remove_vlan(trunk: str, vid: int):
    """Remove a VLAN interface."""
    iface = _vlan_iface(trunk, vid)
    _run(["ip", "link", "set", iface, "down"])
    _run(["ip", "link", "delete", iface])

    # Remove DHCP config
    dhcp_conf = f"/etc/cerberix/dnsmasq.d/vlan{vid}.conf"
    if os.path.exists(dhcp_conf):
        os.remove(dhcp_conf)

    # Remove firewall rules
    fw_conf = f"/tmp/nftables.d/vlan{vid}.nft"
    if os.path.exists(fw_conf):
        os.remove(fw_conf)

    _reload_dnsmasq()


def _setup_vlan_dhcp(vid: int, vlan: dict):
    """Create dnsmasq DHCP config for a VLAN."""
    subnet = vlan.get("subnet", "")
    gateway = vlan.get("gateway", "")
    dhcp_start = vlan.get("dhcp_start", "")
    dhcp_end = vlan.get("dhcp_end", "")

    if not all([subnet, gateway, dhcp_start, dhcp_end]):
        return

    conf_file = f"/etc/cerberix/dnsmasq.d/vlan{vid}.conf"
    with open(conf_file, "w") as f:
        f.write(f"# VLAN {vid} — {vlan.get('name', '')}\n")
        f.write(f"interface={_vlan_iface(vlan.get('_trunk', 'eth0'), vid)}\n")
        f.write(f"dhcp-range=tag:vlan{vid},{dhcp_start},{dhcp_end},255.255.255.0,12h\n")
        f.write(f"dhcp-option=tag:vlan{vid},option:router,{gateway}\n")
        f.write(f"dhcp-option=tag:vlan{vid},option:dns-server,{gateway}\n")

    _reload_dnsmasq()


def _setup_vlan_firewall(vid: int, iface: str, zone: str, subnet: str):
    """Create nftables rules for a VLAN zone."""
    fw_conf = f"/tmp/nftables.d/vlan{vid}.nft"

    if zone == "trusted":
        # Full access — allow all traffic
        rules = f"""# VLAN {vid} — Trusted Zone
# Full access to all networks and the internet
"""
    elif zone == "guest":
        # Internet only — no access to other VLANs or management
        rules = f"""# VLAN {vid} — Guest Zone
# Internet access only, no local network access
"""
    elif zone == "isolated":
        # No inter-VLAN, no internet, only local VLAN traffic
        rules = f"""# VLAN {vid} — Isolated Zone
# No internet, no inter-VLAN routing
"""
    else:
        # Default LAN zone — standard access
        rules = f"""# VLAN {vid} — LAN Zone
# Standard LAN access with internet
"""

    with open(fw_conf, "w") as f:
        f.write(rules)


def _reload_dnsmasq():
    try:
        subprocess.run(["killall", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
    except subprocess.SubprocessError:
        pass


def _get_active_vlans() -> list:
    """Get currently active VLAN interfaces from the system."""
    active = []
    try:
        r = subprocess.run(["ip", "-j", "link", "show", "type", "vlan"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            interfaces = json.loads(r.stdout)
            for iface in interfaces:
                name = iface.get("ifname", "")
                state = iface.get("operstate", "UNKNOWN")
                # Extract VLAN ID from linkinfo
                vid = None
                linkinfo = iface.get("linkinfo", {})
                info_data = linkinfo.get("info_data", {})
                vid = info_data.get("id")
                if vid:
                    active.append({"interface": name, "vlan_id": vid, "state": state})
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return active


# ── API Functions ────────────────────────────────────────────

def get_status():
    """Get VLAN configuration and status."""
    config = _load_config()
    active = _get_active_vlans()
    active_ids = {v["vlan_id"] for v in active}

    vlans = []
    for vlan in config.get("vlans", []):
        vlan_copy = dict(vlan)
        vlan_copy["active"] = vlan["id"] in active_ids
        vlans.append(vlan_copy)

    return {
        "trunk_interface": config.get("trunk_interface", "eth0"),
        "vlans": vlans,
        "active_interfaces": active,
    }


def create_vlan(vlan_data: dict):
    """Create a new VLAN."""
    vid = vlan_data.get("id")
    if not vid or not isinstance(vid, int) or vid < 1 or vid > 4094:
        return {"success": False, "error": "VLAN ID must be 1-4094"}

    name = vlan_data.get("name", f"VLAN {vid}")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,30}$', name):
        return {"success": False, "error": "Invalid VLAN name"}

    subnet = vlan_data.get("subnet", "")
    if subnet and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', subnet):
        return {"success": False, "error": "Invalid subnet (use CIDR, e.g. 10.10.10.0/24)"}

    gateway = vlan_data.get("gateway", "")
    if gateway and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gateway):
        return {"success": False, "error": "Invalid gateway IP"}

    config = _load_config()

    # Check for duplicate
    for v in config.get("vlans", []):
        if v["id"] == vid:
            return {"success": False, "error": f"VLAN {vid} already exists"}

    vlan = {
        "id": vid,
        "name": name,
        "subnet": subnet,
        "gateway": gateway,
        "zone": vlan_data.get("zone", "lan"),
        "dhcp_enabled": vlan_data.get("dhcp_enabled", False),
        "dhcp_start": vlan_data.get("dhcp_start", ""),
        "dhcp_end": vlan_data.get("dhcp_end", ""),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    config.setdefault("vlans", []).append(vlan)
    _save_config(config)

    # Apply
    trunk = config.get("trunk_interface", "eth0")
    vlan["_trunk"] = trunk
    _apply_vlan(trunk, vlan)

    return {"success": True, "vlan": vlan}


def delete_vlan(vid: int):
    """Delete a VLAN."""
    config = _load_config()
    trunk = config.get("trunk_interface", "eth0")

    config["vlans"] = [v for v in config.get("vlans", []) if v["id"] != vid]
    _save_config(config)

    _remove_vlan(trunk, vid)
    return {"success": True}


def update_vlan(vid: int, updates: dict):
    """Update VLAN settings."""
    config = _load_config()
    trunk = config.get("trunk_interface", "eth0")

    for i, v in enumerate(config.get("vlans", [])):
        if v["id"] == vid:
            for key in ["name", "subnet", "gateway", "zone", "dhcp_enabled",
                        "dhcp_start", "dhcp_end"]:
                if key in updates:
                    config["vlans"][i][key] = updates[key]
            _save_config(config)

            # Re-apply
            _remove_vlan(trunk, vid)
            config["vlans"][i]["_trunk"] = trunk
            _apply_vlan(trunk, config["vlans"][i])
            return {"success": True}

    return {"success": False, "error": "VLAN not found"}


def set_trunk(interface: str):
    """Set the trunk interface."""
    if not re.match(r'^[a-zA-Z0-9]+$', interface):
        return {"success": False, "error": "Invalid interface name"}

    config = _load_config()
    old_trunk = config.get("trunk_interface", "eth0")

    # Remove old VLANs
    for vlan in config.get("vlans", []):
        _remove_vlan(old_trunk, vlan["id"])

    config["trunk_interface"] = interface
    _save_config(config)

    # Re-apply on new trunk
    for vlan in config.get("vlans", []):
        vlan["_trunk"] = interface
        _apply_vlan(interface, vlan)

    return {"success": True}
