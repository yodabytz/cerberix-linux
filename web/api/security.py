"""
Cerberix Web API — Security Features
(fail2ban, GeoIP, threat feeds, rate limiting, ARP watch)
"""

import json
import os
import re
import subprocess
import threading
import time


DATA_DIR = "/var/lib/cerberix"
LOG_DIR = "/var/log/cerberix"

# Background fail2ban cache — querying 10 jails takes ~1s
_f2b_cache = {"running": False, "jails": [], "last_update": 0}
_f2b_lock = threading.Lock()
_f2b_thread_started = False


def _start_f2b_thread():
    global _f2b_thread_started
    if _f2b_thread_started:
        return
    _f2b_thread_started = True

    status = _query_fail2ban()
    with _f2b_lock:
        _f2b_cache.update(status)
        _f2b_cache["last_update"] = time.time()

    def _loop():
        while True:
            time.sleep(15)
            status = _query_fail2ban()
            with _f2b_lock:
                _f2b_cache.update(status)
                _f2b_cache["last_update"] = time.time()

    t = threading.Thread(target=_loop, daemon=True, name="f2b-cache")
    t.start()


def _query_fail2ban():
    jails = []
    try:
        result = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return {"running": False, "jails": []}

        jail_names = []
        for line in result.stdout.splitlines():
            if "Jail list:" in line:
                jail_names = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]

        for jail in jail_names:
            jr = subprocess.run(
                ["fail2ban-client", "status", jail],
                capture_output=True, text=True, timeout=5,
            )
            info = {"name": jail, "banned": 0, "total_banned": 0, "failures": 0}
            for line in jr.stdout.splitlines():
                if "Currently banned:" in line:
                    info["banned"] = int(line.split(":")[-1].strip())
                elif "Total banned:" in line:
                    info["total_banned"] = int(line.split(":")[-1].strip())
                elif "Currently failed:" in line:
                    info["failures"] = int(line.split(":")[-1].strip())
            jails.append(info)

        return {"running": True, "jails": jails}
    except (subprocess.SubprocessError, ValueError):
        return {"running": False, "jails": []}


# ── fail2ban ────────────────────────────────────────────────

def get_fail2ban_status():
    """Get fail2ban jail status (from cache)."""
    _start_f2b_thread()
    with _f2b_lock:
        return {"running": _f2b_cache["running"], "jails": list(_f2b_cache["jails"])}


# ── GeoIP ───────────────────────────────────────────────────

def get_geoip_status():
    """Get GeoIP blocking status."""
    status = {"enabled": False, "blocked_countries": [], "last_update": ""}
    conf = "/etc/cerberix/geoip.conf"
    if os.path.exists(conf):
        try:
            with open(conf) as f:
                countries = f.read().strip().split()
            status["enabled"] = len(countries) > 0
            status["blocked_countries"] = countries
        except OSError:
            pass

    update_file = f"{DATA_DIR}/geoip/last_update"
    if os.path.exists(update_file):
        try:
            with open(update_file) as f:
                status["last_update"] = f.read().strip()
        except OSError:
            pass

    return status


def block_country(country_code: str):
    """Block a country by ISO code."""
    cc = country_code.upper().strip()
    if not re.match(r'^[A-Z]{2}$', cc):
        return {"success": False, "error": "Invalid country code"}
    try:
        result = subprocess.run(
            ["cerberix-geoip", "block", cc],
            capture_output=True, text=True, timeout=30,
        )
        return {"success": result.returncode == 0, "output": result.stdout}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def unblock_country(country_code: str):
    """Unblock a country."""
    cc = country_code.upper().strip()
    if not re.match(r'^[A-Z]{2}$', cc):
        return {"success": False, "error": "Invalid country code"}
    try:
        result = subprocess.run(
            ["cerberix-geoip", "unblock", cc],
            capture_output=True, text=True, timeout=30,
        )
        return {"success": result.returncode == 0, "output": result.stdout}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def clear_geoip():
    """Clear all GeoIP blocks."""
    try:
        result = subprocess.run(
            ["cerberix-geoip", "clear"],
            capture_output=True, text=True, timeout=10,
        )
        return {"success": result.returncode == 0}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


# ── Threat Feeds ────────────────────────────────────────────

def get_feed_status():
    """Get threat feed status."""
    status = {
        "ip_count": 0, "domain_count": 0,
        "last_update": "", "feeds": [], "enabled": True,
    }

    state_file = f"{DATA_DIR}/feeds/state"
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                status["enabled"] = f.read().strip() != "disabled"
        except OSError:
            pass

    ip_file = f"{DATA_DIR}/feeds/all-blocked-ips.txt"
    if os.path.exists(ip_file):
        try:
            with open(ip_file) as f:
                status["ip_count"] = sum(1 for _ in f)
        except OSError:
            pass

    dom_file = f"{DATA_DIR}/feeds/all-blocked-domains.txt"
    if os.path.exists(dom_file):
        try:
            with open(dom_file) as f:
                status["domain_count"] = sum(1 for _ in f)
        except OSError:
            pass

    update_file = f"{DATA_DIR}/feeds/last_update"
    if os.path.exists(update_file):
        try:
            with open(update_file) as f:
                status["last_update"] = f.read().strip()
        except OSError:
            pass

    # Individual feed counts
    feed_dir = f"{DATA_DIR}/feeds"
    if os.path.isdir(feed_dir):
        for f in sorted(os.listdir(feed_dir)):
            if f.endswith(".txt") and f not in ("all-blocked-ips.txt", "all-blocked-domains.txt"):
                path = os.path.join(feed_dir, f)
                try:
                    with open(path) as fh:
                        count = sum(1 for _ in fh)
                    status["feeds"].append({"name": f.replace(".txt", ""), "count": count})
                except OSError:
                    pass

    return status


def update_feeds():
    """Trigger a threat feed update."""
    try:
        result = subprocess.run(
            ["cerberix-feeds", "update"],
            capture_output=True, text=True, timeout=120,
        )
        return {"success": result.returncode == 0, "output": result.stdout}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def toggle_feeds(enable: bool):
    """Enable or disable threat feeds."""
    cmd = "enable" if enable else "disable"
    try:
        result = subprocess.run(
            ["cerberix-feeds", cmd],
            capture_output=True, text=True, timeout=120,
        )
        return {"success": result.returncode == 0, "enabled": enable, "output": result.stdout}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


# ── Rate Limiting ───────────────────────────────────────────

def get_rate_limit_stats():
    """Get rate limiting meter stats from nftables."""
    stats = {"meters": []}
    try:
        result = subprocess.run(
            ["nft", "list", "table", "inet", "rate_limit"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            stats["active"] = True
            stats["ruleset"] = result.stdout
        else:
            stats["active"] = False
    except subprocess.SubprocessError:
        stats["active"] = False
    return stats


# ── ARP Watch ───────────────────────────────────────────────

def get_arp_status():
    """Get ARP watch status and alerts."""
    status = {"bindings": {}, "alerts": []}

    bindings_file = f"{DATA_DIR}/ai/arp_bindings.json"
    if os.path.exists(bindings_file):
        try:
            with open(bindings_file) as f:
                status["bindings"] = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass

    # Get ARP-related alerts from threat log
    threat_log = f"{LOG_DIR}/ai-threats.log"
    if os.path.exists(threat_log):
        try:
            with open(threat_log) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry.get("detector") == "arp_watch":
                            status["alerts"].append(entry)
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass

    return status


# ── Bandwidth ──────────────────────────────────────────────

def get_bandwidth():
    """Get bandwidth history."""
    path = f"{DATA_DIR}/ai/bandwidth_history.json"
    if not os.path.exists(path):
        return {"history": []}
    try:
        with open(path) as f:
            return {"history": json.load(f)[-120:]}
    except (OSError, json.JSONDecodeError):
        return {"history": []}
