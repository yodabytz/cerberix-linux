"""
Cerberix Web API — DNS Statistics
"""

import os
import re
import subprocess
import threading
import time
from collections import Counter

LOG_DIR = "/var/log/cerberix"

# Background DNS stats cache — updated every 10 seconds
_dns_cache = {"total_queries": 0, "top_domains": [], "top_clients": [], "last_update": 0}
_dns_lock = threading.Lock()
_dns_thread_started = False


def _start_dns_stats_thread():
    global _dns_thread_started
    if _dns_thread_started:
        return
    _dns_thread_started = True

    stats = _compute_dns_stats()
    with _dns_lock:
        _dns_cache.update(stats)
        _dns_cache["last_update"] = time.time()

    def _loop():
        while True:
            time.sleep(10)
            stats = _compute_dns_stats()
            with _dns_lock:
                _dns_cache.update(stats)
                _dns_cache["last_update"] = time.time()

    t = threading.Thread(target=_loop, daemon=True, name="dns-stats")
    t.start()


def _compute_dns_stats():
    """Compute DNS stats from last 5000 lines of log (not entire file)."""
    log_path = f"{LOG_DIR}/dnsmasq.log"
    total_queries = 0
    domains = Counter()
    clients = Counter()

    if os.path.exists(log_path):
        try:
            # Only read tail of file — much faster than reading entire log
            result = subprocess.run(
                ["tail", "-n", "5000", log_path],
                capture_output=True, text=True, timeout=3,
            )
            query_re = re.compile(r'query\[(\w+)\]\s+(\S+)\s+from\s+([\d.]+)')
            for line in result.stdout.splitlines():
                match = query_re.search(line)
                if match:
                    total_queries += 1
                    domains[match.group(2)] += 1
                    clients[match.group(3)] += 1
        except (subprocess.SubprocessError, OSError):
            pass

    return {
        "total_queries": total_queries,
        "top_domains": [{"domain": d, "count": c} for d, c in domains.most_common(15)],
        "top_clients": [{"client": ip, "count": c} for ip, c in clients.most_common(10)],
    }


def get_stats():
    """Get DNS query statistics (from cache)."""
    _start_dns_stats_thread()
    with _dns_lock:
        return {
            "total_queries": _dns_cache["total_queries"],
            "top_domains": _dns_cache["top_domains"],
            "top_clients": _dns_cache["top_clients"],
        }


def get_blocked():
    """Get list of sinkholed domains."""
    blocked = []
    block_file = "/etc/cerberix/dnsmasq.d/ai-blocked.conf"
    if os.path.exists(block_file):
        try:
            with open(block_file) as f:
                for line in f:
                    match = re.match(r'address=/([^/]+)/0\.0\.0\.0', line)
                    if match:
                        blocked.append(match.group(1))
        except OSError:
            pass
    return {"blocked_domains": blocked}


def block_domain(domain: str):
    """Sinkhole a domain."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {"success": False, "error": "Invalid domain"}
    block_file = "/etc/cerberix/dnsmasq.d/ai-blocked.conf"
    line = f"address=/{domain}/0.0.0.0\n"
    try:
        if os.path.exists(block_file):
            with open(block_file) as f:
                if line in f.read():
                    return {"success": True, "message": "Already blocked"}
        with open(block_file, "a") as f:
            f.write(line)
        subprocess.run(["killall", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


def unblock_domain(domain: str):
    """Remove a domain sinkhole."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {"success": False, "error": "Invalid domain"}
    block_file = "/etc/cerberix/dnsmasq.d/ai-blocked.conf"
    if not os.path.exists(block_file):
        return {"success": False, "error": "No blocked domains"}
    try:
        with open(block_file) as f:
            lines = f.readlines()
        with open(block_file, "w") as f:
            for line in lines:
                if f"/{domain}/" not in line:
                    f.write(line)
        subprocess.run(["killall", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}
