"""
Cerberix Web API — Content Filtering

DNS-based content filtering with category blocklists.
Uses dnsmasq address records to sinkhole domains by category.
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from typing import Optional

log = logging.getLogger("cerberix-web")

FILTER_CONF = "/etc/cerberix/content-filter.conf"
FILTER_DIR = "/var/lib/cerberix/content-filter"
DNSMASQ_FILTER = "/etc/cerberix/dnsmasq.d/content-filter.conf"
WHITELIST_FILE = "/etc/cerberix/content-filter-whitelist.conf"
BLACKLIST_FILE = "/etc/cerberix/content-filter-blacklist.conf"

# Category blocklist sources (well-known, maintained lists)
BLOCKLIST_SOURCES = {
    "malware": {
        "name": "Malware",
        "description": "Known malware distribution domains",
        "urls": [
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
        ],
    },
    "ads": {
        "name": "Ads & Trackers",
        "description": "Advertising and tracking domains",
        "urls": [
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        ],
    },
    "porn": {
        "name": "Adult Content",
        "description": "Pornography and adult content domains",
        "urls": [
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
        ],
    },
    "gambling": {
        "name": "Gambling",
        "description": "Online gambling and betting sites",
        "urls": [
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
        ],
    },
    "social": {
        "name": "Social Media",
        "description": "Social media platforms (Facebook, TikTok, Instagram, etc.)",
        "urls": [
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/social.txt",
        ],
    },
    "fakenews": {
        "name": "Fake News",
        "description": "Known disinformation and fake news sites",
        "urls": [
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt",
        ],
    },
}

# Background stats cache
_filter_cache = {"stats": {}, "last_update": 0}
_filter_lock = threading.Lock()
_filter_thread_started = False


def _ensure_dirs():
    os.makedirs(FILTER_DIR, exist_ok=True)
    for path in [FILTER_CONF, WHITELIST_FILE, BLACKLIST_FILE]:
        if not os.path.exists(path):
            if path == FILTER_CONF:
                _save_config({"enabled": False, "categories": {}, "schedule": {}})
            else:
                with open(path, "w") as f:
                    f.write("")


def _load_config() -> dict:
    _ensure_dirs()
    try:
        with open(FILTER_CONF) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "categories": {}, "schedule": {}}


def _save_config(config: dict):
    os.makedirs(os.path.dirname(FILTER_CONF), exist_ok=True)
    with open(FILTER_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(FILTER_CONF, 0o600)


def _parse_hosts_file(content: str) -> set:
    """Parse a hosts-format blocklist, extracting domains."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].strip().lower()
            if domain and domain != "localhost" and "." in domain:
                domains.add(domain)
    return domains


def _load_whitelist() -> set:
    try:
        with open(WHITELIST_FILE) as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def _load_blacklist() -> set:
    try:
        with open(BLACKLIST_FILE) as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def _rebuild_dnsmasq_filter():
    """Rebuild the dnsmasq filter config from all enabled category lists."""
    config = _load_config()
    if not config.get("enabled"):
        # Remove filter file if disabled
        if os.path.exists(DNSMASQ_FILTER):
            os.remove(DNSMASQ_FILTER)
            _reload_dnsmasq()
        return

    whitelist = _load_whitelist()
    blacklist = _load_blacklist()
    all_domains = set()

    # Load domains from each enabled category
    for cat_id, cat_conf in config.get("categories", {}).items():
        if not cat_conf.get("enabled"):
            continue
        list_file = os.path.join(FILTER_DIR, f"{cat_id}.list")
        if os.path.exists(list_file):
            try:
                with open(list_file) as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and domain not in whitelist:
                            all_domains.add(domain)
            except OSError:
                pass

    # Add custom blacklist
    all_domains.update(blacklist - whitelist)

    # Write dnsmasq config
    with open(DNSMASQ_FILTER, "w") as f:
        f.write("# Cerberix Content Filter — Auto-generated\n")
        f.write(f"# {len(all_domains)} domains blocked\n")
        f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for domain in sorted(all_domains):
            f.write(f"address=/{domain}/0.0.0.0\n")

    _reload_dnsmasq()
    log.info(f"Content filter rebuilt: {len(all_domains)} domains blocked")


def _reload_dnsmasq():
    try:
        subprocess.run(["killall", "-HUP", "dnsmasq"], capture_output=True, timeout=5)
    except subprocess.SubprocessError:
        pass


def _download_list(category: str) -> dict:
    """Download blocklist for a category."""
    if category not in BLOCKLIST_SOURCES:
        return {"success": False, "error": f"Unknown category: {category}"}

    _ensure_dirs()
    source = BLOCKLIST_SOURCES[category]
    all_domains = set()

    for url in source["urls"]:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Cerberix/0.3.0"})
            resp = urllib.request.urlopen(req, timeout=30)
            content = resp.read().decode("utf-8", errors="ignore")
            domains = _parse_hosts_file(content)
            all_domains.update(domains)
        except Exception as e:
            log.warning(f"Failed to download {url}: {e}")

    if not all_domains:
        return {"success": False, "error": "No domains downloaded"}

    # Save domain list
    list_file = os.path.join(FILTER_DIR, f"{category}.list")
    with open(list_file, "w") as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")

    return {"success": True, "count": len(all_domains)}


# ── API Functions ────────────────────────────────────────────

def get_status():
    """Get content filter status and category info."""
    config = _load_config()
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()

    categories = []
    total_blocked = 0
    for cat_id, source in BLOCKLIST_SOURCES.items():
        cat_conf = config.get("categories", {}).get(cat_id, {})
        list_file = os.path.join(FILTER_DIR, f"{cat_id}.list")
        count = 0
        if os.path.exists(list_file):
            try:
                with open(list_file) as f:
                    count = sum(1 for _ in f)
            except OSError:
                pass

        enabled = cat_conf.get("enabled", False)
        if enabled:
            total_blocked += count

        categories.append({
            "id": cat_id,
            "name": source["name"],
            "description": source["description"],
            "enabled": enabled,
            "domain_count": count,
            "last_updated": cat_conf.get("last_updated", ""),
        })

    # Count actual filter file
    filter_count = 0
    if os.path.exists(DNSMASQ_FILTER):
        try:
            with open(DNSMASQ_FILTER) as f:
                filter_count = sum(1 for line in f if line.startswith("address="))
        except OSError:
            pass

    return {
        "enabled": config.get("enabled", False),
        "categories": categories,
        "total_blocked_domains": filter_count,
        "whitelist_count": len(whitelist),
        "blacklist_count": len(blacklist),
    }


def toggle_filter(enabled: bool):
    """Enable or disable content filtering."""
    config = _load_config()
    config["enabled"] = enabled
    _save_config(config)
    _rebuild_dnsmasq_filter()
    return {"success": True, "enabled": enabled}


def toggle_category(category: str, enabled: bool):
    """Enable or disable a specific category."""
    if category not in BLOCKLIST_SOURCES:
        return {"success": False, "error": "Unknown category"}

    config = _load_config()
    if "categories" not in config:
        config["categories"] = {}
    if category not in config["categories"]:
        config["categories"][category] = {}
    config["categories"][category]["enabled"] = enabled
    _save_config(config)

    # Download if enabling and no list exists
    if enabled:
        list_file = os.path.join(FILTER_DIR, f"{category}.list")
        if not os.path.exists(list_file) or os.path.getsize(list_file) == 0:
            result = _download_list(category)
            if result["success"]:
                config["categories"][category]["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                _save_config(config)

    _rebuild_dnsmasq_filter()
    return {"success": True}


def update_lists():
    """Re-download all enabled category lists."""
    config = _load_config()
    results = {}
    for cat_id, cat_conf in config.get("categories", {}).items():
        if cat_conf.get("enabled"):
            result = _download_list(cat_id)
            results[cat_id] = result
            if result["success"]:
                config["categories"][cat_id]["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _save_config(config)
    _rebuild_dnsmasq_filter()
    return {"success": True, "results": results}


def get_whitelist():
    """Get whitelisted domains."""
    return {"domains": sorted(_load_whitelist())}


def get_blacklist():
    """Get custom blacklisted domains."""
    return {"domains": sorted(_load_blacklist())}


def add_whitelist(domain: str):
    """Add a domain to the whitelist."""
    domain = domain.strip().lower()
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {"success": False, "error": "Invalid domain"}
    wl = _load_whitelist()
    wl.add(domain)
    with open(WHITELIST_FILE, "w") as f:
        for d in sorted(wl):
            f.write(d + "\n")
    _rebuild_dnsmasq_filter()
    return {"success": True}


def remove_whitelist(domain: str):
    """Remove a domain from the whitelist."""
    wl = _load_whitelist()
    wl.discard(domain.strip().lower())
    with open(WHITELIST_FILE, "w") as f:
        for d in sorted(wl):
            f.write(d + "\n")
    _rebuild_dnsmasq_filter()
    return {"success": True}


def add_blacklist(domain: str):
    """Add a domain to the custom blacklist."""
    domain = domain.strip().lower()
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return {"success": False, "error": "Invalid domain"}
    bl = _load_blacklist()
    bl.add(domain)
    with open(BLACKLIST_FILE, "w") as f:
        for d in sorted(bl):
            f.write(d + "\n")
    _rebuild_dnsmasq_filter()
    return {"success": True}


def remove_blacklist(domain: str):
    """Remove a domain from the custom blacklist."""
    bl = _load_blacklist()
    bl.discard(domain.strip().lower())
    with open(BLACKLIST_FILE, "w") as f:
        for d in sorted(bl):
            f.write(d + "\n")
    _rebuild_dnsmasq_filter()
    return {"success": True}


def search_blocked(query: str):
    """Search across all blocklists for a domain."""
    query = query.strip().lower()
    if not query:
        return {"results": []}

    results = []
    whitelist = _load_whitelist()
    blacklist = _load_blacklist()

    if query in whitelist:
        results.append({"domain": query, "source": "whitelist", "status": "allowed"})
    if query in blacklist:
        results.append({"domain": query, "source": "custom blacklist", "status": "blocked"})

    for cat_id, source in BLOCKLIST_SOURCES.items():
        list_file = os.path.join(FILTER_DIR, f"{cat_id}.list")
        if os.path.exists(list_file):
            try:
                with open(list_file) as f:
                    for line in f:
                        if query in line.strip().lower():
                            results.append({
                                "domain": line.strip(),
                                "source": source["name"],
                                "status": "whitelisted" if line.strip() in whitelist else "blocked",
                            })
                            if len(results) >= 50:
                                break
            except OSError:
                pass
        if len(results) >= 50:
            break

    return {"results": results, "query": query}
