"""
Cerberix Web API — Firewall Management
"""

import re
import subprocess


def get_rules():
    """Get current nftables ruleset."""
    try:
        result = subprocess.run(
            ["nft", "-a", "list", "ruleset"],
            capture_output=True, text=True, timeout=10,
        )
        return {"ruleset": result.stdout, "error": result.stderr if result.returncode else None}
    except subprocess.SubprocessError as e:
        return {"ruleset": "", "error": str(e)}


def get_counters():
    """Get packet/byte counters per chain."""
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return {"chains": [], "error": result.stderr}

        chains = []
        current_chain = None
        for line in result.stdout.splitlines():
            chain_match = re.match(r'\s+chain\s+(\w+)\s+\{', line)
            if chain_match:
                current_chain = {"name": chain_match.group(1), "rules": 0, "drops": 0, "accepts": 0}
                chains.append(current_chain)
            elif current_chain:
                if "accept" in line:
                    current_chain["accepts"] += 1
                    current_chain["rules"] += 1
                elif "drop" in line:
                    current_chain["drops"] += 1
                    current_chain["rules"] += 1

        return {"chains": chains}
    except subprocess.SubprocessError as e:
        return {"chains": [], "error": str(e)}


def block_ip(ip: str, duration: int = 3600):
    """Manually block an IP address."""
    if not _validate_ip(ip):
        return {"success": False, "error": "Invalid IP address"}
    if duration < 0 or duration > 2592000:  # Max 30 days
        return {"success": False, "error": "Duration must be 0-2592000 seconds"}

    nft_args = ["nft", "add", "element", "inet", "cerberix_ai", "blocklist",
                "{", ip]
    if duration > 0:
        nft_args.extend(["timeout", f"{duration}s"])
    nft_args.append("}")

    try:
        result = subprocess.run(
            nft_args, capture_output=True, text=True, timeout=5,
        )
        return {"success": result.returncode == 0, "error": result.stderr if result.returncode else None}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def unblock_ip(ip: str):
    """Remove an IP from the blocklist."""
    if not _validate_ip(ip):
        return {"success": False, "error": "Invalid IP address"}

    try:
        result = subprocess.run(
            ["nft", "delete", "element", "inet", "cerberix_ai", "blocklist",
             "{", ip, "}"],
            capture_output=True, text=True, timeout=5,
        )
        return {"success": result.returncode == 0, "error": result.stderr if result.returncode else None}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def flush_ai_blocks():
    """Flush all AI-generated blocks."""
    try:
        result = subprocess.run(
            ["nft", "flush", "set", "inet", "cerberix_ai", "blocklist"],
            capture_output=True, text=True, timeout=5,
        )
        return {"success": result.returncode == 0}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}


def _validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and all(
        0 <= int(octet) <= 255 for octet in ip.split('.')
    )
