"""
Cerberix AI — CLI Interface

Provides command-line tools for interacting with the AI engine.
"""

import argparse
import json
import os
import subprocess
import sys
import time


def cmd_status():
    """Show AI engine status."""
    stats_path = "/var/lib/cerberix/ai/engine_stats.json"
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            stats = json.load(f)
        uptime = time.time() - stats.get("start_time", 0)
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        print("Cerberix AI Engine Status")
        print("=" * 40)
        print(f"  Uptime           : {hours}h {minutes}m")
        print(f"  Events processed : {stats.get('events_processed', 0)}")
        print(f"  Alerts generated : {stats.get('alerts_generated', 0)}")
        print(f"  IPs blocked      : {stats.get('ips_blocked', 0)}")
        print(f"  Domains blocked  : {stats.get('domains_blocked', 0)}")
        print(f"  Claude analyses  : {stats.get('claude_analyses', 0)}")
    else:
        print("AI engine not running or no stats available.")


def cmd_blocklist():
    """Show current blocklist."""
    bl_path = "/var/lib/cerberix/ai/blocklist.json"
    if os.path.exists(bl_path):
        with open(bl_path) as f:
            data = json.load(f)
        if not data:
            print("Blocklist is empty.")
            return
        print(f"{'IP':<18} {'Severity':<10} {'Detector':<12} {'Reason'}")
        print("-" * 80)
        for ip, entry in data.items():
            print(
                f"{ip:<18} {entry.get('severity', '?'):<10} "
                f"{entry.get('detector', '?'):<12} "
                f"{entry.get('reason', '')[:40]}"
            )
    else:
        print("No blocklist data found.")


def cmd_unblock(ip: str):
    """Remove an IP from the blocklist."""
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        print(f"Invalid IP: {ip}")
        return
    try:
        subprocess.run(
            ["nft", "delete", "element", "inet", "cerberix_ai", "blocklist", "{", ip, "}"],
            capture_output=True, timeout=5,
        )
    except subprocess.SubprocessError:
        pass

    bl_path = "/var/lib/cerberix/ai/blocklist.json"
    if os.path.exists(bl_path):
        with open(bl_path) as f:
            data = json.load(f)
        if ip in data:
            del data[ip]
            with open(bl_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Unblocked: {ip}")
        else:
            print(f"IP {ip} not found in blocklist.")
    else:
        print("No blocklist data found.")


def cmd_threats():
    """Show recent threat events."""
    log_path = "/var/log/cerberix/ai-threats.log"
    if not os.path.exists(log_path):
        print("No threat log found.")
        return

    with open(log_path) as f:
        lines = f.readlines()

    recent = lines[-20:]  # Last 20 events
    for line in recent:
        try:
            event = json.loads(line)
            ts = event.get("timestamp", "?")
            action = event.get("action", "?")
            target = event.get("target", "?")
            severity = event.get("severity", "?")
            print(f"  {ts}  [{severity:<8}] {action:<16} {target}")
        except json.JSONDecodeError:
            pass


def cmd_analyze():
    """Show recent Claude analyses."""
    log_path = "/var/log/cerberix/ai-analysis.log"
    if not os.path.exists(log_path):
        print("No analysis log found.")
        return

    with open(log_path) as f:
        lines = f.readlines()

    recent = lines[-10:]
    for line in recent:
        try:
            entry = json.loads(line)
            print(
                f"  {entry.get('timestamp', '?')}  "
                f"assessment={entry.get('assessment', '?')}  "
                f"confidence={entry.get('confidence', '?')}  "
                f"{entry.get('summary', '')}"
            )
        except json.JSONDecodeError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Cerberix AI — Threat Detection CLI"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Show AI engine status")
    subparsers.add_parser("blocklist", help="Show blocked IPs")
    subparsers.add_parser("threats", help="Show recent threats")
    subparsers.add_parser("analyze", help="Show Claude analyses")

    unblock_parser = subparsers.add_parser("unblock", help="Unblock an IP")
    unblock_parser.add_argument("ip", help="IP address to unblock")

    args = parser.parse_args()

    commands = {
        "status": cmd_status,
        "blocklist": cmd_blocklist,
        "threats": cmd_threats,
        "analyze": cmd_analyze,
    }

    if args.command == "unblock":
        cmd_unblock(args.ip)
    elif args.command in commands:
        commands[args.command]()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
