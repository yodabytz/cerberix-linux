"""
Cerberix Web API — Suricata IDS
"""

import json
import os
import subprocess
import threading
import time
from collections import Counter

LOG_DIR = "/var/log/cerberix/suricata"

# Incremental IDS cache — only reads NEW lines from eve.json
_ids_cache = {
    "alerts": [], "signatures": Counter(), "sources": Counter(),
    "alert_count": 0, "last_update": 0, "file_pos": 0,
}
_ids_lock = threading.Lock()
_ids_thread_started = False
_MAX_ALERTS = 100


def _start_ids_cache_thread():
    global _ids_thread_started
    if _ids_thread_started:
        return
    _ids_thread_started = True

    # Initial load — read last 2000 lines only (fast)
    _load_recent()

    def _loop():
        while True:
            time.sleep(5)
            _read_new_lines()

    t = threading.Thread(target=_loop, daemon=True, name="ids-cache")
    t.start()


def _load_recent():
    """Fast initial load — tail last 2000 lines for alerts."""
    eve_file = f"{LOG_DIR}/eve.json"
    if not os.path.exists(eve_file):
        return

    try:
        # Grep for alerts only, take last 200
        grep_proc = subprocess.Popen(
            ["grep", '"event_type":"alert"', eve_file],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            ["tail", "-200"],
            stdin=grep_proc.stdout,
            capture_output=True, text=True, timeout=10,
        )
        grep_proc.wait()
        alerts = []
        sigs = Counter()
        sources = Counter()

        for line in result.stdout.strip().splitlines():
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                a = event.get("alert", {})
                sig = a.get("signature", "")
                src = event.get("src_ip", "")
                if sig:
                    sigs[sig] += 1
                if src:
                    sources[src] += 1
                alerts.append(_parse_alert(event, a))
            except json.JSONDecodeError:
                pass

        # Get total count fast
        total = 0
        try:
            cr = subprocess.run(
                ["grep", "-c", '"event_type":"alert"', eve_file],
                capture_output=True, text=True, timeout=5,
            )
            if cr.returncode == 0:
                total = int(cr.stdout.strip())
        except (subprocess.SubprocessError, ValueError):
            total = len(alerts)

        with _ids_lock:
            _ids_cache["alerts"] = alerts[-_MAX_ALERTS:]
            _ids_cache["signatures"] = sigs
            _ids_cache["sources"] = sources
            _ids_cache["alert_count"] = total
            _ids_cache["last_update"] = time.time()
            # Set file position to end
            _ids_cache["file_pos"] = os.path.getsize(eve_file)

    except (subprocess.SubprocessError, OSError):
        pass


def _read_new_lines():
    """Incremental read — only process lines added since last check."""
    eve_file = f"{LOG_DIR}/eve.json"
    if not os.path.exists(eve_file):
        return

    try:
        current_size = os.path.getsize(eve_file)
        with _ids_lock:
            pos = _ids_cache["file_pos"]

        # File was rotated
        if current_size < pos:
            pos = 0

        # No new data
        if current_size <= pos:
            return

        with open(eve_file) as f:
            f.seek(pos)
            new_data = f.read()
            new_pos = f.tell()

        new_alerts = []
        new_sigs = Counter()
        new_sources = Counter()

        for line in new_data.strip().splitlines():
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                a = event.get("alert", {})
                sig = a.get("signature", "")
                src = event.get("src_ip", "")
                if sig:
                    new_sigs[sig] += 1
                if src:
                    new_sources[src] += 1
                new_alerts.append(_parse_alert(event, a))
            except json.JSONDecodeError:
                pass

        if new_alerts or new_sigs:
            with _ids_lock:
                _ids_cache["alerts"].extend(new_alerts)
                _ids_cache["alerts"] = _ids_cache["alerts"][-_MAX_ALERTS:]
                _ids_cache["signatures"].update(new_sigs)
                _ids_cache["sources"].update(new_sources)
                _ids_cache["alert_count"] += len(new_alerts)
                _ids_cache["file_pos"] = new_pos
                _ids_cache["last_update"] = time.time()

    except OSError:
        pass


def _parse_alert(event, a):
    return {
        "timestamp": event.get("timestamp", "")[:19],
        "src_ip": event.get("src_ip", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", 0),
        "protocol": event.get("proto", ""),
        "signature": a.get("signature", ""),
        "signature_id": a.get("signature_id", 0),
        "category": a.get("category", ""),
        "severity": a.get("severity", 3),
        "action": a.get("action", ""),
    }


# ── API Functions ────────────────────────────────────────────

def get_status():
    """Get Suricata IDS status."""
    running = False
    try:
        result = subprocess.run(
            ["pgrep", "-x", "suricata"],
            capture_output=True, timeout=3,
        )
        running = result.returncode == 0
    except subprocess.SubprocessError:
        pass

    rule_count = 0
    rule_file = "/var/lib/suricata/rules/suricata.rules"
    if os.path.exists(rule_file):
        try:
            with open(rule_file) as f:
                rule_count = sum(1 for line in f if line.startswith(("alert", "drop", "pass")))
        except OSError:
            pass

    _start_ids_cache_thread()
    with _ids_lock:
        alert_count = _ids_cache["alert_count"]

    return {"running": running, "rules": rule_count, "alerts": alert_count}


def get_alerts(limit: int = 50):
    _start_ids_cache_thread()
    with _ids_lock:
        return {"alerts": list(_ids_cache["alerts"][-limit:][::-1])}


def get_top_signatures():
    _start_ids_cache_thread()
    with _ids_lock:
        return {"signatures": [
            {"name": s, "count": c}
            for s, c in _ids_cache["signatures"].most_common(20)
        ]}


def get_top_sources():
    _start_ids_cache_thread()
    with _ids_lock:
        return {"sources": [
            {"ip": ip, "count": c}
            for ip, c in _ids_cache["sources"].most_common(15)
        ]}


def update_rules():
    try:
        result = subprocess.run(
            ["cerberix-ids", "update-rules"],
            capture_output=True, text=True, timeout=120,
        )
        return {"success": result.returncode == 0, "output": result.stdout}
    except subprocess.SubprocessError as e:
        return {"success": False, "error": str(e)}
