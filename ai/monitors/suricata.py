"""
Cerberix AI — Suricata IDS Alert Monitor

Watches Suricata's eve.json log and feeds alerts into the AI engine.
High-severity IDS alerts trigger auto-blocking.
"""

import json
import os
import time
import threading
import logging

log = logging.getLogger("cerberix-ai")

EVE_LOG = "/var/log/cerberix/suricata/eve.json"


class SuricataMonitor:
    """Monitors Suricata eve.json and extracts alerts."""

    def __init__(self, data_dir="/var/lib/cerberix/ai"):
        self.data_dir = data_dir
        self._file_pos = 0
        self._running = False
        self._alerts: list[dict] = []
        self._stats = {
            "total_alerts": 0,
            "by_severity": {1: 0, 2: 0, 3: 0},
            "by_category": {},
            "top_sources": {},
            "top_signatures": {},
        }
        self._max_alerts = 500
        self._lock = threading.Lock()

    def start(self):
        self._running = True
        t = threading.Thread(target=self._watch_loop, daemon=True, name="suricata-mon")
        t.start()

    def stop(self):
        self._running = False

    def get_alerts(self, limit=50) -> list[dict]:
        with self._lock:
            return self._alerts[-limit:][::-1]

    def get_stats(self) -> dict:
        with self._lock:
            import subprocess
            try:
                result = subprocess.run(["pgrep", "-x", "suricata"],
                    capture_output=True, timeout=3)
                running = result.returncode == 0
            except subprocess.SubprocessError:
                running = False
            return {
                "running": running,
                **self._stats,
                "top_sources": sorted(
                    self._stats["top_sources"].items(),
                    key=lambda x: x[1], reverse=True
                )[:10],
                "top_signatures": sorted(
                    self._stats["top_signatures"].items(),
                    key=lambda x: x[1], reverse=True
                )[:15],
            }

    def _watch_loop(self):
        log.info(f"Suricata monitor watching: {EVE_LOG}")
        while self._running:
            try:
                if not os.path.exists(EVE_LOG):
                    time.sleep(5)
                    continue

                with open(EVE_LOG) as f:
                    f.seek(self._file_pos)
                    while self._running:
                        line = f.readline()
                        if not line:
                            self._file_pos = f.tell()
                            # Check for rotation
                            try:
                                if os.path.getsize(EVE_LOG) < self._file_pos:
                                    self._file_pos = 0
                                    break
                            except OSError:
                                break
                            time.sleep(1)
                            continue
                        self._process_line(line)

            except OSError as e:
                log.warning(f"Suricata monitor error: {e}")
                time.sleep(5)

    def _process_line(self, line: str):
        try:
            event = json.loads(line.strip())
        except json.JSONDecodeError:
            return

        event_type = event.get("event_type")
        if event_type != "alert":
            return

        alert = event.get("alert", {})
        severity = alert.get("severity", 3)
        signature = alert.get("signature", "Unknown")
        category = alert.get("category", "Unknown")
        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")
        dest_port = event.get("dest_port", 0)

        parsed = {
            "timestamp": event.get("timestamp", ""),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": event.get("proto", ""),
            "signature": signature,
            "signature_id": alert.get("signature_id", 0),
            "category": category,
            "severity": severity,
            "action": alert.get("action", ""),
        }

        with self._lock:
            self._alerts.append(parsed)
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts:]

            self._stats["total_alerts"] += 1
            self._stats["by_severity"][severity] = \
                self._stats["by_severity"].get(severity, 0) + 1
            self._stats["by_category"][category] = \
                self._stats["by_category"].get(category, 0) + 1
            self._stats["top_sources"][src_ip] = \
                self._stats["top_sources"].get(src_ip, 0) + 1
            self._stats["top_signatures"][signature] = \
                self._stats["top_signatures"].get(signature, 0) + 1

        # Log high severity alerts to the AI threat log
        if severity <= 2:
            self._log_to_threats(parsed)

    def _log_to_threats(self, alert: dict):
        """Feed high-severity IDS alerts into the AI threat log."""
        sev_map = {1: "critical", 2: "high", 3: "medium"}
        # Map dest_ip to server name
        dest = alert.get("dest_ip", "")
        server_map = {
            "192.168.1.1": "Cerberix Gateway",
            "50.21.187.13": "quantumbytz.com",
            "54.39.90.215": "vibrixmedia.com",
        }
        server = server_map.get(dest, dest)

        entry = {
            "timestamp": alert["timestamp"],
            "epoch": time.time(),
            "action": "ids_alert",
            "target": alert["src_ip"],
            "server": server,
            "server_ip": dest,
            "reason": f"IDS: {alert['signature']} ({alert['category']})",
            "severity": sev_map.get(alert["severity"], "medium"),
            "detector": "suricata",
        }
        try:
            with open("/var/log/cerberix/ai-threats.log", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
