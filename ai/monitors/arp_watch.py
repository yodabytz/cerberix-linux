"""
Cerberix AI — ARP Spoofing Detector

Monitors the ARP table for IP-MAC binding changes that indicate
ARP spoofing / MITM attacks on the LAN.
"""

import json
import os
import subprocess
import time
import threading
import logging

log = logging.getLogger("cerberix-ai")


class ARPWatcher:
    """Watches for ARP table changes that indicate spoofing."""

    def __init__(self, data_dir="/var/lib/cerberix/ai", check_interval=15):
        self.data_dir = data_dir
        self.check_interval = check_interval
        self._known_bindings: dict[str, str] = {}  # ip -> mac
        self._alerts: list[dict] = []
        self._running = False

        self._load_bindings()

    def start(self):
        self._running = True
        t = threading.Thread(target=self._watch_loop, daemon=True, name="arp-watcher")
        t.start()

    def stop(self):
        self._running = False

    def get_alerts(self) -> list[dict]:
        return self._alerts[-50:]

    def get_bindings(self) -> dict:
        return dict(self._known_bindings)

    def _watch_loop(self):
        while self._running:
            try:
                self._check_arp()
            except Exception:
                pass
            time.sleep(self.check_interval)

    def _check_arp(self):
        """Read ARP table and check for changes."""
        try:
            result = subprocess.run(
                ["ip", "neigh"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return

            current: dict[str, str] = {}
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) < 5 or "lladdr" not in line:
                    continue
                ip = parts[0]
                mac_idx = parts.index("lladdr") + 1 if "lladdr" in parts else -1
                if mac_idx > 0 and mac_idx < len(parts):
                    mac = parts[mac_idx].lower()
                    current[ip] = mac

            # Check for changes
            for ip, mac in current.items():
                if ip in self._known_bindings:
                    old_mac = self._known_bindings[ip]
                    if old_mac != mac:
                        alert = {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            "type": "arp_spoof",
                            "severity": "critical",
                            "ip": ip,
                            "old_mac": old_mac,
                            "new_mac": mac,
                            "description": (
                                f"ARP spoofing detected: {ip} changed from "
                                f"{old_mac} to {mac}"
                            ),
                        }
                        self._alerts.append(alert)
                        log.warning(
                            f"[CRITICAL] [arp_spoof] {alert['description']}"
                        )

                        # Log to threat file
                        self._log_alert(alert)

            # Update known bindings
            self._known_bindings.update(current)
            self._save_bindings()

        except subprocess.SubprocessError:
            pass

    def _log_alert(self, alert):
        log_path = "/var/log/cerberix/ai-threats.log"
        try:
            entry = {**alert, "detector": "arp_watch", "action": "alert",
                     "target": alert["ip"], "epoch": time.time()}
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _save_bindings(self):
        path = os.path.join(self.data_dir, "arp_bindings.json")
        try:
            with open(path + ".tmp", "w") as f:
                json.dump(self._known_bindings, f, indent=2)
            os.rename(path + ".tmp", path)
        except OSError:
            pass

    def _load_bindings(self):
        path = os.path.join(self.data_dir, "arp_bindings.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self._known_bindings = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
