"""
Cerberix AI — Bandwidth Monitor

Tracks per-interface throughput and stores history for dashboard graphs.
"""

import json
import os
import time
import threading


class BandwidthMonitor:
    """Monitors interface bandwidth and stores rolling history."""

    def __init__(self, data_dir="/var/lib/cerberix/ai", interval=5):
        self.data_dir = data_dir
        self.interval = interval
        self._history: list[dict] = []
        self._max_history = 720  # 1 hour at 5s intervals
        self._prev: dict[str, dict] = {}
        self._running = False

        os.makedirs(data_dir, exist_ok=True)
        self._load_history()

    def start(self):
        """Start monitoring in a background thread."""
        self._running = True
        t = threading.Thread(target=self._monitor_loop, daemon=True, name="bw-monitor")
        t.start()

    def stop(self):
        self._running = False

    def get_history(self, points=120) -> list[dict]:
        """Return recent bandwidth history."""
        return self._history[-points:]

    def get_current(self) -> dict:
        """Return current bandwidth rates."""
        if self._history:
            return self._history[-1]
        return {}

    def _monitor_loop(self):
        while self._running:
            try:
                snapshot = self._read_interfaces()
                if snapshot:
                    self._history.append(snapshot)
                    if len(self._history) > self._max_history:
                        self._history = self._history[-self._max_history:]
                    # Save periodically
                    if len(self._history) % 12 == 0:
                        self._save_history()
            except Exception:
                pass
            time.sleep(self.interval)

    def _read_interfaces(self) -> dict:
        """Read current interface stats from /proc/net/dev."""
        now = time.time()
        snapshot = {"timestamp": now, "interfaces": {}}

        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    parts = line.split()
                    iface = parts[0].rstrip(":")
                    if iface == "lo":
                        continue

                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    rx_packets = int(parts[2])
                    tx_packets = int(parts[10])

                    # Calculate rates if we have previous data
                    rate = {"rx_bps": 0, "tx_bps": 0, "rx_pps": 0, "tx_pps": 0}
                    if iface in self._prev:
                        prev = self._prev[iface]
                        dt = now - prev["time"]
                        if dt > 0:
                            rate["rx_bps"] = int((rx_bytes - prev["rx_bytes"]) / dt)
                            rate["tx_bps"] = int((tx_bytes - prev["tx_bytes"]) / dt)
                            rate["rx_pps"] = int((rx_packets - prev["rx_packets"]) / dt)
                            rate["tx_pps"] = int((tx_packets - prev["tx_packets"]) / dt)

                    self._prev[iface] = {
                        "time": now, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
                        "rx_packets": rx_packets, "tx_packets": tx_packets,
                    }

                    snapshot["interfaces"][iface] = {
                        "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
                        **rate,
                    }

        except (OSError, ValueError, IndexError):
            pass

        return snapshot

    def _save_history(self):
        path = os.path.join(self.data_dir, "bandwidth_history.json")
        try:
            with open(path + ".tmp", "w") as f:
                json.dump(self._history[-200:], f)
            os.rename(path + ".tmp", path)
        except OSError:
            pass

    def _load_history(self):
        path = os.path.join(self.data_dir, "bandwidth_history.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self._history = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
