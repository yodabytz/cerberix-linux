"""
Cerberix AI — Alert Notifications

Sends security alerts to external channels:
- Webhook (generic HTTP POST)
- Telegram bot
- Discord webhook
"""

import json
import logging
import os
import threading
import time
import urllib.request
from typing import Optional

log = logging.getLogger("cerberix-ai")

NOTIFY_CONF = "/etc/cerberix/notifications.conf"


class NotificationEngine:
    """Sends alerts to configured channels."""

    def __init__(self):
        self._config = self._load_config()
        self._rate_limit: dict[str, float] = {}
        self._min_interval = 60  # Don't spam — max 1 alert per minute per channel

    def notify(self, alert: dict):
        """Send an alert to all configured channels."""
        if not self._config.get("enabled", False):
            return

        severity = alert.get("severity", "low")
        min_severity = self._config.get("min_severity", "high")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        if severity_order.get(severity, 3) > severity_order.get(min_severity, 1):
            return

        message = self._format_message(alert)

        # Send to each channel in background
        for channel in ["webhook", "telegram", "discord"]:
            if self._config.get(channel, {}).get("enabled"):
                if self._rate_check(channel):
                    threading.Thread(
                        target=self._send,
                        args=(channel, message, alert),
                        daemon=True,
                    ).start()

    def _get_hostname(self) -> str:
        try:
            with open("/etc/hostname") as f:
                return f.read().strip()
        except OSError:
            import socket
            return socket.gethostname()

    def _format_message(self, alert: dict) -> str:
        severity = alert.get("severity", "unknown").upper()
        detector = alert.get("detector", "unknown")
        target = alert.get("target", "")
        reason = alert.get("reason", alert.get("description", ""))
        ts = alert.get("timestamp", "")
        host = self._get_hostname()
        server = alert.get("server", "")

        msg = (
            f"🚨 Cerberix Alert [{severity}]\n"
            f"System: {host}\n"
            f"Detector: {detector}\n"
            f"Target: {target}\n"
        )
        if server:
            msg += f"Server: {server}\n"
        msg += (
            f"Reason: {reason}\n"
            f"Time: {ts}"
        )
        return msg

    def _send(self, channel: str, message: str, alert: dict):
        try:
            conf = self._config[channel]
            if channel == "webhook":
                self._send_webhook(conf, message, alert)
            elif channel == "telegram":
                self._send_telegram(conf, message)
            elif channel == "discord":
                self._send_discord(conf, message)
        except Exception as e:
            log.warning(f"Notification ({channel}) failed: {e}")

    def _validate_url(self, url: str) -> bool:
        """Block SSRF — only allow https:// to public hosts."""
        if not url or not url.startswith("https://"):
            return False
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Block internal/private IPs
        for prefix in ["127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                       "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                       "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                       "172.29.", "172.30.", "172.31.", "169.254.", "0."]:
            if host.startswith(prefix):
                return False
        if host in ["localhost", "metadata.google.internal"]:
            return False
        return True

    def _send_webhook(self, conf: dict, message: str, alert: dict):
        url = conf.get("url", "")
        if not self._validate_url(url):
            log.warning(f"Webhook URL rejected (SSRF protection): {url[:50]}")
            return
        data = json.dumps({"text": message, "alert": alert}).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_telegram(self, conf: dict, message: str):
        token = conf.get("bot_token", "")
        chat_id = conf.get("chat_id", "")
        if not token or not chat_id:
            return
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_discord(self, conf: dict, message: str):
        url = conf.get("webhook_url", "")
        if not self._validate_url(url):
            log.warning(f"Discord URL rejected (SSRF protection): {url[:50]}")
            return
        data = json.dumps({"content": message}).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _rate_check(self, channel: str) -> bool:
        now = time.time()
        last = self._rate_limit.get(channel, 0)
        if now - last < self._min_interval:
            return False
        self._rate_limit[channel] = now
        return True

    def _load_config(self) -> dict:
        if not os.path.exists(NOTIFY_CONF):
            return {"enabled": False}
        try:
            with open(NOTIFY_CONF) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"enabled": False}

    def reload_config(self):
        self._config = self._load_config()

    def get_config(self) -> dict:
        """Return config without secrets."""
        conf = dict(self._config)
        for ch in ["webhook", "telegram", "discord"]:
            if ch in conf and isinstance(conf[ch], dict):
                conf[ch] = {k: ("***" if "token" in k or "url" in k.lower() else v)
                            for k, v in conf[ch].items()}
        return conf

    def save_config(self, config: dict) -> bool:
        try:
            with open(NOTIFY_CONF, "w") as f:
                json.dump(config, f, indent=2)
            os.chmod(NOTIFY_CONF, 0o600)
            self._config = config
            return True
        except OSError:
            return False

    def test(self, channel: str) -> bool:
        """Send a test notification."""
        test_alert = {
            "severity": "medium",
            "detector": "test",
            "target": "127.0.0.1",
            "reason": "This is a test notification from Cerberix Firewall",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        message = self._format_message(test_alert)
        try:
            self._send(channel, message, test_alert)
            return True
        except Exception:
            return False
