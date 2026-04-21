"""
Cerberix Web API — Settings (2FA, Notifications, Password, Reports)
"""

import json
import os

from web.totp import (
    is_2fa_enabled, generate_secret, get_provisioning_uri,
    enable_2fa, disable_2fa,
)
from web.auth import change_password


def get_2fa_status():
    return {"enabled": is_2fa_enabled()}


def setup_2fa():
    """Generate a new TOTP secret for setup."""
    secret = generate_secret()
    uri = get_provisioning_uri(secret, "admin")
    return {"secret": secret, "uri": uri}


def confirm_2fa(code: str, secret: str):
    """Confirm and enable 2FA."""
    if enable_2fa(secret, code):
        return {"success": True}
    return {"success": False, "error": "Invalid code — try again"}


def remove_2fa():
    """Disable 2FA."""
    disable_2fa()
    return {"success": True}


def update_password(current: str, new_password: str):
    """Change admin password."""
    from web.auth import load_credentials, verify_password
    creds = load_credentials()
    if not creds:
        return {"success": False, "error": "No credentials found"}
    if not verify_password(current, creds["password_hash"], creds["salt"]):
        return {"success": False, "error": "Current password is wrong"}
    if len(new_password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters"}
    if change_password(new_password):
        # Invalidate all sessions — force re-login with new password
        from web.auth import _sessions, _lock
        with _lock:
            _sessions.clear()
        return {"success": True, "message": "Password changed. All sessions invalidated."}
    return {"success": False, "error": "Failed to update password"}


def _mask_secret(val: str) -> str:
    """Mask a secret value, showing only last 4 chars."""
    if not val or len(val) < 8:
        return "****" if val else ""
    return "****" + val[-4:]


def get_notifications_config():
    """Get notification settings (secrets masked)."""
    conf_path = "/etc/cerberix/notifications.conf"
    default = {
        "enabled": False,
        "min_severity": "high",
        "webhook": {"enabled": False, "url": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "discord": {"enabled": False, "webhook_url": ""},
    }
    if not os.path.exists(conf_path):
        return default
    try:
        with open(conf_path) as f:
            conf = json.load(f)
        # Mask secrets before returning
        if "webhook" in conf and conf["webhook"].get("url"):
            conf["webhook"]["url"] = _mask_secret(conf["webhook"]["url"])
        if "telegram" in conf and conf["telegram"].get("bot_token"):
            conf["telegram"]["bot_token"] = _mask_secret(conf["telegram"]["bot_token"])
        if "discord" in conf and conf["discord"].get("webhook_url"):
            conf["discord"]["webhook_url"] = _mask_secret(conf["discord"]["webhook_url"])
        return conf
    except (OSError, json.JSONDecodeError):
        return default


def save_notifications_config(config: dict):
    """Save notification settings."""
    conf_path = "/etc/cerberix/notifications.conf"
    try:
        with open(conf_path, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(conf_path, 0o600)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


def get_daily_report():
    """Get latest daily report."""
    from ai.daily_report import DailyReportGenerator
    gen = DailyReportGenerator()
    report = gen.get_latest()
    return report or {"summary": "No reports generated yet"}


def generate_daily_report():
    """Force generate a daily report."""
    from ai.daily_report import DailyReportGenerator
    from ai.claude_analyzer import ClaudeAnalyzer
    claude = ClaudeAnalyzer(
        api_key=os.environ.get("CERBERIX_AI_API_KEY"),
        model=os.environ.get("CERBERIX_AI_MODEL", "claude-sonnet-4-6"),
    )
    gen = DailyReportGenerator(claude_analyzer=claude)
    report = gen.generate(force=True)
    return report or {"error": "Report generation failed"}
