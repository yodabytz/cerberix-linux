"""
Cerberix Web — Authentication & Session Management

- PBKDF2-SHA256 password hashing (stdlib only)
- HMAC-signed session tokens
- CSRF token generation
- Login rate limiting
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Optional


# Session storage (in-memory — no persistence needed for a single-process appliance)
_sessions: dict[str, dict] = {}
_failed_logins: dict[str, list[float]] = {}
_server_secret = secrets.token_bytes(32)
_lock = threading.Lock()

WEBUI_CONF = "/etc/cerberix/ssl/webui.conf"
SESSION_MAX_AGE = 28800      # 8 hours absolute
SESSION_IDLE_TIMEOUT = 1800  # 30 minutes idle
RATE_LIMIT_WINDOW = 300      # 5 minutes
RATE_LIMIT_MAX = 5           # max failures per window


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Hash password with PBKDF2-SHA256. Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify password against stored hash."""
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return hmac.compare_digest(dk.hex(), stored_hash)


def create_initial_config(username: str, password: str):
    """Create initial webui.conf with hashed credentials."""
    pw_hash, salt = hash_password(password)
    config = {
        "username": username,
        "password_hash": pw_hash,
        "salt": salt,
    }
    os.makedirs(os.path.dirname(WEBUI_CONF), exist_ok=True)
    with open(WEBUI_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(WEBUI_CONF, 0o600)


def load_credentials() -> Optional[dict]:
    """Load credentials from webui.conf."""
    if not os.path.exists(WEBUI_CONF):
        return None
    try:
        with open(WEBUI_CONF) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def check_rate_limit(client_ip: str) -> bool:
    """Returns True if login is allowed, False if rate-limited."""
    with _lock:
        now = time.time()
        if client_ip not in _failed_logins:
            return True
        _failed_logins[client_ip] = [
            t for t in _failed_logins[client_ip]
            if now - t < RATE_LIMIT_WINDOW
        ]
        return len(_failed_logins[client_ip]) < RATE_LIMIT_MAX


def record_failed_login(client_ip: str):
    """Record a failed login attempt."""
    with _lock:
        if client_ip not in _failed_logins:
            _failed_logins[client_ip] = []
        _failed_logins[client_ip].append(time.time())


def create_session(username: str) -> str:
    """Create a new session, return session ID."""
    session_id = secrets.token_hex(32)
    with _lock:
        _sessions[session_id] = {
            "username": username,
            "created": time.time(),
            "last_active": time.time(),
            "csrf_token": secrets.token_hex(16),
        }
    return session_id


def validate_session(session_id: str) -> Optional[dict]:
    """Validate session. Returns session data or None."""
    with _lock:
        if not session_id or session_id not in _sessions:
            return None
        session = _sessions[session_id]
        now = time.time()
        if now - session["created"] > SESSION_MAX_AGE:
            del _sessions[session_id]
            return None
        if now - session["last_active"] > SESSION_IDLE_TIMEOUT:
            del _sessions[session_id]
            return None
        session["last_active"] = now
        return session.copy()  # Return copy to avoid races


def destroy_session(session_id: str):
    """Destroy a session."""
    with _lock:
        _sessions.pop(session_id, None)


def authenticate(username: str, password: str) -> Optional[str]:
    """Authenticate user. Returns session_id on success, None on failure."""
    creds = load_credentials()
    if not creds:
        return None
    if username != creds.get("username"):
        return None
    if not verify_password(password, creds["password_hash"], creds["salt"]):
        return None
    return create_session(username)


def change_password(new_password: str) -> bool:
    """Change the admin password."""
    creds = load_credentials()
    if not creds:
        return False
    pw_hash, salt = hash_password(new_password)
    creds["password_hash"] = pw_hash
    creds["salt"] = salt
    try:
        with open(WEBUI_CONF, "w") as f:
            json.dump(creds, f, indent=2)
        return True
    except OSError:
        return False
