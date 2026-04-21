"""
Cerberix Web — TOTP Two-Factor Authentication

Implements RFC 6238 TOTP using stdlib only (hmac + struct).
Compatible with Google Authenticator, Authy, etc.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Optional

TOTP_CONF = "/etc/cerberix/totp.conf"


def _hotp(key: bytes, counter: int) -> str:
    """Generate HOTP code (RFC 4226)."""
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


def generate_totp(secret: bytes, time_step: int = 30) -> str:
    """Generate current TOTP code."""
    counter = int(time.time()) // time_step
    return _hotp(secret, counter)


def verify_totp(secret: bytes, code: str, time_step: int = 30, window: int = 1) -> bool:
    """Verify a TOTP code with time window tolerance."""
    counter = int(time.time()) // time_step
    for offset in range(-window, window + 1):
        if _hotp(secret, counter + offset) == code.strip():
            return True
    return False


def generate_secret() -> str:
    """Generate a random TOTP secret (base32 encoded)."""
    return base64.b32encode(os.urandom(20)).decode()


def secret_to_bytes(secret_b32: str) -> bytes:
    """Convert base32 secret to bytes."""
    return base64.b32decode(secret_b32)


def get_provisioning_uri(secret_b32: str, username: str, issuer: str = "Cerberix") -> str:
    """Generate otpauth:// URI for QR code scanning."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def is_2fa_enabled() -> bool:
    """Check if 2FA is configured."""
    if not os.path.exists(TOTP_CONF):
        return False
    try:
        with open(TOTP_CONF) as f:
            conf = json.load(f)
        return conf.get("enabled", False)
    except (OSError, json.JSONDecodeError):
        return False


def get_2fa_secret() -> Optional[str]:
    """Get stored TOTP secret."""
    if not os.path.exists(TOTP_CONF):
        return None
    try:
        with open(TOTP_CONF) as f:
            conf = json.load(f)
        return conf.get("secret")
    except (OSError, json.JSONDecodeError):
        return None


def enable_2fa(secret_b32: str, code: str) -> bool:
    """Enable 2FA after verifying a code."""
    secret = secret_to_bytes(secret_b32)
    if not verify_totp(secret, code):
        return False
    conf = {"enabled": True, "secret": secret_b32}
    try:
        with open(TOTP_CONF, "w") as f:
            json.dump(conf, f)
        os.chmod(TOTP_CONF, 0o600)
        return True
    except OSError:
        return False


def disable_2fa() -> bool:
    """Disable 2FA."""
    try:
        if os.path.exists(TOTP_CONF):
            os.remove(TOTP_CONF)
        return True
    except OSError:
        return False


def verify_login_2fa(code: str) -> bool:
    """Verify 2FA code during login."""
    secret_b32 = get_2fa_secret()
    if not secret_b32:
        return False
    return verify_totp(secret_to_bytes(secret_b32), code)
