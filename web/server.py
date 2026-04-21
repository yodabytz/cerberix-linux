"""
Cerberix Web — HTTPS Server

Stdlib-only HTTP server with TLS, routing, session auth, and security headers.
"""

import gzip
import http.server
import json
import logging
import mimetypes
import os
import re
import ssl
import socketserver
import time
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

# Pre-compressed file cache — compress once, serve many times
_file_cache: dict[str, tuple[bytes, bytes, str]] = {}  # path -> (raw, gzipped, mime)

from web.auth import (
    authenticate, validate_session, destroy_session,
    check_rate_limit, record_failed_login,
)
from web.api import dashboard, firewall, network, threats, system, dns, security, ids, settings, content_filter, vlans, qos, ai_rules, captive_portal

log = logging.getLogger("cerberix-web")

STATIC_DIR = "/opt/cerberix/web/static"
TEMPLATE_DIR = "/opt/cerberix/web/templates"
CERT_FILE = "/etc/cerberix/ssl/cert.pem"
KEY_FILE = "/etc/cerberix/ssl/key.pem"
AUDIT_LOG = "/var/log/cerberix/webui-audit.log"


def audit(action: str, detail: str, user: str = "", ip: str = ""):
    """Write to audit log."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": user, "ip": ip, "action": action, "detail": detail,
    }
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# ── Route definitions ───────────────────────────────────────
# (method, path_regex) -> handler_func
# Handler receives (handler_instance, match, body) returns (status, data)
ROUTES: list[tuple[str, str, callable]] = []


def route(method: str, pattern: str):
    """Decorator to register a route."""
    def decorator(func):
        ROUTES.append((method, re.compile(f"^{pattern}$"), func))
        return func
    return decorator


# ── Auth routes (no session required) ───────────────────────

@route("POST", "/api/auth/login")
def handle_login(handler, match, body):
    from web.totp import is_2fa_enabled, verify_login_2fa

    client_ip = handler.client_address[0]
    if not check_rate_limit(client_ip):
        return 429, {"error": "Too many failed attempts. Try again later."}

    username = body.get("username", "")
    password = body.get("password", "")

    # Verify password WITHOUT creating a session
    from web.auth import load_credentials, verify_password
    creds = load_credentials()
    if not creds or username != creds.get("username") or \
       not verify_password(password, creds["password_hash"], creds["salt"]):
        record_failed_login(client_ip)
        audit("login_failed", f"user={username[:20]}", ip=client_ip)
        return 401, {"error": "Invalid credentials"}

    # Check 2FA BEFORE creating session
    if is_2fa_enabled():
        totp_code = body.get("totp", "")
        if not totp_code:
            return 200, {"requires_2fa": True}
        if not verify_login_2fa(totp_code):
            record_failed_login(client_ip)
            audit("2fa_failed", f"user={username[:20]}", ip=client_ip)
            return 401, {"error": "Invalid 2FA code"}

    # Both factors verified — NOW create session
    from web.auth import create_session
    session_id = create_session(username)

    audit("login_success", f"user={username[:20]}", user=username, ip=client_ip)
    handler._set_session_cookie(session_id)
    return 200, {"success": True, "session_id": session_id}


@route("POST", "/api/auth/logout")
def handle_logout(handler, match, body):
    session_id = handler._get_session_id()
    if session_id:
        destroy_session(session_id)
    handler._clear_session_cookie()
    return 200, {"success": True}


@route("GET", "/api/auth/check")
def handle_auth_check(handler, match, body):
    session = handler._get_session()
    if session:
        return 200, {"authenticated": True, "csrf_token": session["csrf_token"]}
    return 401, {"authenticated": False}


# ── Dashboard ───────────────────────────────────────────────

@route("GET", "/api/dashboard")
def handle_dashboard(handler, match, body):
    return 200, dashboard.get_dashboard()


# ── Firewall ────────────────────────────────────────────────

@route("GET", "/api/firewall/rules")
def handle_fw_rules(handler, match, body):
    return 200, firewall.get_rules()

@route("GET", "/api/firewall/counters")
def handle_fw_counters(handler, match, body):
    return 200, firewall.get_counters()

@route("POST", "/api/firewall/block")
def handle_fw_block(handler, match, body):
    ip = body.get("ip", "")
    duration = int(body.get("duration", 3600))
    audit("manual_block", f"ip={ip} duration={duration}", user=handler._get_username())
    return 200, firewall.block_ip(ip, duration)

@route("DELETE", "/api/firewall/block/([\\d.]+)")
def handle_fw_unblock(handler, match, body):
    ip = match.group(1)
    audit("manual_unblock", f"ip={ip}", user=handler._get_username())
    return 200, firewall.unblock_ip(ip)

@route("POST", "/api/firewall/flush-ai")
def handle_fw_flush(handler, match, body):
    audit("flush_ai_blocks", "", user=handler._get_username())
    return 200, firewall.flush_ai_blocks()


# ── Network ─────────────────────────────────────────────────

@route("GET", "/api/network/interfaces")
def handle_net_ifaces(handler, match, body):
    return 200, network.get_interfaces()

@route("GET", "/api/network/dhcp")
def handle_net_dhcp(handler, match, body):
    return 200, network.get_dhcp_leases()

@route("GET", "/api/network/routes")
def handle_net_routes(handler, match, body):
    return 200, network.get_routes()

@route("GET", "/api/network/arp")
def handle_net_arp(handler, match, body):
    return 200, network.get_arp()

@route("GET", "/api/network/conntrack")
def handle_net_conntrack(handler, match, body):
    return 200, network.get_conntrack()


# ── Threats ─────────────────────────────────────────────────

@route("GET", "/api/threats/recent")
def handle_threats_recent(handler, match, body):
    return 200, threats.get_recent()

@route("GET", "/api/threats/stats")
def handle_threats_stats(handler, match, body):
    return 200, threats.get_stats()

@route("GET", "/api/threats/blocklist")
def handle_threats_blocklist(handler, match, body):
    return 200, threats.get_blocklist()

@route("DELETE", "/api/threats/blocklist/([\\d.]+)")
def handle_threats_unblock(handler, match, body):
    ip = match.group(1)
    audit("ai_unblock", f"ip={ip}", user=handler._get_username())
    return 200, threats.unblock_ip(ip)

@route("GET", "/api/threats/timeline")
def handle_threats_timeline(handler, match, body):
    return 200, threats.get_timeline()

@route("GET", "/api/threats/analysis")
def handle_threats_analysis(handler, match, body):
    return 200, threats.get_analysis()


# ── DNS ─────────────────────────────────────────────────────

@route("GET", "/api/dns/stats")
def handle_dns_stats(handler, match, body):
    return 200, dns.get_stats()

@route("GET", "/api/dns/blocked")
def handle_dns_blocked(handler, match, body):
    return 200, dns.get_blocked()

@route("POST", "/api/dns/block")
def handle_dns_block(handler, match, body):
    domain = body.get("domain", "")
    audit("dns_block", f"domain={domain}", user=handler._get_username())
    return 200, dns.block_domain(domain)

@route("DELETE", "/api/dns/block/(.+)")
def handle_dns_unblock(handler, match, body):
    domain = match.group(1)
    audit("dns_unblock", f"domain={domain}", user=handler._get_username())
    return 200, dns.unblock_domain(domain)


# ── Content Filter ─────────────────────────────────────────

@route("GET", "/api/content-filter/status")
def handle_cf_status(handler, match, body):
    return 200, content_filter.get_status()

@route("POST", "/api/content-filter/toggle")
def handle_cf_toggle(handler, match, body):
    enabled = body.get("enabled", False)
    audit("content_filter_toggle", f"enabled={enabled}", user=handler._get_username())
    return 200, content_filter.toggle_filter(enabled)

@route("POST", "/api/content-filter/category")
def handle_cf_category(handler, match, body):
    category = body.get("category", "")
    enabled = body.get("enabled", False)
    audit("content_filter_category", f"{category}={enabled}", user=handler._get_username())
    return 200, content_filter.toggle_category(category, enabled)

@route("POST", "/api/content-filter/update")
def handle_cf_update(handler, match, body):
    audit("content_filter_update", "refresh lists", user=handler._get_username())
    return 200, content_filter.update_lists()

@route("GET", "/api/content-filter/whitelist")
def handle_cf_whitelist(handler, match, body):
    return 200, content_filter.get_whitelist()

@route("POST", "/api/content-filter/whitelist")
def handle_cf_whitelist_add(handler, match, body):
    domain = body.get("domain", "")
    audit("content_filter_whitelist_add", f"domain={domain}", user=handler._get_username())
    return 200, content_filter.add_whitelist(domain)

@route("DELETE", "/api/content-filter/whitelist/(.+)")
def handle_cf_whitelist_remove(handler, match, body):
    domain = match.group(1)
    audit("content_filter_whitelist_remove", f"domain={domain}", user=handler._get_username())
    return 200, content_filter.remove_whitelist(domain)

@route("GET", "/api/content-filter/blacklist")
def handle_cf_blacklist(handler, match, body):
    return 200, content_filter.get_blacklist()

@route("POST", "/api/content-filter/blacklist")
def handle_cf_blacklist_add(handler, match, body):
    domain = body.get("domain", "")
    audit("content_filter_blacklist_add", f"domain={domain}", user=handler._get_username())
    return 200, content_filter.add_blacklist(domain)

@route("DELETE", "/api/content-filter/blacklist/(.+)")
def handle_cf_blacklist_remove(handler, match, body):
    domain = match.group(1)
    audit("content_filter_blacklist_remove", f"domain={domain}", user=handler._get_username())
    return 200, content_filter.remove_blacklist(domain)

@route("GET", "/api/content-filter/search")
def handle_cf_search(handler, match, body):
    from urllib.parse import parse_qs, urlparse
    query = parse_qs(urlparse(handler.path).query).get("q", [""])[0]
    return 200, content_filter.search_blocked(query)


# ── VLANs ──────────────────────────────────────────────────

@route("GET", "/api/vlans/status")
def handle_vlans_status(handler, match, body):
    return 200, vlans.get_status()

@route("POST", "/api/vlans/create")
def handle_vlans_create(handler, match, body):
    audit("vlan_create", f"id={body.get('id')}", user=handler._get_username())
    return 200, vlans.create_vlan(body)

@route("DELETE", "/api/vlans/(\\d+)")
def handle_vlans_delete(handler, match, body):
    vid = int(match.group(1))
    audit("vlan_delete", f"id={vid}", user=handler._get_username())
    return 200, vlans.delete_vlan(vid)

@route("PUT", "/api/vlans/(\\d+)")
def handle_vlans_update(handler, match, body):
    vid = int(match.group(1))
    audit("vlan_update", f"id={vid}", user=handler._get_username())
    return 200, vlans.update_vlan(vid, body)

@route("POST", "/api/vlans/trunk")
def handle_vlans_trunk(handler, match, body):
    iface = body.get("interface", "")
    audit("vlan_trunk", f"interface={iface}", user=handler._get_username())
    return 200, vlans.set_trunk(iface)


# ── QoS ────────────────────────────────────────────────────

@route("GET", "/api/qos/status")
def handle_qos_status(handler, match, body):
    return 200, qos.get_status()

@route("POST", "/api/qos/toggle")
def handle_qos_toggle(handler, match, body):
    enabled = body.get("enabled", False)
    audit("qos_toggle", f"enabled={enabled}", user=handler._get_username())
    return 200, qos.toggle_qos(enabled)

@route("POST", "/api/qos/bandwidth")
def handle_qos_bandwidth(handler, match, body):
    audit("qos_bandwidth", f"up={body.get('upload_mbps')} down={body.get('download_mbps')}", user=handler._get_username())
    return 200, qos.update_bandwidth(body.get("upload_mbps", 100), body.get("download_mbps", 100))

@route("POST", "/api/qos/rule")
def handle_qos_rule_add(handler, match, body):
    audit("qos_rule_add", f"type={body.get('type')}", user=handler._get_username())
    return 200, qos.add_rule(body)

@route("DELETE", "/api/qos/rule/(\\d+)")
def handle_qos_rule_delete(handler, match, body):
    idx = int(match.group(1))
    audit("qos_rule_delete", f"index={idx}", user=handler._get_username())
    return 200, qos.delete_rule(idx)


# ── AI Firewall Rules ──────────────────────────────────────

@route("POST", "/api/ai-rules/generate")
def handle_ai_rules_generate(handler, match, body):
    desc = body.get("description", "")
    audit("ai_rule_generate", f"desc={desc[:50]}", user=handler._get_username())
    return 200, ai_rules.generate_rule(desc)

@route("POST", "/api/ai-rules/apply")
def handle_ai_rules_apply(handler, match, body):
    cmd = body.get("nft_command", "")
    desc = body.get("description", "")
    audit("ai_rule_apply", f"cmd={cmd[:80]}", user=handler._get_username())
    return 200, ai_rules.apply_rule(cmd, desc)

@route("GET", "/api/ai-rules/history")
def handle_ai_rules_history(handler, match, body):
    return 200, ai_rules.get_history()


# ── Captive Portal ─────────────────────────────────────────

@route("GET", "/api/captive-portal/status")
def handle_portal_status(handler, match, body):
    return 200, captive_portal.get_status()

@route("POST", "/api/captive-portal/toggle")
def handle_portal_toggle(handler, match, body):
    enabled = body.get("enabled", False)
    audit("portal_toggle", f"enabled={enabled}", user=handler._get_username())
    return 200, captive_portal.toggle_portal(enabled)

@route("POST", "/api/captive-portal/config")
def handle_portal_config(handler, match, body):
    audit("portal_config", "updated", user=handler._get_username())
    return 200, captive_portal.update_config(body)

@route("POST", "/api/captive-portal/authorize")
def handle_portal_authorize(handler, match, body):
    ip = body.get("ip", "")
    audit("portal_authorize", f"ip={ip}", user=handler._get_username())
    return 200, captive_portal.authorize_client(ip, body.get("mac", ""))

@route("DELETE", "/api/captive-portal/client/(.+)")
def handle_portal_deauth(handler, match, body):
    ip = match.group(1)
    audit("portal_deauth", f"ip={ip}", user=handler._get_username())
    return 200, captive_portal.deauthorize_client(ip)

@route("POST", "/api/captive-portal/disconnect-all")
def handle_portal_disconnect_all(handler, match, body):
    audit("portal_disconnect_all", "", user=handler._get_username())
    return 200, captive_portal.disconnect_all()


# ── System ──────────────────────────────────────────────────

@route("GET", "/api/system/info")
def handle_sys_info(handler, match, body):
    return 200, system.get_info()

@route("GET", "/api/system/services")
def handle_sys_services(handler, match, body):
    return 200, system.get_services()

@route("GET", "/api/system/logs/(\\w[\\w-]*)")
def handle_sys_logs(handler, match, body):
    return 200, system.get_logs(match.group(1))


# ── Security Features ───────────────────────────────────────

@route("GET", "/api/security/fail2ban")
def handle_fail2ban(handler, match, body):
    return 200, security.get_fail2ban_status()

@route("GET", "/api/security/geoip")
def handle_geoip(handler, match, body):
    return 200, security.get_geoip_status()

@route("POST", "/api/security/geoip/block")
def handle_geoip_block(handler, match, body):
    cc = body.get("country", "")
    audit("geoip_block", f"country={cc}", user=handler._get_username())
    return 200, security.block_country(cc)

@route("POST", "/api/security/geoip/unblock")
def handle_geoip_unblock(handler, match, body):
    cc = body.get("country", "")
    audit("geoip_unblock", f"country={cc}", user=handler._get_username())
    return 200, security.unblock_country(cc)

@route("POST", "/api/security/geoip/clear")
def handle_geoip_clear(handler, match, body):
    audit("geoip_clear", "", user=handler._get_username())
    return 200, security.clear_geoip()

@route("GET", "/api/security/feeds")
def handle_feeds(handler, match, body):
    return 200, security.get_feed_status()

@route("POST", "/api/security/feeds/update")
def handle_feeds_update(handler, match, body):
    audit("feeds_update", "", user=handler._get_username())
    return 200, security.update_feeds()

@route("POST", "/api/security/feeds/toggle")
def handle_feeds_toggle(handler, match, body):
    enable = body.get("enabled", True)
    audit("feeds_toggle", f"enabled={enable}", user=handler._get_username())
    return 200, security.toggle_feeds(enable)

@route("GET", "/api/security/ratelimit")
def handle_ratelimit(handler, match, body):
    return 200, security.get_rate_limit_stats()

@route("GET", "/api/security/arp")
def handle_arp_watch(handler, match, body):
    return 200, security.get_arp_status()

@route("GET", "/api/security/bandwidth")
def handle_bandwidth(handler, match, body):
    return 200, security.get_bandwidth()


# ── Suricata IDS ────────────────────────────────────────────

@route("GET", "/api/ids/status")
def handle_ids_status(handler, match, body):
    return 200, ids.get_status()

@route("GET", "/api/ids/alerts")
def handle_ids_alerts(handler, match, body):
    return 200, ids.get_alerts()

@route("GET", "/api/ids/signatures")
def handle_ids_sigs(handler, match, body):
    return 200, ids.get_top_signatures()

@route("GET", "/api/ids/sources")
def handle_ids_sources(handler, match, body):
    return 200, ids.get_top_sources()

@route("POST", "/api/ids/update-rules")
def handle_ids_update(handler, match, body):
    audit("ids_update_rules", "", user=handler._get_username())
    return 200, ids.update_rules()


# ── Settings & 2FA ──────────────────────────────────────────

@route("GET", "/api/settings/2fa")
def handle_2fa_status(handler, match, body):
    return 200, settings.get_2fa_status()

@route("POST", "/api/settings/2fa/setup")
def handle_2fa_setup(handler, match, body):
    return 200, settings.setup_2fa()

@route("POST", "/api/settings/2fa/confirm")
def handle_2fa_confirm(handler, match, body):
    return 200, settings.confirm_2fa(body.get("code", ""), body.get("secret", ""))

@route("POST", "/api/settings/2fa/disable")
def handle_2fa_disable(handler, match, body):
    audit("2fa_disabled", "", user=handler._get_username())
    return 200, settings.remove_2fa()

@route("POST", "/api/settings/password")
def handle_password_change(handler, match, body):
    audit("password_change", "", user=handler._get_username())
    return 200, settings.update_password(body.get("current", ""), body.get("new_password", ""))

@route("GET", "/api/settings/notifications")
def handle_get_notifications(handler, match, body):
    return 200, settings.get_notifications_config()

@route("POST", "/api/settings/notifications")
def handle_save_notifications(handler, match, body):
    audit("notifications_updated", "", user=handler._get_username())
    return 200, settings.save_notifications_config(body)

@route("GET", "/api/settings/report")
def handle_get_report(handler, match, body):
    return 200, settings.get_daily_report()

@route("POST", "/api/settings/report/generate")
def handle_generate_report(handler, match, body):
    audit("report_generated", "", user=handler._get_username())
    return 200, settings.generate_daily_report()


# ── Request Handler ─────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

AUTH_EXEMPT = {"/api/auth/login", "/api/auth/check"}


class CerberixHandler(http.server.BaseHTTPRequestHandler):
    """HTTPS request handler with routing and auth."""

    def log_message(self, format, *args):
        log.info(f"{self.client_address[0]} {format % args}")

    def _accepts_gzip(self):
        return "gzip" in self.headers.get("Accept-Encoding", "")

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        if self._accepts_gzip() and len(body) > 512:
            body = gzip.compress(body, compresslevel=1)
            self.send_response(status)
            self.send_header("Content-Encoding", "gzip")
        else:
            self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str):
        if not os.path.isfile(path):
            self.send_error(404)
            return

        # Use cache for static files
        if path in _file_cache:
            raw, gz, mime = _file_cache[path]
        else:
            mime, _ = mimetypes.guess_type(path)
            mime = mime or "application/octet-stream"
            with open(path, "rb") as f:
                raw = f.read()
            gz = gzip.compress(raw, compresslevel=6) if len(raw) > 512 else raw
            _file_cache[path] = (raw, gz, mime)

        if self._accepts_gzip() and len(raw) > 512:
            data = gz
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
        else:
            data = raw
            self.send_response(200)

        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=300")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _get_session_id(self) -> str:
        # Try cookie first
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "cerberix_session" in cookie:
            return cookie["cerberix_session"].value
        # Fall back to Authorization header (used by localStorage flow)
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return ""

    def _get_session(self):
        return validate_session(self._get_session_id())

    def _get_username(self) -> str:
        session = self._get_session()
        return session.get("username", "") if session else ""

    def _set_session_cookie(self, session_id: str):
        self._pending_cookie = (
            f"cerberix_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800"
        )

    def _clear_session_cookie(self):
        self._pending_cookie = (
            "cerberix_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
        )

    def _check_csrf(self, body: dict) -> bool:
        """Verify CSRF token for mutating requests."""
        session = self._get_session()
        if not session:
            return False
        token = self.headers.get("X-CSRF-Token", "")
        return token == session.get("csrf_token", "")

    def _handle_request(self, method: str):
        self._pending_cookie = None
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # ── Static files ────────────────────────────────────
        if path.startswith("/static/"):
            file_path = os.path.join(STATIC_DIR, path[8:])
            # Prevent directory traversal
            real = os.path.realpath(file_path)
            if not real.startswith(os.path.realpath(STATIC_DIR)):
                self.send_error(403)
                return
            self._send_file(real)
            return

        # ── Login page ──────────────────────────────────────
        if path == "/login" or path == "/login.html":
            self._send_file(os.path.join(TEMPLATE_DIR, "login.html"))
            return

        # ── Root / index — always serve the page ─────────────
        # Auth is handled client-side via localStorage token.
        # The JS in app.js checks /api/auth/check and redirects
        # to /login if the token is missing or invalid.
        if path == "/" or path == "/index.html":
            self._send_file(os.path.join(TEMPLATE_DIR, "index.html"))
            return

        # ── API routes ──────────────────────────────────────
        if path.startswith("/api/"):
            # Auth check (exempt login/check)
            if path not in AUTH_EXEMPT:
                session = self._get_session()
                if not session:
                    self._send_json(401, {"error": "Unauthorized"})
                    return

                # CSRF check for mutating requests
                if method in ("POST", "PUT", "DELETE"):
                    csrf_token = self.headers.get("X-CSRF-Token", "")
                    if csrf_token != session.get("csrf_token", ""):
                        self._send_json(403, {"error": "Invalid CSRF token"})
                        return

            # Parse body (max 1MB to prevent OOM DoS)
            body = {}
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 1_048_576:
                self._send_json(413, {"error": "Request body too large"})
                return
            if content_length > 0:
                raw = self.rfile.read(content_length)
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

            # Route matching
            for route_method, pattern, handler_func in ROUTES:
                if route_method != method:
                    continue
                match = pattern.match(path)
                if match:
                    try:
                        status, data = handler_func(self, match, body)
                    except Exception as e:
                        log.error(f"API error: {e}")
                        status, data = 500, {"error": "Internal server error"}
                    # Apply pending cookie if set
                    if self._pending_cookie:
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", self._pending_cookie)
                        resp_body = json.dumps(data).encode()
                        self.send_header("Content-Length", str(len(resp_body)))
                        for k, v in SECURITY_HEADERS.items():
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(resp_body)
                    else:
                        self._send_json(status, data)
                    return

            self._send_json(404, {"error": "Not found"})
            return

        self.send_error(404)

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server(host: str = "0.0.0.0", port: int = 8443):
    """Start the HTTPS server."""
    server = ThreadedHTTPServer((host, port), CerberixHandler)

    # TLS setup
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        log.info(f"Web panel listening on https://{host}:{port}")
    else:
        log.warning(f"No TLS cert found — running HTTP on {host}:{port}")
        log.info(f"Web panel listening on http://{host}:{port}")

    server.serve_forever()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="[cerberix-web] %(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    port = int(os.environ.get("CERBERIX_WEBUI_PORT", "8443"))
    start_server(port=port)


if __name__ == "__main__":
    main()
