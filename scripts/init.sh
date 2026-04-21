#!/bin/bash
# ============================================================
# Cerberix Firewall — Init Script (Entrypoint)
# ============================================================
# Orchestrates startup: networking → firewall → services
# ============================================================

set -euo pipefail

CERBERIX_VERSION="0.3.0"
CONF_DIR="/etc/cerberix"
LOG_DIR="/var/log/cerberix"

# ── Banner ──────────────────────────────────────────────────
cat << 'BANNER'
                   CERBERIX LINUX

                   #          %
                  =@+        +@=
                  @@%*      *@@@
            ++     @@=@%-##-%@=@@:    +*
      =      :@@*  +@@-%@@@@@@%:@@*  *@@-      =
      :@@*   @+@@*  @@@@@@@@@@@@@@  +@@+@   +@@-
       #@@+*@@:%@@@%.*@@@@@@@@@@@@*.%@@@%:@@*=@@#
        @@@@@@@@@@*.@@@::%@@@@@::@@@.+@@@@@@@@@@
       +@@@@@@@@@@%.:@@@@%@@@@%@@@@:.%@@@@@@@@@@+
       @@@%:.%@@@@**-.+@@@@@@@@@@*.-**@@@@%.:%@@@
      =@@@%@@@@@@@@@@#..-@@@@@@-..#@@@@@@@@@@%@@@=
   :@@@@@@@@@@%%@@@@@@=.#@@@@#.=@@@@@@%%@@@@@@@@@@-
    %@@@@@#:.#@@@@@@@@@%.:##:.%@@@@@@@@@#.:#@@@@@%
     :##-....-:=%@@@#@@@@+..+@@@@#%@@%=:=....-##:
              :@%.=@%=@@@@@@@@@@=%@=.%@
                =@@+:+:@@@@@@@@:+:+@@+
                  @@@#.:@@@@@@:.#@@@
                  -@@@=-@@@@-=@@@-
                   %@@:=@@+:@@%
                    :@%.**.%@:
                      *+..+*
                        :::

         v0.3.0 (Hades) — Firewall Gateway
BANNER
echo "  Version: ${CERBERIX_VERSION}"
echo "  Starting at $(date -Iseconds)"
echo "============================================"

# ── Load configuration ──────────────────────────────────────
if [ -f "${CONF_DIR}/cerberix.conf" ]; then
    # shellcheck source=/dev/null
    source "${CONF_DIR}/cerberix.conf"
fi

# Environment variables override config file
WAN_IF="${CERBERIX_WAN_IF:-${WAN_IF:-eth0}}"
LAN_IF="${CERBERIX_LAN_IF:-${LAN_IF:-eth1}}"
LAN_SUBNET="${CERBERIX_LAN_SUBNET:-${LAN_SUBNET:-192.168.1.0/24}}"
LAN_IP="${CERBERIX_LAN_IP:-${LAN_IP:-192.168.1.1}}"
DNS_UPSTREAM="${CERBERIX_DNS_UPSTREAM:-${DNS_UPSTREAM:-1.1.1.1,1.0.0.1}}"
LOG_LEVEL="${CERBERIX_LOG_LEVEL:-${LOG_LEVEL:-info}}"

export WAN_IF LAN_IF LAN_SUBNET LAN_IP DNS_UPSTREAM LOG_LEVEL

log() {
    echo "[cerberix] $(date '+%H:%M:%S') $*"
}

die() {
    echo "[cerberix] FATAL: $*" >&2
    exit 1
}

# ── Verify capabilities ────────────────────────────────────
log "Checking required capabilities..."
if ! ip link show >/dev/null 2>&1; then
    die "NET_ADMIN capability required. Run with --cap-add=NET_ADMIN"
fi

# ── Step 0.5: Ensure container can resolve external DNS ─────
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf

# ── Step 1: Configure networking ────────────────────────────
log "Configuring network interfaces..."
/usr/local/bin/cerberix-network

# ── Load detected interface mapping ─────────────────────────
if [ -f /var/run/cerberix/interfaces.env ]; then
    source /var/run/cerberix/interfaces.env
    export WAN_IF LAN_IF
    log "Interfaces: WAN=${WAN_IF} LAN=${LAN_IF}"
fi

# ── Step 2: Apply firewall rules ────────────────────────────
log "Loading nftables firewall rules..."
/usr/local/bin/cerberix-firewall || log "WARNING: Firewall loaded with emergency rules"

# ── Step 3: Start syslog ────────────────────────────────────
log "Starting syslog-ng..."
mkdir -p "${LOG_DIR}"
syslog-ng --cfgfile="${CONF_DIR}/syslog-ng.conf" \
    --pidfile=/var/run/cerberix/syslog-ng.pid \
    || log "WARNING: syslog-ng failed to start (non-fatal in container)"

# ── Step 4: Start dnsmasq (DHCP + DNS) ─────────────────────
log "Starting dnsmasq (DHCP + DNS)..."
touch /var/lib/cerberix/dnsmasq.leases

# Update dnsmasq config with runtime values
RUNTIME_DNSMASQ="/tmp/dnsmasq-runtime.conf"
cp "${CONF_DIR}/dnsmasq.conf" "${RUNTIME_DNSMASQ}"

# Override upstream DNS from environment
if [ -n "${DNS_UPSTREAM}" ]; then
    sed -i '/^server=/d' "${RUNTIME_DNSMASQ}"
    IFS=',' read -ra SERVERS <<< "${DNS_UPSTREAM}"
    for srv in "${SERVERS[@]}"; do
        echo "server=${srv}" >> "${RUNTIME_DNSMASQ}"
    done
fi

# Override listen address
sed -i "s/listen-address=192.168.1.1/listen-address=${LAN_IP}/" "${RUNTIME_DNSMASQ}"

# Override DHCP range from environment
if [ -n "${CERBERIX_DHCP_RANGE_START:-}" ] && [ -n "${CERBERIX_DHCP_RANGE_END:-}" ]; then
    LEASE="${CERBERIX_DHCP_LEASE:-12h}"
    LAN_MASK=$(echo "${LAN_SUBNET}" | cut -d'/' -f2)
    # Convert CIDR to dotted notation
    case "${LAN_MASK}" in
        24) NETMASK="255.255.255.0" ;;
        16) NETMASK="255.255.0.0" ;;
        8)  NETMASK="255.0.0.0" ;;
        *)  NETMASK="255.255.255.0" ;;
    esac
    sed -i "s|^dhcp-range=.*|dhcp-range=${CERBERIX_DHCP_RANGE_START},${CERBERIX_DHCP_RANGE_END},${NETMASK},${LEASE}|" \
        "${RUNTIME_DNSMASQ}"
fi

# Override DHCP options
sed -i "s|dhcp-option=option:router,.*|dhcp-option=option:router,${LAN_IP}|" "${RUNTIME_DNSMASQ}"
sed -i "s|dhcp-option=option:dns-server,.*|dhcp-option=option:dns-server,${LAN_IP}|" "${RUNTIME_DNSMASQ}"
sed -i "s|dhcp-option=option:ntp-server,.*|dhcp-option=option:ntp-server,${LAN_IP}|" "${RUNTIME_DNSMASQ}"

dnsmasq --conf-file="${RUNTIME_DNSMASQ}" \
    || die "dnsmasq failed to start"

# ── Step 5: Certificate Authority and TLS ───────────────────
if [ ! -f /etc/cerberix/ssl/ca/ca.crt ]; then
    log "Creating Cerberix Certificate Authority..."
    /usr/local/bin/cerberix-ca init
    log "Signing server certificate..."
    /usr/local/bin/cerberix-ca sign
    log "============================================"
    log "CA CERTIFICATE — install on your devices"
    log "Run: docker exec cerberix-gw cerberix-ca export-ca"
    log "============================================"
elif [ ! -f /etc/cerberix/ssl/cert.pem ]; then
    log "Signing server certificate..."
    /usr/local/bin/cerberix-ca sign
fi

if [ ! -f /etc/cerberix/webui.conf ]; then
    ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
    log "============================================"
    log "WEB UI INITIAL CREDENTIALS"
    log "  Username: admin"
    log "  Password: ${ADMIN_PASS}"
    log "  URL: https://<LAN_IP>:8443"
    log "  SAVE THIS PASSWORD — it will not be shown again"
    log "============================================"
    CERBERIX_INIT_PASS="${ADMIN_PASS}" PYTHONPATH=/opt/cerberix python3 -c "
import os
from web.auth import create_initial_config
create_initial_config('admin', os.environ['CERBERIX_INIT_PASS'])
" || log "WARNING: Failed to create web UI credentials"
fi

WEBUI_ENABLED="${CERBERIX_WEBUI_ENABLED:-true}"
if [ "${WEBUI_ENABLED}" = "true" ]; then
    log "Starting Web Control Panel..."
    PYTHONPATH=/opt/cerberix python3 -m web.server &
    WEBUI_PID=$!
    echo "${WEBUI_PID}" > /var/run/cerberix/webui.pid
    log "Web Panel started (PID: ${WEBUI_PID}, port: 8443)"
fi

# ── Step 6.5: Start WireGuard VPN ─────────────────────────
WG_ENABLED="${CERBERIX_WG_ENABLED:-true}"
if [ "${WG_ENABLED}" = "true" ]; then
    log "Starting WireGuard VPN..."
    /usr/local/bin/cerberix-wg start || log "WARNING: WireGuard failed to start (kernel module may be missing)"

    # Add NAT masquerade for VPN subnet so VPN clients can reach the internet
    WG_SUBNET="${CERBERIX_WG_SUBNET:-10.100.0.0/24}"
    nft add rule ip nat postrouting oifname "${WAN_IF}" ip saddr "${WG_SUBNET}" masquerade 2>/dev/null || true
    log "VPN NAT rule added for ${WG_SUBNET}"

    # Restart dnsmasq to also listen on VPN gateway IP
    WG_SERVER_IP="${CERBERIX_WG_SERVER_IP:-10.100.0.1}"
    echo "listen-address=${WG_SERVER_IP}" >> /tmp/dnsmasq-runtime.conf
    killall dnsmasq 2>/dev/null
    dnsmasq --conf-file=/tmp/dnsmasq-runtime.conf || log "WARNING: dnsmasq restart failed"
    log "dnsmasq now listening on VPN interface (${WG_SERVER_IP})"

    # Allow DNS from VPN subnet in firewall
    nft add rule inet filter input iifname "wg0" udp dport 53 accept 2>/dev/null || true
    nft add rule inet filter input iifname "wg0" tcp dport 53 accept 2>/dev/null || true
    # Allow web UI from VPN
    nft add rule inet filter input iifname "wg0" tcp dport 8443 accept 2>/dev/null || true
    log "Firewall rules added for VPN access"
fi

# ── Step 7: Start fail2ban ─────────────────────────────────
log "Starting fail2ban..."
mkdir -p /var/log/cerberix/hosts
touch /var/log/cerberix/hosts/remote.log
touch /var/log/fail2ban.log
touch /var/log/cerberix/webui-audit.log
rm -f /etc/fail2ban/jail.d/alpine-ssh.conf
fail2ban-server -b --pidfile /var/run/cerberix/fail2ban.pid \
    || log "WARNING: fail2ban failed to start"
log "fail2ban started"

# ── Step 8: Log Rotation ──────────────────────────────────
log "Configuring log rotation..."
cat > /etc/periodic/hourly/cerberix-logrotate << 'LOGROT'
#!/bin/sh
# Rotate Cerberix logs — keep them under control
for logfile in /var/log/cerberix/*.log /var/log/cerberix/hosts/*.log; do
    [ -f "$logfile" ] || continue
    size=$(stat -f%z "$logfile" 2>/dev/null || stat -c%s "$logfile" 2>/dev/null || echo 0)
    # Rotate if over 10MB
    if [ "$size" -gt 10485760 ]; then
        mv "$logfile" "${logfile}.1"
        : > "$logfile"
    fi
    # Delete old rotated files over 50MB
    for old in "${logfile}".1; do
        [ -f "$old" ] || continue
        oldsize=$(stat -f%z "$old" 2>/dev/null || stat -c%s "$old" 2>/dev/null || echo 0)
        if [ "$oldsize" -gt 52428800 ]; then
            rm -f "$old"
        fi
    done
done
# Suricata eve.json — rotate at 20MB
evefile="/var/log/cerberix/suricata/eve.json"
if [ -f "$evefile" ]; then
    size=$(stat -c%s "$evefile" 2>/dev/null || echo 0)
    if [ "$size" -gt 20971520 ]; then
        mv "$evefile" "${evefile}.1"
        : > "$evefile"
    fi
fi
LOGROT
chmod 755 /etc/periodic/hourly/cerberix-logrotate
# Run crond for periodic tasks
crond -b 2>/dev/null || true
log "Log rotation configured (hourly check, 10MB max per log)"

# ── Step 9: Download threat feeds (background) ────────────
log "Scheduling threat feed download..."
(
    sleep 30  # Wait for DNS to be ready
    /usr/local/bin/cerberix-feeds update 2>&1 | while read -r line; do
        echo "[cerberix] $(date '+%H:%M:%S') $line"
    done
) &

# ── Step 10: Start Suricata IDS ────────────────────────────
IDS_ENABLED="${CERBERIX_IDS_ENABLED:-true}"
if [ "${IDS_ENABLED}" = "true" ]; then
    log "Starting Suricata IDS..."
    /usr/local/bin/cerberix-ids start || log "WARNING: Suricata failed to start"
fi

# ── Step 11: Start AI Threat Engine ──────────────────────────
AI_ENABLED="${CERBERIX_AI_ENABLED:-true}"
if [ "${AI_ENABLED}" = "true" ]; then
    log "Starting AI Threat Detection Engine..."
    PYTHONPATH=/opt/cerberix python3 -m ai.engine &
    AI_PID=$!
    echo "${AI_PID}" > /var/run/cerberix/ai-engine.pid
    log "AI Engine started (PID: ${AI_PID})"
else
    log "AI Engine disabled (CERBERIX_AI_ENABLED=false)"
fi

# ── Step 6: Verify ──────────────────────────────────────────
log "============================================"
log "Cerberix Firewall is ONLINE"
log "  WAN interface : ${WAN_IF}"
log "  LAN interface : ${LAN_IF}"
log "  LAN subnet    : ${LAN_SUBNET}"
log "  LAN gateway   : ${LAN_IP}"
log "  DNS upstream  : ${DNS_UPSTREAM}"
log "  DHCP          : active"
log "  Firewall      : active"
log "  AI Engine     : ${AI_ENABLED}"
log "  Web Panel     : ${WEBUI_ENABLED} (port 8443)"
log "  WireGuard VPN : ${WG_ENABLED} (port 51820)"
log "  fail2ban      : active"
log "  NTP           : active"
log "  Syslog recv   : active (514/tcp+udp)"
log "  Threat feeds  : updating in background"
log "  Suricata IDS  : ${IDS_ENABLED}"
if [ -n "${CERBERIX_AI_API_KEY:-}" ]; then
    log "  Claude API    : configured"
else
    log "  Claude API    : not configured (local-only mode)"
fi
log "============================================"

# ── Keep container running ──────────────────────────────────
# Trap signals for clean shutdown
cleanup() {
    log "Shutting down Cerberix Firewall..."
    /usr/local/bin/cerberix-ids stop 2>/dev/null
    /usr/local/bin/cerberix-wg stop 2>/dev/null
    fail2ban-client stop 2>/dev/null
    kill "$(cat /var/run/cerberix/chrony.pid 2>/dev/null)" 2>/dev/null
    kill "$(cat /var/run/cerberix/webui.pid 2>/dev/null)" 2>/dev/null
    kill "$(cat /var/run/cerberix/ai-engine.pid 2>/dev/null)" 2>/dev/null
    kill "$(cat /var/run/cerberix/syslog-ng.pid 2>/dev/null)" 2>/dev/null
    killall dnsmasq 2>/dev/null
    nft flush ruleset 2>/dev/null
    log "Shutdown complete."
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

# Wait indefinitely (PID 1 behavior)
log "Cerberix init running as PID 1. Waiting for signals..."
while true; do
    sleep 3600 &
    wait $!
done
