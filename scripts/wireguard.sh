#!/bin/bash
# ============================================================
# Cerberix Firewall — WireGuard VPN Setup
# ============================================================
# Generates keys, builds wg0 config, starts the interface.
# Manages peer (client) additions.
# ============================================================

set -euo pipefail

CONF_DIR="/etc/cerberix"
WG_DIR="${CONF_DIR}/wireguard"
WG_PEERS_DIR="${WG_DIR}/peers"
WG_CONF="/etc/wireguard/wg0.conf"

# ── Load config ─────────────────────────────────────────────
if [ -f "${CONF_DIR}/wireguard.conf" ]; then
    source "${CONF_DIR}/wireguard.conf"
fi

WG_INTERFACE="${CERBERIX_WG_INTERFACE:-${WG_INTERFACE:-wg0}}"
WG_PORT="${CERBERIX_WG_PORT:-${WG_PORT:-51820}}"
WG_SUBNET="${CERBERIX_WG_SUBNET:-${WG_SUBNET:-10.100.0.0/24}}"
WG_SERVER_IP="${CERBERIX_WG_SERVER_IP:-${WG_SERVER_IP:-10.100.0.1}}"
WG_DNS="${CERBERIX_WG_DNS:-${WG_DNS:-192.168.1.1}}"
WG_KEEPALIVE="${CERBERIX_WG_KEEPALIVE:-${WG_KEEPALIVE:-25}}"

# LAN access for VPN peers
LAN_SUBNET="${CERBERIX_LAN_SUBNET:-192.168.1.0/24}"

log() {
    echo "[wireguard] $(date '+%H:%M:%S') $*"
}

# ── Generate server keys if missing ─────────────────────────
init_keys() {
    mkdir -p "${WG_DIR}" "${WG_PEERS_DIR}" /etc/wireguard
    chmod 700 "${WG_DIR}" "${WG_PEERS_DIR}" /etc/wireguard

    if [ ! -f "${WG_DIR}/server_private.key" ]; then
        log "Generating server keypair..."
        wg genkey > "${WG_DIR}/server_private.key"
        cat "${WG_DIR}/server_private.key" | wg pubkey > "${WG_DIR}/server_public.key"
        chmod 600 "${WG_DIR}/server_private.key"
        log "Server public key: $(cat "${WG_DIR}/server_public.key")"
    fi
}

# ── Build wg0.conf from server keys + peers ─────────────────
build_config() {
    local SERVER_PRIVKEY
    SERVER_PRIVKEY=$(cat "${WG_DIR}/server_private.key")
    local CIDR
    CIDR=$(echo "${WG_SUBNET}" | cut -d'/' -f2)

    cat > "${WG_CONF}" <<EOF
# Cerberix WireGuard — Auto-generated (do not edit manually)
# Generated: $(date -Iseconds)

[Interface]
Address = ${WG_SERVER_IP}/${CIDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVKEY}

# PostUp/PostDown handled by cerberix init (nftables integration)
EOF

    # Append server-side peer configs (exclude *.client.conf)
    if [ -d "${WG_PEERS_DIR}" ]; then
        for peer_conf in "${WG_PEERS_DIR}"/*.conf; do
            [ -f "$peer_conf" ] || continue
            # Skip client configs — those are for the user to download
            case "$peer_conf" in *.client.conf) continue ;; esac
            echo "" >> "${WG_CONF}"
            cat "$peer_conf" >> "${WG_CONF}"
        done
    fi

    chmod 600 "${WG_CONF}"
    log "WireGuard config built: ${WG_CONF}"
}

# ── Add a new peer ──────────────────────────────────────────
add_peer() {
    local PEER_NAME="${1:?Usage: add_peer <name>}"
    local PEER_DIR="${WG_PEERS_DIR}"
    local PEER_CONF="${PEER_DIR}/${PEER_NAME}.conf"
    local PEER_CLIENT="${PEER_DIR}/${PEER_NAME}.client.conf"

    if [ -f "${PEER_CONF}" ]; then
        log "Peer '${PEER_NAME}' already exists"
        return 1
    fi

    # Find next available IP in the VPN subnet
    local BASE_IP
    BASE_IP=$(echo "${WG_SERVER_IP}" | sed 's/\.[0-9]*$//')
    local NEXT_IP=2  # .1 is the server

    while [ -f "${PEER_DIR}/"*".conf" ] 2>/dev/null; do
        if grep -rq "${BASE_IP}.${NEXT_IP}" "${PEER_DIR}/" 2>/dev/null; then
            NEXT_IP=$((NEXT_IP + 1))
        else
            break
        fi
    done

    local PEER_IP="${BASE_IP}.${NEXT_IP}"

    # Generate peer keys
    local PEER_PRIVKEY PEER_PUBKEY PRESHARED_KEY
    PEER_PRIVKEY=$(wg genkey)
    PEER_PUBKEY=$(echo "${PEER_PRIVKEY}" | wg pubkey)
    PRESHARED_KEY=$(wg genpsk)

    local SERVER_PUBKEY
    SERVER_PUBKEY=$(cat "${WG_DIR}/server_public.key")

    # Determine AllowedIPs for client
    local CLIENT_ALLOWED_IPS="${WG_SUBNET}, ${LAN_SUBNET}"

    # Server-side peer config (appended to wg0.conf)
    cat > "${PEER_CONF}" <<EOF
# Peer: ${PEER_NAME} (${PEER_IP})
[Peer]
PublicKey = ${PEER_PUBKEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${PEER_IP}/32
EOF

    # Determine the endpoint for the client
    # In Docker dev, use the host's WAN IP; in production, use public IP
    local ENDPOINT="${CERBERIX_WG_ENDPOINT:-$(hostname -i | awk '{print $1}'):${WG_PORT}}"

    # Client config file (user downloads this)
    cat > "${PEER_CLIENT}" <<EOF
# ============================================================
# Cerberix VPN — Client Config: ${PEER_NAME}
# ============================================================
# Import this into WireGuard on your device
# macOS: brew install wireguard-tools
#   or install WireGuard from the App Store
# ============================================================

[Interface]
PrivateKey = ${PEER_PRIVKEY}
Address = ${PEER_IP}/32
DNS = ${WG_DNS}

[Peer]
PublicKey = ${SERVER_PUBKEY}
PresharedKey = ${PRESHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}
PersistentKeepalive = ${WG_KEEPALIVE}
EOF

    chmod 600 "${PEER_CONF}" "${PEER_CLIENT}"

    log "============================================"
    log "Peer '${PEER_NAME}' created"
    log "  VPN IP  : ${PEER_IP}"
    log "  Config  : ${PEER_CLIENT}"
    log "============================================"
    log "Client config:"
    cat "${PEER_CLIENT}"
    log "============================================"

    # Rebuild and reload if WireGuard is running
    build_config
    if ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
        wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}")
        log "Live-reloaded WireGuard config"
    fi
}

# ── Remove a peer ───────────────────────────────────────────
remove_peer() {
    local PEER_NAME="${1:?Usage: remove_peer <name>}"
    rm -f "${WG_PEERS_DIR}/${PEER_NAME}.conf"
    rm -f "${WG_PEERS_DIR}/${PEER_NAME}.client.conf"
    build_config
    if ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
        wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}")
    fi
    log "Peer '${PEER_NAME}' removed"
}

# ── List peers ──────────────────────────────────────────────
list_peers() {
    echo "=== Configured Peers ==="
    if [ -d "${WG_PEERS_DIR}" ]; then
        for f in "${WG_PEERS_DIR}"/*.conf; do
            [ -f "$f" ] || continue
            local name
            name=$(basename "$f" .conf)
            local ip
            ip=$(grep "AllowedIPs" "$f" | awk '{print $3}' | cut -d'/' -f1)
            echo "  ${name}: ${ip}"
        done
    fi
    echo ""
    if ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
        echo "=== Live Status ==="
        wg show "${WG_INTERFACE}"
    else
        echo "WireGuard interface not running"
    fi
}

# ── Start WireGuard ─────────────────────────────────────────
start_wg() {
    init_keys
    build_config

    log "Starting WireGuard interface ${WG_INTERFACE}..."

    # Create the interface
    ip link add dev "${WG_INTERFACE}" type wireguard 2>/dev/null || true

    # Strip wg-quick directives (Address, DNS, etc.) for wg setconf
    local WG_STRIPPED="/tmp/wg0-stripped.conf"
    grep -v -E '^\s*(Address|DNS|PostUp|PostDown|SaveConfig)\s*=' "${WG_CONF}" > "${WG_STRIPPED}"

    # Apply config
    wg setconf "${WG_INTERFACE}" "${WG_STRIPPED}"
    rm -f "${WG_STRIPPED}"

    # Set IP address
    local CIDR
    CIDR=$(echo "${WG_SUBNET}" | cut -d'/' -f2)
    ip addr add "${WG_SERVER_IP}/${CIDR}" dev "${WG_INTERFACE}" 2>/dev/null || true
    ip link set "${WG_INTERFACE}" up

    log "WireGuard ${WG_INTERFACE} is UP"
    log "  Listening: 0.0.0.0:${WG_PORT}"
    log "  Server IP: ${WG_SERVER_IP}/${CIDR}"
    log "  Public key: $(cat "${WG_DIR}/server_public.key")"

    # Show peer count
    local PEER_COUNT
    PEER_COUNT=$(find "${WG_PEERS_DIR}" -name "*.conf" 2>/dev/null | wc -l)
    log "  Peers configured: ${PEER_COUNT}"
}

# ── Stop WireGuard ──────────────────────────────────────────
stop_wg() {
    if ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
        ip link set "${WG_INTERFACE}" down
        ip link del "${WG_INTERFACE}" 2>/dev/null || true
        log "WireGuard ${WG_INTERFACE} stopped"
    fi
}

# ── CLI dispatch ────────────────────────────────────────────
case "${1:-start}" in
    start)      start_wg ;;
    stop)       stop_wg ;;
    restart)    stop_wg; start_wg ;;
    add-peer)   init_keys; add_peer "${2:-}" ;;
    remove-peer) remove_peer "${2:-}" ;;
    list-peers) list_peers ;;
    show-client) cat "${WG_PEERS_DIR}/${2:-}.client.conf" 2>/dev/null || echo "Peer not found" ;;
    genconfig)  init_keys; build_config ;;
    *)          echo "Usage: $0 {start|stop|restart|add-peer <name>|remove-peer <name>|list-peers|show-client <name>}" ;;
esac
