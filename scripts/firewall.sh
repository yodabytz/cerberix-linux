#!/bin/bash
# ============================================================
# Cerberix Firewall — Firewall Setup Script
# ============================================================
# Loads nftables rules with runtime variable substitution
# ============================================================

set -euo pipefail

CONF_DIR="/etc/cerberix"

WAN_IF="${WAN_IF:-eth0}"
LAN_IF="${LAN_IF:-eth1}"
LAN_SUBNET="${LAN_SUBNET:-192.168.1.0/24}"

log() {
    echo "[firewall] $(date '+%H:%M:%S') $*"
}

# ── Generate runtime nftables config ────────────────────────
RUNTIME_NFT="/tmp/nftables-runtime.conf"

# Start with the base config
cp "${CONF_DIR}/nftables.conf" "${RUNTIME_NFT}"

# Substitute interface variables in main config
sed -i "s|define WAN_IF  = \"eth0\"|define WAN_IF  = \"${WAN_IF}\"|g" "${RUNTIME_NFT}"
sed -i "s|define LAN_IF  = \"eth1\"|define LAN_IF  = \"${LAN_IF}\"|g" "${RUNTIME_NFT}"
sed -i "s|define LAN_NET = 192.168.1.0/24|define LAN_NET = ${LAN_SUBNET}|g" "${RUNTIME_NFT}"

# Copy drop-in files, stripping any 'define' lines (variables come from main config)
mkdir -p /tmp/nftables.d
for f in "${CONF_DIR}"/nftables.d/*.nft; do
    if [ -f "$f" ]; then
        RUNTIME_F="/tmp/nftables.d/$(basename "$f")"
        grep -v '^define ' "$f" > "$RUNTIME_F" || cp "$f" "$RUNTIME_F"
    fi
done

# Update include path to use runtime copies
sed -i "s|/etc/cerberix/nftables.d/|/tmp/nftables.d/|g" "${RUNTIME_NFT}"

# ── Load nftables rules ────────────────────────────────────
log "Flushing existing ruleset..."
nft flush ruleset 2>/dev/null || true

log "Loading firewall rules..."
if nft -f "${RUNTIME_NFT}"; then
    log "Firewall rules loaded successfully."
else
    log "ERROR: Failed to load nftables rules!"
    log "Applying emergency lockdown rules..."

    # Emergency fallback: drop everything except established
    nft flush ruleset
    nft add table inet emergency
    nft add chain inet emergency input '{ type filter hook input priority 0; policy drop; }'
    nft add rule inet emergency input ct state established,related accept
    nft add rule inet emergency input iif lo accept
    nft add chain inet emergency forward '{ type filter hook forward priority 0; policy drop; }'
    nft add chain inet emergency output '{ type filter hook output priority 0; policy accept; }'

    log "Emergency rules active — all inbound/forward DROPPED"
    exit 1
fi

# ── Display loaded rules ───────────────────────────────────
log "Active ruleset:"
nft list ruleset | head -80

RULE_COUNT=$(nft list ruleset | grep -cE "accept|drop|reject|masquerade" || true)
log "Total rules loaded: ${RULE_COUNT}"
