#!/bin/bash
# ============================================================
# Cerberix Firewall — Network Configuration Script
# ============================================================
# Auto-detects WAN/LAN interfaces based on assigned IPs,
# configures routing and kernel hardening.
# ============================================================

set -euo pipefail

LAN_IP="${LAN_IP:-192.168.1.1}"
LAN_SUBNET="${LAN_SUBNET:-192.168.1.0/24}"

log() {
    echo "[network] $(date '+%H:%M:%S') $*"
}

# ── Auto-detect interfaces by IP assignment ─────────────────
# Docker assigns IPs based on network config; we detect which
# interface got the LAN IP and which got the WAN IP.
log "Auto-detecting interface roles..."

DETECTED_LAN_IF=""
DETECTED_WAN_IF=""

# List interfaces, stripping @ifN veth suffixes
for iface in $(ip -o link show | awk -F'[@:]' '{gsub(/ /,"",$2); print $2}' | grep -v lo); do
    IF_IP=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    if [ -z "$IF_IP" ]; then
        continue
    fi
    if [ "$IF_IP" = "$LAN_IP" ]; then
        DETECTED_LAN_IF="$iface"
        log "  ${iface} (${IF_IP}) → LAN"
    else
        DETECTED_WAN_IF="$iface"
        log "  ${iface} (${IF_IP}) → WAN"
    fi
done

# Use detected values, fall back to env/defaults
WAN_IF="${DETECTED_WAN_IF:-${WAN_IF:-eth0}}"
LAN_IF="${DETECTED_LAN_IF:-${LAN_IF:-eth1}}"

# Export so downstream scripts (firewall, init) see the correct values
export WAN_IF LAN_IF

# Write detected mapping for other scripts to source
cat > /var/run/cerberix/interfaces.env <<EOF
WAN_IF=${WAN_IF}
LAN_IF=${LAN_IF}
EOF

# ── Enable IP forwarding ───────────────────────────────────
log "Enabling IP forwarding..."
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    log "  IPv4 forwarding: enabled"
else
    log "  IPv4 forwarding: set via sysctl (read-only /proc)"
fi

# ── Apply kernel hardening parameters ──────────────────────
log "Applying kernel network hardening..."
declare -A SYSCTL_PARAMS=(
    ["net.ipv4.conf.all.rp_filter"]="1"
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.tcp_max_syn_backlog"]="2048"
    ["net.ipv4.tcp_synack_retries"]="2"
    ["net.ipv4.tcp_syn_retries"]="5"
)

for param in "${!SYSCTL_PARAMS[@]}"; do
    SYSCTL_PATH="/proc/sys/$(echo "${param}" | tr '.' '/')"
    if [ -w "${SYSCTL_PATH}" ]; then
        echo "${SYSCTL_PARAMS[$param]}" > "${SYSCTL_PATH}"
        log "  ${param} = ${SYSCTL_PARAMS[$param]}"
    fi
done

# Bring interfaces up
ip link set "${WAN_IF}" up 2>/dev/null || true
ip link set "${LAN_IF}" up 2>/dev/null || true

# ── Display network state ──────────────────────────────────
log "Network configuration complete:"
log "  WAN (${WAN_IF}):"
ip -4 addr show "${WAN_IF}" 2>/dev/null | grep "inet " | awk '{print "    " $2}' || log "    no address"
log "  LAN (${LAN_IF}):"
ip -4 addr show "${LAN_IF}" 2>/dev/null | grep "inet " | awk '{print "    " $2}' || log "    no address"
log "  Default route:"
ip route show default 2>/dev/null | awk '{print "    " $0}' || log "    none"
