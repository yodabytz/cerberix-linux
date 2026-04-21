#!/bin/bash
# ============================================================
# Cerberix Firewall — GeoIP Country Blocking
# ============================================================
# Downloads country IP ranges and creates nftables sets to
# block/allow traffic by country.
#
# Usage:
#   cerberix-geoip update              Download latest IP data
#   cerberix-geoip block CN RU KP      Block countries (ISO codes)
#   cerberix-geoip allow US GB DE      Allow only these countries (block all others)
#   cerberix-geoip list                Show blocked countries
#   cerberix-geoip status              Show status
# ============================================================

set -euo pipefail

GEO_DIR="/var/lib/cerberix/geoip"
CONF_FILE="/etc/cerberix/geoip.conf"
LOG="/var/log/cerberix/geoip.log"

mkdir -p "${GEO_DIR}"

log() {
    local msg="[geoip] $(date '+%Y-%m-%d %H:%M:%S') $*"
    echo "$msg"
    echo "$msg" >> "${LOG}" 2>/dev/null || true
}

# ── Download country IP ranges ──────────────────────────────
update_data() {
    log "Downloading GeoIP country data..."

    # Use ipdeny.com aggregated CIDR zones (free, no registration)
    local URL="https://www.ipdeny.com/ipblocks/data/aggregated"

    if curl -fsSL --connect-timeout 10 "${URL}/" -o "${GEO_DIR}/index.html" 2>/dev/null; then
        # Extract available country zone files
        grep -oE '[a-z]{2}-aggregated\.zone' "${GEO_DIR}/index.html" | sort -u | while read -r zone; do
            local cc="${zone%%-aggregated.zone}"
            if curl -fsSL "${URL}/${zone}" -o "${GEO_DIR}/${cc}.zone" 2>/dev/null; then
                local count
                count=$(wc -l < "${GEO_DIR}/${cc}.zone")
                log "  ${cc}: ${count} CIDR blocks"
            fi
        done
        rm -f "${GEO_DIR}/index.html"
        date -Iseconds > "${GEO_DIR}/last_update"
        log "GeoIP data updated"
    else
        log "ERROR: Failed to download GeoIP data"
        return 1
    fi
}

# ── Block specific countries ────────────────────────────────
block_countries() {
    local countries=("$@")

    # Create nftables table and set
    nft add table inet geoip 2>/dev/null || true
    nft add set inet geoip blocked \
        '{ type ipv4_addr; flags interval; }' 2>/dev/null || true

    # Flush existing
    nft flush set inet geoip blocked 2>/dev/null || true

    local total=0

    for cc in "${countries[@]}"; do
        cc=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
        local zone="${GEO_DIR}/${cc}.zone"

        if [ ! -f "$zone" ]; then
            log "WARNING: No data for country '${cc}' — run 'cerberix-geoip update' first"
            continue
        fi

        local count
        count=$(wc -l < "$zone")
        log "Loading ${cc}: ${count} CIDR blocks..."

        # Load in batches
        local batch=""
        local bcount=0

        while IFS= read -r cidr; do
            [ -z "$cidr" ] && continue
            batch="${batch}${batch:+, }${cidr}"
            bcount=$((bcount + 1))
            total=$((total + 1))

            if [ $bcount -ge 500 ]; then
                nft add element inet geoip blocked "{ ${batch} }" 2>/dev/null || true
                batch=""
                bcount=0
            fi
        done < "$zone"

        if [ -n "$batch" ]; then
            nft add element inet geoip blocked "{ ${batch} }" 2>/dev/null || true
        fi
    done

    # Add drop rules
    nft add chain inet geoip geo_block \
        '{ type filter hook input priority -4; policy accept; }' 2>/dev/null || true
    nft add chain inet geoip geo_block_fwd \
        '{ type filter hook forward priority -4; policy accept; }' 2>/dev/null || true

    # Only add rules if not already present
    local rc
    rc=$(nft list chain inet geoip geo_block 2>/dev/null | grep -c "drop" || echo 0)
    if [ "$rc" -eq 0 ]; then
        nft add rule inet geoip geo_block \
            ip saddr @blocked log prefix '"[CERBERIX GEOIP] "' drop 2>/dev/null || true
        nft add rule inet geoip geo_block_fwd \
            ip saddr @blocked log prefix '"[CERBERIX GEOIP FWD] "' drop 2>/dev/null || true
    fi

    # Save config
    echo "${countries[*]}" > "${CONF_FILE}"
    log "Blocked ${total} CIDR ranges from: ${countries[*]}"
}

# ── Status ──────────────────────────────────────────────────
show_status() {
    echo "=== GeoIP Status ==="
    if [ -f "${GEO_DIR}/last_update" ]; then
        echo "  Last update: $(cat "${GEO_DIR}/last_update")"
        echo "  Countries available: $(find "${GEO_DIR}" -name "*.zone" | wc -l)"
    else
        echo "  Data not downloaded — run 'cerberix-geoip update'"
    fi

    if [ -f "${CONF_FILE}" ]; then
        echo "  Blocked countries: $(cat "${CONF_FILE}")"
    else
        echo "  No countries blocked"
    fi

    local set_count
    set_count=$(nft list set inet geoip blocked 2>/dev/null | grep -oE 'elements = ' | wc -l || echo 0)
    echo "  nftables set loaded: $([ "$set_count" -gt 0 ] && echo "yes" || echo "no")"
}

unblock_country() {
    local remove_cc="${1:?Usage: unblock <CC>}"
    remove_cc=$(echo "$remove_cc" | tr '[:upper:]' '[:lower:]')

    if [ ! -f "${CONF_FILE}" ]; then
        log "No countries are blocked"
        return
    fi

    local current
    current=$(cat "${CONF_FILE}")
    local remaining=""

    for cc in $current; do
        cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
        if [ "$cc_lower" != "$remove_cc" ]; then
            remaining="${remaining} ${cc}"
        fi
    done

    remaining=$(echo "$remaining" | xargs)

    if [ -z "$remaining" ]; then
        # No countries left — clear everything
        nft flush set inet geoip blocked 2>/dev/null || true
        rm -f "${CONF_FILE}"
        log "All GeoIP blocks removed"
    else
        # Re-block remaining countries
        echo "$remaining" > "${CONF_FILE}"
        block_countries $remaining
    fi

    log "Unblocked country: $(echo "$remove_cc" | tr '[:lower:]' '[:upper:]')"
}

clear_all() {
    nft flush set inet geoip blocked 2>/dev/null || true
    rm -f "${CONF_FILE}"
    log "All GeoIP blocks cleared"
}

list_blocked() {
    if [ -f "${CONF_FILE}" ]; then
        echo "Blocked countries: $(cat "${CONF_FILE}")"
    else
        echo "No countries blocked"
    fi
}

# ── CLI dispatch ────────────────────────────────────────────
case "${1:-help}" in
    update)   update_data ;;
    block)    shift; block_countries "$@" ;;
    unblock)  unblock_country "${2:-}" ;;
    clear)    clear_all ;;
    list)     list_blocked ;;
    status)   show_status ;;
    *)        echo "Usage: cerberix-geoip {update|block <CC>|unblock <CC>|clear|list|status}" ;;
esac
