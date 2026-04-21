#!/bin/bash
# ============================================================
# Cerberix Firewall — Threat Feed Updater
# ============================================================
# Downloads known malicious IP/domain blocklists and loads
# them into nftables sets and dnsmasq sinkhole configs.
#
# Usage:
#   cerberix-feeds update     Download and apply feeds
#   cerberix-feeds status     Show feed status
#   cerberix-feeds list       Show loaded entries
# ============================================================

set -euo pipefail

FEED_DIR="/var/lib/cerberix/feeds"
CONF_DIR="/etc/cerberix"
LOG="/var/log/cerberix/feeds.log"

mkdir -p "${FEED_DIR}"

log() {
    local msg="[feeds] $(date '+%Y-%m-%d %H:%M:%S') $*"
    echo "$msg"
    echo "$msg" >> "${LOG}" 2>/dev/null || true
}

# ── IP Threat Feeds ─────────────────────────────────────────
IP_FEEDS=(
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt|ipsum-l3|IPSum Level 3+"
    "https://www.spamhaus.org/drop/drop.txt|spamhaus-drop|Spamhaus DROP"
    "https://www.spamhaus.org/drop/edrop.txt|spamhaus-edrop|Spamhaus EDROP"
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt|et-block|Emerging Threats"
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt|feodo|Feodo Tracker (Banking Trojans)"
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt|sslbl|SSL Blacklist"
    "https://lists.blocklist.de/lists/all.txt|blocklist-de|Blocklist.de (SecuNX)"
    "https://check.torproject.org/torbulkexitlist|tor-exit|Tor Exit Nodes (SecuNX)"
)

# AbuseIPDB (requires API key — set CERBERIX_ABUSEIPDB_KEY)
ABUSEIPDB_KEY="${CERBERIX_ABUSEIPDB_KEY:-}"
ABUSEIPDB_THRESHOLD="${CERBERIX_ABUSEIPDB_THRESHOLD:-50}"

# ── Domain Threat Feeds ────────────────────────────────────
DOMAIN_FEEDS=(
    "https://urlhaus.abuse.ch/downloads/hostfile/|urlhaus|URLhaus Malware Domains"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts|stevenblack|StevenBlack Unified Hosts"
)

# ── Download and parse IP feeds ─────────────────────────────
download_ip_feeds() {
    local COMBINED="${FEED_DIR}/all-blocked-ips.txt"
    > "${COMBINED}"

    for feed_entry in "${IP_FEEDS[@]}"; do
        IFS='|' read -r url name desc <<< "${feed_entry}"
        local outfile="${FEED_DIR}/${name}.txt"

        log "Downloading ${desc}..."
        if curl -fsSL --connect-timeout 10 --max-time 30 "${url}" -o "${outfile}.tmp" 2>/dev/null; then
            # Extract valid IPs/CIDRs (skip comments, empty lines)
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "${outfile}.tmp" \
                | sort -u > "${outfile}"
            local count
            count=$(wc -l < "${outfile}")
            log "  ${desc}: ${count} entries"
            cat "${outfile}" >> "${COMBINED}"
            rm -f "${outfile}.tmp"
        else
            log "  WARNING: Failed to download ${desc}"
        fi
    done

    # Deduplicate
    # AbuseIPDB (if API key is set)
    if [ -n "${ABUSEIPDB_KEY}" ]; then
        log "Downloading AbuseIPDB (threshold: ${ABUSEIPDB_THRESHOLD})..."
        local abuseipdb_file="${FEED_DIR}/abuseipdb.txt"
        local response
        response=$(curl -fsSL --connect-timeout 10 --max-time 30 \
            -G "https://api.abuseipdb.com/api/v2/blacklist" \
            --data-urlencode "maxAgeInDays=90" \
            --data-urlencode "confidenceMinimum=${ABUSEIPDB_THRESHOLD}" \
            -H "Key: ${ABUSEIPDB_KEY}" \
            -H "Accept: text/plain" 2>/dev/null) || true
        if [ -n "${response}" ]; then
            echo "${response}" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
                | sort -u > "${abuseipdb_file}"
            local count
            count=$(wc -l < "${abuseipdb_file}")
            log "  AbuseIPDB (SecuNX): ${count} entries"
            cat "${abuseipdb_file}" >> "${COMBINED}"
        else
            log "  WARNING: AbuseIPDB failed (check API key)"
        fi
    else
        log "  AbuseIPDB skipped (set CERBERIX_ABUSEIPDB_KEY to enable)"
    fi

    sort -u "${COMBINED}" -o "${COMBINED}"
    local total
    total=$(wc -l < "${COMBINED}")
    log "Total unique blocked IPs/networks: ${total}"
}

# ── Download and parse domain feeds ─────────────────────────
download_domain_feeds() {
    local COMBINED="${FEED_DIR}/all-blocked-domains.txt"
    > "${COMBINED}"

    for feed_entry in "${DOMAIN_FEEDS[@]}"; do
        IFS='|' read -r url name desc <<< "${feed_entry}"
        local outfile="${FEED_DIR}/${name}.txt"

        log "Downloading ${desc}..."
        if curl -fsSL --connect-timeout 10 --max-time 60 "${url}" -o "${outfile}.tmp" 2>/dev/null; then
            # Extract domains from hosts file format (0.0.0.0 domain.com)
            grep -oE '0\.0\.0\.0\s+[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${outfile}.tmp" \
                | awk '{print $2}' \
                | grep -v 'localhost' \
                | sort -u > "${outfile}"
            local count
            count=$(wc -l < "${outfile}")
            log "  ${desc}: ${count} entries"
            cat "${outfile}" >> "${COMBINED}"
            rm -f "${outfile}.tmp"
        else
            log "  WARNING: Failed to download ${desc}"
        fi
    done

    sort -u "${COMBINED}" -o "${COMBINED}"
    local total
    total=$(wc -l < "${COMBINED}")
    log "Total unique blocked domains: ${total}"
}

# ── Load IPs into nftables ──────────────────────────────────
load_ip_blocklist() {
    local COMBINED="${FEED_DIR}/all-blocked-ips.txt"
    [ -f "${COMBINED}" ] || return

    # Create the threat feed nftables set
    nft add table inet threat_feeds 2>/dev/null || true
    nft add set inet threat_feeds blocklist \
        '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
    nft add chain inet threat_feeds feed_block \
        '{ type filter hook input priority -3; policy accept; }' 2>/dev/null || true
    nft add chain inet threat_feeds feed_block_fwd \
        '{ type filter hook forward priority -3; policy accept; }' 2>/dev/null || true

    # Flush existing entries
    nft flush set inet threat_feeds blocklist 2>/dev/null || true

    # Load in batches of 1000 (nft has argument limits)
    local batch=""
    local count=0
    local total=0

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        batch="${batch}${batch:+, }${ip}"
        count=$((count + 1))
        total=$((total + 1))

        if [ $count -ge 500 ]; then
            nft add element inet threat_feeds blocklist "{ ${batch} }" 2>/dev/null || true
            batch=""
            count=0
        fi
    done < "${COMBINED}"

    # Load remaining
    if [ -n "$batch" ]; then
        nft add element inet threat_feeds blocklist "{ ${batch} }" 2>/dev/null || true
    fi

    # Add drop rules if not present
    local rule_count
    rule_count=$(nft list chain inet threat_feeds feed_block 2>/dev/null | grep -c "drop" || echo 0)
    if [ "$rule_count" -eq 0 ]; then
        nft add rule inet threat_feeds feed_block \
            ip saddr @blocklist log prefix '"[CERBERIX THREAT FEED] "' drop 2>/dev/null || true
        nft add rule inet threat_feeds feed_block_fwd \
            ip saddr @blocklist log prefix '"[CERBERIX THREAT FEED FWD] "' drop 2>/dev/null || true
    fi

    log "Loaded ${total} IPs into nftables threat feed blocklist"
}

# ── Load domains into dnsmasq ───────────────────────────────
load_domain_blocklist() {
    local COMBINED="${FEED_DIR}/all-blocked-domains.txt"
    [ -f "${COMBINED}" ] || return

    local DNSMASQ_BLOCK="${CONF_DIR}/dnsmasq.d/threat-feeds.conf"

    # Generate dnsmasq sinkhole config
    log "Generating dnsmasq sinkhole config..."
    {
        echo "# Auto-generated by Cerberix threat feeds"
        echo "# Updated: $(date -Iseconds)"
        echo "# Do not edit — will be overwritten on next update"
        while IFS= read -r domain; do
            [ -z "$domain" ] && continue
            echo "address=/${domain}/0.0.0.0"
        done < "${COMBINED}"
    } > "${DNSMASQ_BLOCK}"

    local count
    count=$(wc -l < "${COMBINED}")
    log "Sinkholed ${count} domains via dnsmasq"

    # Reload dnsmasq
    killall -HUP dnsmasq 2>/dev/null || true
}

# ── Status ──────────────────────────────────────────────────
show_status() {
    echo "=== Threat Feed Status ==="
    local ip_file="${FEED_DIR}/all-blocked-ips.txt"
    local dom_file="${FEED_DIR}/all-blocked-domains.txt"

    if [ -f "$ip_file" ]; then
        echo "  IP blocklist:     $(wc -l < "$ip_file") entries"
        echo "  Last updated:     $(stat -c '%y' "$ip_file" 2>/dev/null | cut -d. -f1)"
    else
        echo "  IP blocklist:     not downloaded"
    fi

    if [ -f "$dom_file" ]; then
        echo "  Domain blocklist: $(wc -l < "$dom_file") entries"
        echo "  Last updated:     $(stat -c '%y' "$dom_file" 2>/dev/null | cut -d. -f1)"
    else
        echo "  Domain blocklist: not downloaded"
    fi

    echo ""
    echo "  nftables set entries: $(nft list set inet threat_feeds blocklist 2>/dev/null | grep -c 'elements' || echo 0)"

    echo ""
    echo "=== Individual Feeds ==="
    for feed_entry in "${IP_FEEDS[@]}"; do
        IFS='|' read -r _ name desc <<< "${feed_entry}"
        local f="${FEED_DIR}/${name}.txt"
        if [ -f "$f" ]; then
            printf "  %-30s %6d entries\n" "${desc}" "$(wc -l < "$f")"
        else
            printf "  %-30s %s\n" "${desc}" "not downloaded"
        fi
    done
}

# ── Full update ─────────────────────────────────────────────
update() {
    log "============================================"
    log "Cerberix Threat Feed Update starting"
    log "============================================"
    download_ip_feeds
    download_domain_feeds
    load_ip_blocklist
    load_domain_blocklist
    log "============================================"
    log "Threat Feed Update complete"
    log "============================================"

    # Save timestamp
    date -Iseconds > "${FEED_DIR}/last_update"
}

# ── CLI dispatch ────────────────────────────────────────────
enable() {
    echo "enabled" > "${FEED_DIR}/state"
    log "Threat feeds ENABLED"
    update
}

disable() {
    echo "disabled" > "${FEED_DIR}/state"
    # Flush nftables set
    nft flush set inet threat_feeds blocklist 2>/dev/null || true
    # Remove dnsmasq sinkhole
    rm -f "${CONF_DIR}/dnsmasq.d/threat-feeds.conf"
    killall -HUP dnsmasq 2>/dev/null || true
    log "Threat feeds DISABLED — all feed blocks removed"
}

is_enabled() {
    local state_file="${FEED_DIR}/state"
    if [ -f "$state_file" ] && [ "$(cat "$state_file")" = "disabled" ]; then
        return 1
    fi
    return 0
}

case "${1:-help}" in
    update)
        if is_enabled; then
            update
        else
            log "Threat feeds are disabled. Run 'cerberix-feeds enable' first."
        fi
        ;;
    status)  show_status ;;
    list)    nft list set inet threat_feeds blocklist 2>/dev/null | head -50 ;;
    enable)  enable ;;
    disable) disable ;;
    *)       echo "Usage: cerberix-feeds {update|status|list|enable|disable}" ;;
esac
