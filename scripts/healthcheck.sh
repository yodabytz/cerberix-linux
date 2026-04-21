#!/bin/bash
# ============================================================
# Cerberix Firewall — Health Check
# ============================================================
# Returns 0 (healthy) or 1 (unhealthy)
# Used by Docker HEALTHCHECK
# ============================================================

ERRORS=0

# Check dnsmasq is running
if ! pgrep -x dnsmasq >/dev/null; then
    echo "UNHEALTHY: dnsmasq not running"
    ERRORS=$((ERRORS + 1))
fi

# Check nftables has rules loaded
RULE_COUNT=$(nft list ruleset 2>/dev/null | grep -c "accept\|drop\|reject\|masquerade" || echo 0)
if [ "${RULE_COUNT}" -lt 5 ]; then
    echo "UNHEALTHY: nftables rules missing (${RULE_COUNT} rules found)"
    ERRORS=$((ERRORS + 1))
fi

# Check IP forwarding
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
    echo "UNHEALTHY: IP forwarding disabled"
    ERRORS=$((ERRORS + 1))
fi

# Check DNS resolution works
if ! nslookup cloudflare.com 127.0.0.1 >/dev/null 2>&1; then
    # Fallback: try direct upstream
    if ! nslookup cloudflare.com 1.1.1.1 >/dev/null 2>&1; then
        echo "WARNING: DNS resolution failing (upstream unreachable)"
        # Don't count as error — upstream may be legitimately down
    fi
fi

# Check AI engine is running
if [ "${CERBERIX_AI_ENABLED:-true}" = "true" ]; then
    if ! pgrep -f "ai.engine" >/dev/null; then
        echo "WARNING: AI engine not running"
        # Non-fatal — firewall still works without AI
    fi
fi

if [ "${ERRORS}" -gt 0 ]; then
    exit 1
fi

echo "HEALTHY"
exit 0
