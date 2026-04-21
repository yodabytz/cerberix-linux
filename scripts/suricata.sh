#!/bin/bash
# ============================================================
# Cerberix Firewall — Suricata IDS Manager
# ============================================================
# Usage:
#   cerberix-ids start         Start Suricata IDS
#   cerberix-ids stop          Stop Suricata
#   cerberix-ids update-rules  Download latest rules
#   cerberix-ids status        Show status
#   cerberix-ids alerts        Show recent alerts
# ============================================================

set -euo pipefail

CONF_DIR="/etc/cerberix/suricata"
LOG_DIR="/var/log/cerberix/suricata"
PID_FILE="/var/run/cerberix/suricata.pid"
SURICATA_CONF="${CONF_DIR}/suricata.yaml"

log() {
    echo "[suricata] $(date '+%H:%M:%S') $*"
}

# ── Start Suricata ──────────────────────────────────────────
start_ids() {
    mkdir -p "${LOG_DIR}" "${CONF_DIR}"

    # Detect WAN interface
    local WAN_IF="eth0"
    if [ -f /var/run/cerberix/interfaces.env ]; then
        source /var/run/cerberix/interfaces.env
        WAN_IF="${WAN_IF:-eth0}"
    fi

    # Update interface in config
    local RUNTIME_CONF="/tmp/suricata-runtime.yaml"
    cp "${SURICATA_CONF}" "${RUNTIME_CONF}"
    sed -i "s/interface: eth0/interface: ${WAN_IF}/" "${RUNTIME_CONF}"

    # Update rules if none exist
    if [ ! -f /var/lib/suricata/rules/suricata.rules ] || \
       [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
        log "Downloading initial rule set..."
        suricata-update --no-test 2>/dev/null || log "WARNING: Rule update failed"
    fi

    log "Starting Suricata IDS on ${WAN_IF}..."
    suricata -c "${RUNTIME_CONF}" \
        --af-packet="${WAN_IF}" \
        --pidfile "${PID_FILE}" \
        -D 2>/dev/null

    sleep 2
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        log "Suricata IDS running (PID: $(cat "${PID_FILE}"))"
        local rule_count
        rule_count=$(grep -c "^alert\|^drop\|^pass" /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
        log "  Rules loaded: ${rule_count}"
        log "  Monitoring: ${WAN_IF}"
        log "  Alerts: ${LOG_DIR}/eve.json"
    else
        log "WARNING: Suricata failed to start"
        return 1
    fi
}

# ── Stop Suricata ───────────────────────────────────────────
stop_ids() {
    if [ -f "${PID_FILE}" ]; then
        kill "$(cat "${PID_FILE}")" 2>/dev/null || true
        rm -f "${PID_FILE}"
        log "Suricata stopped"
    fi
}

# ── Update Rules ────────────────────────────────────────────
update_rules() {
    log "Updating Suricata rules..."
    suricata-update --no-test 2>&1
    local rule_count
    rule_count=$(grep -c "^alert\|^drop\|^pass" /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
    log "Rules updated: ${rule_count} rules loaded"

    # Reload if running
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        kill -USR2 "$(cat "${PID_FILE}")" 2>/dev/null
        log "Suricata reloaded with new rules"
    fi
}

# ── Status ──────────────────────────────────────────────────
show_status() {
    echo "=== Suricata IDS Status ==="
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "  Status:  RUNNING (PID: $(cat "${PID_FILE}"))"
    else
        echo "  Status:  STOPPED"
    fi

    local rule_count
    rule_count=$(grep -c "^alert\|^drop\|^pass" /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
    echo "  Rules:   ${rule_count}"

    if [ -f "${LOG_DIR}/eve.json" ]; then
        local alert_count
        alert_count=$(grep -c '"event_type":"alert"' "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
        echo "  Alerts:  ${alert_count}"
        echo "  Log size: $(du -h "${LOG_DIR}/eve.json" 2>/dev/null | awk '{print $1}')"
    else
        echo "  Alerts:  no log yet"
    fi
}

# ── Recent Alerts ───────────────────────────────────────────
show_alerts() {
    if [ ! -f "${LOG_DIR}/eve.json" ]; then
        echo "No alerts yet"
        return
    fi
    grep '"event_type":"alert"' "${LOG_DIR}/eve.json" | tail -20 | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        print(f\"{e.get('timestamp','?')[:19]}  [{a.get('severity',0)}] {a.get('signature','?')}  {e.get('src_ip','?')} -> {e.get('dest_ip','?')}:{e.get('dest_port','?')}\")
    except: pass
" 2>/dev/null || grep '"event_type":"alert"' "${LOG_DIR}/eve.json" | tail -10
}

# ── CLI dispatch ────────────────────────────────────────────
case "${1:-help}" in
    start)        start_ids ;;
    stop)         stop_ids ;;
    restart)      stop_ids; start_ids ;;
    update-rules) update_rules ;;
    status)       show_status ;;
    alerts)       show_alerts ;;
    *)            echo "Usage: cerberix-ids {start|stop|restart|update-rules|status|alerts}" ;;
esac
