#!/bin/bash
# Cerberix Shield — Waybar security status indicator

fw_active=false
av_ok=false
updates=0

# Check firewall
if systemctl is-active --quiet ufw 2>/dev/null || nft list ruleset &>/dev/null; then
    fw_active=true
fi

# Check for security issues
if $fw_active; then
    class="secure"
    icon=""
    tooltip="Shield: Active\nFirewall: Enabled"
else
    class="danger"
    icon=""
    tooltip="Shield: WARNING\nFirewall: Disabled"
fi

echo "{\"text\": \"$icon\", \"class\": \"$class\", \"tooltip\": \"$tooltip\"}"
