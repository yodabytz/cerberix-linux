#!/bin/bash
# Cerberix VPN — Waybar status indicator

if ip link show wg0 &>/dev/null 2>&1; then
    echo '{"text": " VPN", "class": "connected", "tooltip": "WireGuard: Connected"}'
elif nmcli -t -f TYPE,STATE connection show --active 2>/dev/null | grep -q "vpn:activated"; then
    echo '{"text": " VPN", "class": "connected", "tooltip": "VPN: Connected"}'
else
    echo '{"text": " VPN", "class": "disconnected", "tooltip": "VPN: Disconnected"}'
fi
