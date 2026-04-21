#!/bin/bash
# ============================================================
# Cerberix Firewall — First Boot Setup Wizard
# ============================================================

# Only run once
if [ -f /etc/cerberix/.setup-complete ]; then
    # Show MOTD on subsequent logins
    cat /etc/motd 2>/dev/null
    echo ""
    IP=$(ip -4 addr show eth0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
    [ -z "$IP" ] && IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "  Web Panel: https://${IP:-<configure network>}:8443"
    echo "  Commands:  cerberix-version | cerberix-ai status | nft list ruleset"
    echo ""
    exit 0
fi

clear
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
         AI-Powered Network Security

============================================
        FIRST BOOT SETUP
============================================

BANNER

echo "Welcome to Cerberix Firewall!"
echo ""
echo "This wizard will configure your firewall gateway."
echo ""

# Step 1: Root password
echo "──────────────────────────────────────────"
echo "Step 1: Set root password"
echo "──────────────────────────────────────────"
passwd root
echo ""

# Step 2: Network
echo "──────────────────────────────────────────"
echo "Step 2: Network Configuration"
echo "──────────────────────────────────────────"
echo ""
echo "Available interfaces:"
ip -o link show | awk -F': ' '{print "  " $2}' | grep -v lo
echo ""
echo "Cerberix needs two interfaces:"
echo "  WAN = connects to your internet/modem"
echo "  LAN = connects to your internal network"
echo ""

# Check if network is already up
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
if [ -n "$IP" ]; then
    echo "Network is already configured: ${IP}"
    echo ""
    read -p "Reconfigure networking? (y/N): " RECONF
    if [ "$RECONF" = "y" ] || [ "$RECONF" = "Y" ]; then
        setup-interfaces
    fi
else
    echo "No network detected. Running network setup..."
    setup-interfaces
    echo ""
    echo "Starting networking..."
    rc-service networking restart 2>/dev/null
fi

# Get IP again
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
[ -z "$IP" ] && IP=$(hostname -I 2>/dev/null | awk '{print $1}')

echo ""

# Step 3: Hostname
echo "──────────────────────────────────────────"
echo "Step 3: Hostname"
echo "──────────────────────────────────────────"
read -p "Hostname [cerberix]: " NEWHOST
NEWHOST="${NEWHOST:-cerberix}"
echo "${NEWHOST}" > /etc/hostname
hostname "${NEWHOST}"
echo "Hostname set to: ${NEWHOST}"
echo ""

# Step 4: Timezone
echo "──────────────────────────────────────────"
echo "Step 4: Timezone"
echo "──────────────────────────────────────────"
setup-timezone 2>/dev/null || {
    read -p "Timezone (e.g. US/Eastern, UTC) [UTC]: " TZ
    TZ="${TZ:-UTC}"
    ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime 2>/dev/null
    echo "${TZ}" > /etc/timezone 2>/dev/null
    echo "Timezone: ${TZ}"
}
echo ""

# Step 5: Generate certs and web credentials
echo "──────────────────────────────────────────"
echo "Step 5: Security Setup"
echo "──────────────────────────────────────────"
echo "Generating TLS certificates..."
/usr/local/bin/cerberix-ca init 2>/dev/null
/usr/local/bin/cerberix-ca sign 2>/dev/null
echo "Certificates generated."
echo ""

ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
CERBERIX_INIT_PASS="${ADMIN_PASS}" PYTHONPATH=/opt/cerberix python3 -c \
    "import os; from web.auth import create_initial_config; create_initial_config('admin', os.environ['CERBERIX_INIT_PASS'])" 2>/dev/null

echo ""

# Step 6: Start services
echo "──────────────────────────────────────────"
echo "Step 6: Starting Services"
echo "──────────────────────────────────────────"
echo "Starting Cerberix services..."
/usr/local/bin/cerberix-init &
sleep 3
echo "Services started."
echo ""

# Mark setup complete
mkdir -p /etc/cerberix
touch /etc/cerberix/.setup-complete

# Final summary
clear
cat << SUMMARY

============================================
   CERBERIX LINUX — SETUP COMPLETE
============================================

   Hostname:  ${NEWHOST}
   IP:        ${IP:-not configured}

   Web Panel: https://${IP:-<IP>}:8443
   Username:  admin
   Password:  ${ADMIN_PASS}

   SSH:       ssh root@${IP:-<IP>}

============================================

   IMPORTANT: Save your web panel password!
   It will not be shown again.

   Commands:
     cerberix-version      System info
     cerberix-ai status    AI engine status
     cerberix-ai threats   Recent threats
     cerberix-ai blocklist Blocked IPs
     nft list ruleset      Firewall rules
     cerberix-wg           WireGuard VPN
     cerberix-ids status   Suricata IDS
     cerberix-feeds update Update threat feeds

   To access the web panel from another
   computer, open a browser and go to:
   https://${IP:-<IP>}:8443

============================================

SUMMARY
