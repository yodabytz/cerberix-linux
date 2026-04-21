#!/bin/bash
# ============================================================
# Cerberix Firewall — ISO Builder using Alpine's mkimage
# ============================================================

set -euo pipefail

VERSION="0.3.0"
WORK="/build/work"
ISO_OUT="/build/cerberix-${VERSION}.iso"

echo "[1/4] Creating Cerberix overlay..."

# Build an apkovl (Alpine local overlay) with all Cerberix customizations
OVERLAY="/build/overlay"
mkdir -p "${OVERLAY}"

# Create the overlay structure that Alpine unpacks on boot
mkdir -p "${OVERLAY}/etc/cerberix"/{nftables.d,dnsmasq.d,suricata,ssl}
mkdir -p "${OVERLAY}/etc/profile.d"
mkdir -p "${OVERLAY}/etc/runlevels/default"
mkdir -p "${OVERLAY}/etc/local.d"
mkdir -p "${OVERLAY}/etc/sysctl.d"
mkdir -p "${OVERLAY}/opt/cerberix"/{ai,web}
mkdir -p "${OVERLAY}/usr/local/bin"
mkdir -p "${OVERLAY}/var/log/cerberix"/{hosts,suricata}
mkdir -p "${OVERLAY}/var/lib/cerberix/ai"

# Copy Cerberix files
cp -r /src/config/*.conf "${OVERLAY}/etc/cerberix/" 2>/dev/null || true
cp -r /src/config/nftables.d/* "${OVERLAY}/etc/cerberix/nftables.d/" 2>/dev/null || true
cp -r /src/config/dnsmasq.d/* "${OVERLAY}/etc/cerberix/dnsmasq.d/" 2>/dev/null || true
cp -r /src/config/suricata/* "${OVERLAY}/etc/cerberix/suricata/" 2>/dev/null || true
cp -r /src/ai/* "${OVERLAY}/opt/cerberix/ai/"
cp -r /src/web/* "${OVERLAY}/opt/cerberix/web/"

# Scripts
declare -A SCRIPTS=(
    [init.sh]=cerberix-init [firewall.sh]=cerberix-firewall
    [network.sh]=cerberix-network [healthcheck.sh]=cerberix-healthcheck
    [wireguard.sh]=cerberix-wg [cerberix-ca.sh]=cerberix-ca
    [threatfeeds.sh]=cerberix-feeds [geoip.sh]=cerberix-geoip
    [suricata.sh]=cerberix-ids
)
for src in "${!SCRIPTS[@]}"; do
    [ -f "/src/scripts/${src}" ] && cp "/src/scripts/${src}" "${OVERLAY}/usr/local/bin/${SCRIPTS[$src]}"
done
chmod 755 "${OVERLAY}/usr/local/bin/"* 2>/dev/null || true

printf '#!/bin/bash\nPYTHONPATH=/opt/cerberix python3 -m ai.cli "$@"\n' > "${OVERLAY}/usr/local/bin/cerberix-ai"
printf '#!/bin/bash\ncat /etc/cerberix-release\n' > "${OVERLAY}/usr/local/bin/cerberix-version"
chmod 755 "${OVERLAY}/usr/local/bin/cerberix-ai" "${OVERLAY}/usr/local/bin/cerberix-version"

# Identity
cp /src/rootfs/etc/os-release "${OVERLAY}/etc/os-release" 2>/dev/null || true
cp /src/rootfs/etc/cerberix-release "${OVERLAY}/etc/cerberix-release" 2>/dev/null || true
cp /src/rootfs/etc/motd "${OVERLAY}/etc/motd" 2>/dev/null || true
cp /src/rootfs/etc/issue "${OVERLAY}/etc/issue" 2>/dev/null || true
cp /src/rootfs/etc/issue.net "${OVERLAY}/etc/issue.net" 2>/dev/null || true
cp /src/rootfs/etc/profile.d/cerberix.sh "${OVERLAY}/etc/profile.d/" 2>/dev/null || true
echo "cerberix" > "${OVERLAY}/etc/hostname"

# Sysctl
cat > "${OVERLAY}/etc/sysctl.d/cerberix.conf" << 'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOF

# First-boot setup script
cat > "${OVERLAY}/etc/local.d/cerberix-setup.start" << 'FBEOF'
#!/bin/bash
if [ ! -f /etc/cerberix/.installed ]; then
    # Install extra packages on first boot
    apk add --no-cache nftables dnsmasq iproute2 iptables syslog-ng \
        bash curl openssl wireguard-tools fail2ban suricata \
        python3 py3-numpy py3-scikit-learn \
        libstdc++ openblas libgfortran libgomp 2>/dev/null

    pip3 install --no-cache-dir --break-system-packages anthropic 2>/dev/null

    # Generate certs
    /usr/local/bin/cerberix-ca init 2>/dev/null
    /usr/local/bin/cerberix-ca sign 2>/dev/null

    # Generate admin password
    ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
    CERBERIX_INIT_PASS="${ADMIN_PASS}" PYTHONPATH=/opt/cerberix python3 -c \
        "import os; from web.auth import create_initial_config; create_initial_config('admin', os.environ['CERBERIX_INIT_PASS'])" 2>/dev/null

    echo ""
    echo "============================================"
    echo "CERBERIX LINUX — FIRST BOOT"
    echo "  Web UI: https://$(hostname -I | awk '{print $1}'):8443"
    echo "  Username: admin"
    echo "  Password: ${ADMIN_PASS}"
    echo "  SAVE THIS PASSWORD"
    echo "============================================"

    touch /etc/cerberix/.installed
fi

# Start Cerberix services
/usr/local/bin/cerberix-init &
FBEOF
chmod 755 "${OVERLAY}/etc/local.d/cerberix-setup.start"

# Installer script
cat > "${OVERLAY}/usr/local/bin/cerberix-install" << 'INSTEOF'
#!/bin/bash
echo "============================================"
echo "Cerberix Firewall Disk Installer"
echo "============================================"
echo ""
lsblk
echo ""
read -p "Install to disk (e.g. sda): " DISK
[ -z "$DISK" ] && exit 1
DISK="/dev/${DISK}"
read -p "ERASE ${DISK}? (yes/no): " CONFIRM
[ "$CONFIRM" != "yes" ] && exit 1

setup-disk -m sys "${DISK}"
echo ""
echo "Done! Remove ISO and reboot."
INSTEOF
chmod 755 "${OVERLAY}/usr/local/bin/cerberix-install"

# Enable local service for first-boot
ln -sf /etc/init.d/local "${OVERLAY}/etc/runlevels/default/local" 2>/dev/null || true

echo "[2/4] Packing overlay..."
cd "${OVERLAY}"
tar czf /build/cerberix.apkovl.tar.gz .
echo "Overlay: $(du -h /build/cerberix.apkovl.tar.gz | awk '{print $1}')"

echo "[3/4] Building ISO with Alpine mkimage..."

# Use Alpine's standard ISO profile with our overlay
mkdir -p /build/iso-work

# Set up aports for mkimage
export PROFILENAME="cerberix"
export PROFILE_cerberix='
profile_cerberix() {
    profile_standard
    title="Cerberix Firewall"
    desc="AI-Powered Firewall Gateway"
    arch="x86_64"
    kernel_flavors="lts"
    apkovl="/build/cerberix.apkovl.tar.gz"
    apks="$apks nftables dnsmasq iproute2 bash curl openssl
        wireguard-tools fail2ban python3 syslog-ng iptables
        e2fsprogs sfdisk dosfstools"
}
'

# Try mkimage if available
if command -v mkimage.sh &>/dev/null || [ -f /usr/share/alpine-conf/mkimage.sh ]; then
    eval "$PROFILE_cerberix"
    mkimage.sh --tag "${VERSION}" \
        --outdir /build \
        --arch x86_64 \
        --repository https://dl-cdn.alpinelinux.org/alpine/v3.21/main \
        --extra-repository https://dl-cdn.alpinelinux.org/alpine/v3.21/community \
        --profile cerberix 2>&1 || echo "mkimage failed, using fallback"
fi

# Fallback: build ISO manually from Alpine's netboot files
if [ ! -f /build/alpine-cerberix-*.iso ] && [ ! -f /build/cerberix-*.iso ]; then
    echo "Using manual ISO assembly..."

    ISO_STAGE="/build/iso-stage"
    mkdir -p "${ISO_STAGE}/boot/grub"

    # Download Alpine's boot files
    MIRROR="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64"
    ALPINE_ISO="alpine-standard-3.21.3-x86_64.iso"

    echo "Downloading Alpine base ISO..."
    wget -q "${MIRROR}/${ALPINE_ISO}" -O /tmp/alpine.iso 2>/dev/null || \
    curl -fsSL "${MIRROR}/${ALPINE_ISO}" -o /tmp/alpine.iso

    # Extract Alpine ISO
    mkdir -p /tmp/alpine-mount
    mount -o loop /tmp/alpine.iso /tmp/alpine-mount

    # Copy boot infrastructure
    cp -a /tmp/alpine-mount/boot "${ISO_STAGE}/"
    cp -a /tmp/alpine-mount/apks "${ISO_STAGE}/" 2>/dev/null || true
    cp -a /tmp/alpine-mount/.alpine-release "${ISO_STAGE}/" 2>/dev/null || true

    # Add our overlay
    cp /build/cerberix.apkovl.tar.gz "${ISO_STAGE}/"

    # Custom GRUB menu
    cat > "${ISO_STAGE}/boot/grub/grub.cfg" << 'GRUBEOF'
set timeout=5
set default=0
insmod all_video
insmod gzio

menuentry "Cerberix Firewall 0.3.0 (Hades)" {
    linux /boot/vmlinuz-lts modules=loop,squashfs,sd-mod,usb-storage quiet
    initrd /boot/initramfs-lts
}
menuentry "Cerberix Firewall (Recovery)" {
    linux /boot/vmlinuz-lts modules=loop,squashfs,sd-mod,usb-storage single
    initrd /boot/initramfs-lts
}
GRUBEOF

    umount /tmp/alpine-mount

    # Build ISO
    grub-mkrescue -o "/build/cerberix-${VERSION}.iso" "${ISO_STAGE}" 2>/dev/null
fi

echo "[4/4] Finalizing..."

# Rename if mkimage created it with Alpine name
for f in /build/alpine-cerberix-*.iso; do
    [ -f "$f" ] && mv "$f" "/build/cerberix-${VERSION}.iso"
done

cp /build/cerberix-${VERSION}.iso /output/ 2>/dev/null || true

echo ""
echo "============================================"
echo "Cerberix Firewall ${VERSION} ISO ready!"
ls -lh /output/cerberix-${VERSION}.*
echo ""
echo "Boot → Login: root (no password) → cerberix-install"
echo "============================================"
