#!/bin/bash
# Runs INSIDE Alpine Docker container to build the VDI
set -e

IMG="/tmp/cerberix.img"
MOUNT="/tmp/cmount"
SRC="/src"

dd if=/dev/zero of="${IMG}" bs=1M count=3072 status=none
parted -s "${IMG}" mklabel msdos
parted -s "${IMG}" mkpart primary ext4 1MiB 100%
parted -s "${IMG}" set 1 boot on

LOOP=$(losetup --show -fP "${IMG}")
mkfs.ext4 -L CERBERIX -q "${LOOP}p1"
mkdir -p "${MOUNT}"
mount "${LOOP}p1" "${MOUNT}"

echo "[1/8] Alpine base..."
apk -X https://dl-cdn.alpinelinux.org/alpine/v3.21/main \
    -X https://dl-cdn.alpinelinux.org/alpine/v3.21/community \
    -U --allow-untrusted --root "${MOUNT}" --initdb \
    add alpine-base openrc linux-lts e2fsprogs grub grub-bios

echo "[2/8] Cerberix packages..."
echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/main" > "${MOUNT}/etc/apk/repositories"
echo "https://dl-cdn.alpinelinux.org/alpine/v3.21/community" >> "${MOUNT}/etc/apk/repositories"
mount -t proc none "${MOUNT}/proc"
mount -t sysfs none "${MOUNT}/sys"
mount --bind /dev "${MOUNT}/dev"
echo "nameserver 1.1.1.1" > "${MOUNT}/etc/resolv.conf"

chroot "${MOUNT}" apk update
chroot "${MOUNT}" apk add --no-cache \
    nftables dnsmasq iproute2 iptables syslog-ng \
    bash curl ca-certificates openssl \
    wireguard-tools fail2ban suricata \
    python3 py3-pip py3-numpy py3-scikit-learn \
    libstdc++ openblas libgfortran libgomp

echo "[3/8] Python AI..."
chroot "${MOUNT}" pip3 install --no-cache-dir --break-system-packages anthropic 2>/dev/null || true

echo "[4/8] Cerberix app files..."
mkdir -p "${MOUNT}/etc/cerberix"/{nftables.d,dnsmasq.d,suricata,ssl,wireguard}
mkdir -p "${MOUNT}/opt/cerberix"/{ai,web}
mkdir -p "${MOUNT}/var/log/cerberix"/{hosts,suricata}
mkdir -p "${MOUNT}/var/lib/cerberix/ai" "${MOUNT}/var/run/cerberix"
mkdir -p "${MOUNT}/etc/profile.d" "${MOUNT}/etc/local.d" "${MOUNT}/etc/sysctl.d"
mkdir -p "${MOUNT}/etc/network" "${MOUNT}/etc/modules-load.d"

cp ${SRC}/config/*.conf "${MOUNT}/etc/cerberix/" 2>/dev/null || true
cp ${SRC}/config/nftables.d/* "${MOUNT}/etc/cerberix/nftables.d/" 2>/dev/null || true
cp ${SRC}/config/dnsmasq.d/* "${MOUNT}/etc/cerberix/dnsmasq.d/" 2>/dev/null || true
cp ${SRC}/config/suricata/* "${MOUNT}/etc/cerberix/suricata/" 2>/dev/null || true
cp -r ${SRC}/config/fail2ban/* "${MOUNT}/etc/fail2ban/" 2>/dev/null || true
cp -r ${SRC}/ai/* "${MOUNT}/opt/cerberix/ai/"
cp -r ${SRC}/web/* "${MOUNT}/opt/cerberix/web/"

cp ${SRC}/scripts/init.sh "${MOUNT}/usr/local/bin/cerberix-init"
cp ${SRC}/scripts/firewall.sh "${MOUNT}/usr/local/bin/cerberix-firewall"
cp ${SRC}/scripts/network.sh "${MOUNT}/usr/local/bin/cerberix-network"
cp ${SRC}/scripts/healthcheck.sh "${MOUNT}/usr/local/bin/cerberix-healthcheck"
for f in wireguard.sh cerberix-ca.sh threatfeeds.sh geoip.sh suricata.sh; do
    [ -f "${SRC}/scripts/${f}" ] && cp "${SRC}/scripts/${f}" "${MOUNT}/usr/local/bin/cerberix-$(echo $f | sed 's/\.sh//' | sed 's/wireguard/wg/' | sed 's/cerberix-//' | sed 's/threatfeeds/feeds/')"
done
echo '#!/bin/bash' > "${MOUNT}/usr/local/bin/cerberix-ai"
echo 'PYTHONPATH=/opt/cerberix python3 -m ai.cli "$@"' >> "${MOUNT}/usr/local/bin/cerberix-ai"
echo '#!/bin/bash' > "${MOUNT}/usr/local/bin/cerberix-version"
echo 'cat /etc/cerberix-release' >> "${MOUNT}/usr/local/bin/cerberix-version"
chmod 755 "${MOUNT}/usr/local/bin/cerberix-"*

cp ${SRC}/rootfs/etc/os-release "${MOUNT}/etc/" 2>/dev/null || true
cp ${SRC}/rootfs/etc/cerberix-release "${MOUNT}/etc/" 2>/dev/null || true
cp ${SRC}/rootfs/etc/motd "${MOUNT}/etc/" 2>/dev/null || true
cp ${SRC}/rootfs/etc/issue "${MOUNT}/etc/" 2>/dev/null || true
cp ${SRC}/rootfs/etc/issue.net "${MOUNT}/etc/issue.net" 2>/dev/null || true
cp ${SRC}/rootfs/etc/profile.d/cerberix.sh "${MOUNT}/etc/profile.d/" 2>/dev/null || true
rm -f "${MOUNT}/etc/alpine-release"

echo "[5/8] Bootloader..."
UUID=$(blkid -s UUID -o value "${LOOP}p1")
KVER=$(ls "${MOUNT}/lib/modules/" | head -1)
chroot "${MOUNT}" mkinitfs -F "ata base cdrom ext4 keymap kms mmc network nvme raid scsi usb virtio" "${KVER}"
chroot "${MOUNT}" grub-install --target=i386-pc --boot-directory=/boot "${LOOP}"

mkdir -p "${MOUNT}/boot/grub"
cat > "${MOUNT}/boot/grub/grub.cfg" << EOF
set timeout=3
set default=0
insmod ext2
insmod gzio
insmod part_msdos
menuentry "Cerberix Firewall 0.3.0 (Hades)" {
    linux /boot/vmlinuz-lts root=UUID=${UUID} rootfstype=ext4 rw modules=ext4,ata_piix,sd_mod,e1000 quiet
    initrd /boot/initramfs-lts
}
menuentry "Cerberix Firewall (Recovery)" {
    linux /boot/vmlinuz-lts root=UUID=${UUID} rootfstype=ext4 rw modules=ext4,ata_piix,sd_mod,e1000 single
    initrd /boot/initramfs-lts
}
EOF

echo "[6/8] System config..."
echo "UUID=${UUID} / ext4 rw,noatime 0 1" > "${MOUNT}/etc/fstab"
printf "e1000\ne1000e\nvirtio_net\n" > "${MOUNT}/etc/modules"
printf "auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet dhcp\nauto eth1\niface eth1 inet dhcp\n" > "${MOUNT}/etc/network/interfaces"
printf "nameserver 1.1.1.1\nnameserver 1.0.0.1\n" > "${MOUNT}/etc/resolv.conf"
echo "cerberix" > "${MOUNT}/etc/hostname"
echo "root:cerberix" | chroot "${MOUNT}" chpasswd

cat > "${MOUNT}/etc/sysctl.d/cerberix.conf" << 'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOF

# inittab with remount rw + modprobe + autologin
cat > "${MOUNT}/etc/inittab" << 'EOF'
::sysinit:/bin/mount -o remount,rw /
::sysinit:/sbin/modprobe e1000
::sysinit:/sbin/modprobe e1000e
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
tty1::respawn:/sbin/getty -n -l /usr/local/bin/cerberix-autologin 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

echo '#!/bin/sh' > "${MOUNT}/usr/local/bin/cerberix-autologin"
echo 'exec /bin/login -f root' >> "${MOUNT}/usr/local/bin/cerberix-autologin"
chmod 755 "${MOUNT}/usr/local/bin/cerberix-autologin"

# Network fallback
cat > "${MOUNT}/etc/local.d/01-network.start" << 'EOF'
#!/bin/sh
for m in e1000 e1000e virtio_net; do modprobe $m 2>/dev/null; done
sleep 1
for i in eth0 eth1; do
    ip link show "$i" >/dev/null 2>&1 && { ip link set "$i" up; udhcpc -i "$i" -n -q 2>/dev/null & }
done
sleep 2
grep -q nameserver /etc/resolv.conf 2>/dev/null || echo "nameserver 1.1.1.1" > /etc/resolv.conf
EOF
chmod 755 "${MOUNT}/etc/local.d/01-network.start"

echo "[7/8] Services..."
rm -rf "${MOUNT}/etc/runlevels"
mkdir -p "${MOUNT}/etc/runlevels"/{sysinit,boot,default,shutdown}
for s in devfs dmesg mdev hwdrivers modules; do ln -sf /etc/init.d/$s "${MOUNT}/etc/runlevels/sysinit/$s" 2>/dev/null; done
for s in hostname hwclock bootmisc sysctl networking; do ln -sf /etc/init.d/$s "${MOUNT}/etc/runlevels/boot/$s" 2>/dev/null; done
for s in local syslog-ng dnsmasq nftables fail2ban; do ln -sf /etc/init.d/$s "${MOUNT}/etc/runlevels/default/$s" 2>/dev/null; done
for s in killprocs savecache mount-ro; do ln -sf /etc/init.d/$s "${MOUNT}/etc/runlevels/shutdown/$s" 2>/dev/null; done

# Cerberix OpenRC service
cp ${SRC}/installer/cerberix.initd "${MOUNT}/etc/init.d/cerberix" 2>/dev/null || cat > "${MOUNT}/etc/init.d/cerberix" << 'SVCEOF'
#!/sbin/openrc-run
name="cerberix"
description="Cerberix Firewall Gateway"
depend() { need net localmount; after networking syslog-ng dnsmasq nftables; }
start() {
    ebegin "Starting Cerberix Gateway"
    mkdir -p /var/run/cerberix /var/log/cerberix/hosts /var/log/cerberix/suricata /etc/cerberix/ssl
    grep -q nameserver /etc/resolv.conf 2>/dev/null || echo "nameserver 1.1.1.1" > /etc/resolv.conf
    [ ! -f /etc/cerberix/ssl/cert.pem ] && { /usr/local/bin/cerberix-ca init 2>/dev/null; /usr/local/bin/cerberix-ca sign 2>/dev/null; }
    if [ ! -f /etc/cerberix/ssl/webui.conf ]; then
        PASS=$(head -c 16 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 16)
        CERBERIX_INIT_PASS="$PASS" PYTHONPATH=/opt/cerberix python3 -c "import os;from web.auth import create_initial_config;create_initial_config('admin',os.environ['CERBERIX_INIT_PASS'])" 2>/dev/null
        echo "$PASS" > /etc/cerberix/.webui-pass; chmod 600 /etc/cerberix/.webui-pass
    fi
    /usr/local/bin/cerberix-firewall 2>/dev/null || true
    /usr/local/bin/cerberix-ids start 2>/dev/null || true
    rm -f /etc/fail2ban/jail.d/alpine-ssh.conf 2>/dev/null
    touch /var/log/fail2ban.log /var/log/cerberix/hosts/remote.log /var/log/cerberix/webui-audit.log
    PYTHONPATH=/opt/cerberix start-stop-daemon --start --background --make-pidfile --pidfile /run/cerberix/webui.pid --exec /usr/bin/python3 -- -m web.server 2>/dev/null
    PYTHONPATH=/opt/cerberix start-stop-daemon --start --background --make-pidfile --pidfile /run/cerberix/ai-engine.pid --exec /usr/bin/python3 -- -m ai.engine 2>/dev/null
    eend 0
}
stop() {
    ebegin "Stopping Cerberix Gateway"
    start-stop-daemon --stop --pidfile /run/cerberix/webui.pid 2>/dev/null
    start-stop-daemon --stop --pidfile /run/cerberix/ai-engine.pid 2>/dev/null
    eend 0
}
SVCEOF
chmod 755 "${MOUNT}/etc/init.d/cerberix"
ln -sf /etc/init.d/cerberix "${MOUNT}/etc/runlevels/default/cerberix"

echo "[8/8] Login + password tool..."
cat > "${MOUNT}/usr/local/bin/set-panel-password" << 'EOF'
#!/bin/bash
echo ""
read -sp "New web panel password: " NEWPASS; echo ""
read -sp "Confirm: " CONFIRM; echo ""
[ "$NEWPASS" != "$CONFIRM" ] && { echo "Mismatch."; exit 1; }
[ ${#NEWPASS} -lt 6 ] && { echo "Too short (min 6)."; exit 1; }
CERBERIX_INIT_PASS="$NEWPASS" PYTHONPATH=/opt/cerberix python3 -c "import os;from web.auth import create_initial_config;create_initial_config('admin',os.environ['CERBERIX_INIT_PASS'])"
echo "$NEWPASS" > /etc/cerberix/.webui-pass; chmod 600 /etc/cerberix/.webui-pass
echo "Updated! Login: admin / $NEWPASS"
EOF
chmod 755 "${MOUNT}/usr/local/bin/set-panel-password"

cat > "${MOUNT}/root/.profile" << 'PROFEOF'
clear
for i in 1 2 3 4 5; do
    IP=$(ip -4 addr show eth0 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}')
    [ -n "$IP" ] && break; sleep 1
done
[ -z "$IP" ] && IP="127.0.0.1"
PASS=$(cat /etc/cerberix/.webui-pass 2>/dev/null || echo "not set")
cat /etc/motd 2>/dev/null
echo ""
echo "  Web Panel: https://${IP}:8443"
echo "  Username:  admin"
echo "  Password:  ${PASS}"
echo ""
echo "  Root login: cerberix"
echo ""
echo "  set-panel-password  Change web panel password"
echo "  cerberix-version    System info"
echo "  cerberix-ai status  AI engine"
echo ""
PROFEOF

chroot "${MOUNT}" suricata-update --no-test 2>/dev/null || true

echo "=== VERIFY ==="
for p in nft dnsmasq syslog-ng fail2ban-server suricata python3 bash openssl; do
    printf "  $p: "; chroot "${MOUNT}" which $p 2>/dev/null || echo "MISSING"
done
echo "  Disk: $(du -sh ${MOUNT} | awk '{print $1}')"

umount "${MOUNT}/dev" "${MOUNT}/sys" "${MOUNT}/proc" 2>/dev/null
umount "${MOUNT}"
losetup -d "${LOOP}"

qemu-img convert -f raw -O vdi "${IMG}" /output/cerberix-0.3.0.vdi
ls -lh /output/cerberix-0.3.0.vdi
echo "BUILD COMPLETE"
