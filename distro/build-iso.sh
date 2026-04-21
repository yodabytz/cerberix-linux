#!/bin/bash
set -e

PROFILE_DIR="/cerberix-profile"
WORK_DIR="/tmp/cerberix-build"
OUT_DIR="/output"

echo "============================================"
echo " Cerberix Linux ISO Builder — XFCE Edition"
echo "============================================"

ARCHISO_PROFILE="/tmp/archiso-profile"
cp -r /usr/share/archiso/configs/releng "${ARCHISO_PROFILE}"

# Add our packages
cat "${PROFILE_DIR}/packages.x86_64" >> "${ARCHISO_PROFILE}/packages.x86_64"
sort -u "${ARCHISO_PROFILE}/packages.x86_64" -o "${ARCHISO_PROFILE}/packages.x86_64"
sed -i '/grml-zsh-config/d' "${ARCHISO_PROFILE}/packages.x86_64"

# Ship the package list on the live ISO so the installer reuses it verbatim
install -Dm644 "${PROFILE_DIR}/packages.x86_64" "${ARCHISO_PROFILE}/airootfs/etc/cerberix/packages.x86_64"

# Overlay our custom rootfs (cerberix scripts, /etc/skel, systemd units, icons)
# build.sh stages this as /cerberix-profile/rootfs inside the container
if [ -d "${PROFILE_DIR}/rootfs" ]; then
    cp -a "${PROFILE_DIR}/rootfs/." "${ARCHISO_PROFILE}/airootfs/"
    chmod 755 "${ARCHISO_PROFILE}/airootfs/usr/local/bin/"cerberix-* 2>/dev/null || true
    chmod 755 "${ARCHISO_PROFILE}/airootfs/usr/local/bin/"{grep,egrep,fgrep} 2>/dev/null || true
fi

# Rebrand
sed -i 's/Arch Linux/Cerberix Linux/g' "${ARCHISO_PROFILE}/syslinux/"*.cfg 2>/dev/null || true
sed -i 's/Arch Linux/Cerberix Linux/g' "${ARCHISO_PROFILE}/efiboot/loader/entries/"*.conf 2>/dev/null || true
sed -i 's/Arch Linux/Cerberix Linux/g' "${ARCHISO_PROFILE}/grub/grub.cfg" 2>/dev/null || true
rm -f "${ARCHISO_PROFILE}/efiboot/loader/entries/02-archiso-speech-linux.conf" 2>/dev/null
rm -f "${ARCHISO_PROFILE}/efiboot/loader/entries/03-archiso-memtest86+x64.conf" 2>/dev/null

sed -i 's/iso_name="archlinux"/iso_name="cerberix-linux"/' "${ARCHISO_PROFILE}/profiledef.sh"
sed -i 's/iso_label="ARCH_/iso_label="CERBERIX_/' "${ARCHISO_PROFILE}/profiledef.sh"
sed -i 's/iso_publisher="Arch Linux.*/iso_publisher="Cerberus Systems"/' "${ARCHISO_PROFILE}/profiledef.sh"
sed -i 's/iso_application="Arch Linux.*/iso_application="Cerberix Linux"/' "${ARCHISO_PROFILE}/profiledef.sh"

# mkarchiso only preserves exec bits for paths listed in file_permissions;
# inject our scripts into that array before the closing paren.
sed -i '/^)$/i\
  ["/usr/local/bin/cerberix-install"]="0:0:0755"\
  ["/usr/local/bin/cerberix-alerts"]="0:0:0755"\
  ["/usr/local/bin/cerberix-connect"]="0:0:0755"\
  ["/usr/local/bin/cerberix-firstboot"]="0:0:0755"\
  ["/usr/local/bin/cerberix-fw-setup"]="0:0:0755"\
  ["/usr/local/bin/cerberix-notify"]="0:0:0755"\
  ["/usr/local/bin/cerberix-rkhunter-check"]="0:0:0755"\
  ["/usr/local/bin/cerberix-shield"]="0:0:0755"\
  ["/usr/local/bin/cerberix-update"]="0:0:0755"\
  ["/usr/local/bin/grep"]="0:0:0755"\
  ["/usr/local/bin/egrep"]="0:0:0755"\
  ["/usr/local/bin/fgrep"]="0:0:0755"' "${ARCHISO_PROFILE}/profiledef.sh"

# Live environment — boot to terminal, no LightDM
# LightDM only gets enabled on the INSTALLED system
# Show welcome message on login
cat > "${ARCHISO_PROFILE}/airootfs/etc/motd" << 'MOTDEOF'

  ============================================
   Cerberix Linux 0.1.0 (Styx) — Live
  ============================================

   To install:  sudo cerberix-install

  ============================================

MOTDEOF

# OS branding
cat > "${ARCHISO_PROFILE}/airootfs/etc/os-release" << 'OSEOF'
NAME="Cerberix Linux"
ID=cerberix
ID_LIKE=arch
VERSION="0.1.0 (Styx)"
VERSION_ID=0.1.0
PRETTY_NAME="Cerberix Linux 0.1.0 (Styx)"
HOME_URL="https://cerberix.org"
OSEOF

# Installer script
mkdir -p "${ARCHISO_PROFILE}/airootfs/usr/local/bin"
cat > "${ARCHISO_PROFILE}/airootfs/usr/local/bin/cerberix-install" << 'INSTEOF'
#!/bin/bash
set -e

BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

msg() { echo -e "${GREEN}[*]${NC} $1"; }
err() { echo -e "${RED}[X]${NC} $1"; }

clear
echo -e "${BLUE}"
echo "  ============================================"
echo "   Cerberix Linux Installer"
echo "  ============================================"
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then err "Run as root: sudo cerberix-install"; exit 1; fi

echo "Available Disks:"
lsblk -d -o NAME,SIZE,MODEL,TYPE | grep disk
echo ""
read -p "Install to disk (e.g. sda): " DISK
[[ -z "$DISK" ]] && exit 1
[[ "$DISK" != /dev/* ]] && DISK="/dev/$DISK"
[[ ! -b "$DISK" ]] && { err "Disk $DISK not found"; exit 1; }

echo ""
echo -e "${RED}THIS WILL ERASE ALL DATA ON ${DISK}${NC}"
read -p "Type 'yes' to continue: " CONFIRM
[[ "$CONFIRM" != "yes" ]] && exit 1

echo ""
read -p "Username: " USERNAME
[[ -z "$USERNAME" ]] && USERNAME="cerberix"
read -sp "Password: " USERPASS
echo ""

if [[ "$DISK" == *nvme* ]] || [[ "$DISK" == *mmcblk* ]]; then PART="${DISK}p"; else PART="${DISK}"; fi

msg "Partitioning..."
if [[ -d /sys/firmware/efi ]]; then
    BOOT_MODE="uefi"
    parted -s "$DISK" mklabel gpt
    parted -s "$DISK" mkpart ESP fat32 1MiB 513MiB
    parted -s "$DISK" set 1 esp on
    parted -s "$DISK" mkpart primary 513MiB 100%
    mkfs.fat -F32 "${PART}1"
else
    BOOT_MODE="bios"
    parted -s "$DISK" mklabel msdos
    parted -s "$DISK" mkpart primary ext4 1MiB 513MiB
    parted -s "$DISK" set 1 boot on
    parted -s "$DISK" mkpart primary ext4 513MiB 100%
    mkfs.ext4 -q -L BOOT "${PART}1"
fi

mkfs.ext4 -q -L CERBERIX "${PART}2"

msg "Mounting..."
mount "${PART}2" /mnt
mkdir -p /mnt/boot
mount "${PART}1" /mnt/boot

msg "Bootstrapping Chaotic-AUR on live ISO (required for pacstrap)..."
if ! grep -q '^\[chaotic-aur\]' /etc/pacman.conf; then
    pacman-key --init 2>/dev/null || true
    pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com 2>/dev/null
    pacman-key --lsign-key 3056513887B78AEB 2>/dev/null
    pacman -U --noconfirm \
        'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst' \
        'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst' 2>/dev/null
    cat >> /etc/pacman.conf <<PMEOF

[chaotic-aur]
Include = /etc/pacman.d/chaotic-mirrorlist
PMEOF
    pacman -Sy
fi

msg "Installing base system (this takes a while)..."
# Reuse the same package list the live ISO was built from
PKGS=$(grep -vE '^#|^$' /etc/cerberix/packages.x86_64 | tr '\n' ' ')
pacstrap -K /mnt $PKGS

msg "Installing Cerberix customizations..."
cp -r /usr/local/bin/cerberix-* /mnt/usr/local/bin/ 2>/dev/null || true
cp /usr/local/bin/grep /usr/local/bin/egrep /usr/local/bin/fgrep /mnt/usr/local/bin/ 2>/dev/null || true
chmod 755 /mnt/usr/local/bin/cerberix-* /mnt/usr/local/bin/{grep,egrep,fgrep} 2>/dev/null || true
[ -d /usr/share/cerberix ] && cp -r /usr/share/cerberix /mnt/usr/share/
[ -d /usr/share/backgrounds/cerberix ] && mkdir -p /mnt/usr/share/backgrounds && cp -r /usr/share/backgrounds/cerberix /mnt/usr/share/backgrounds/
cp -a /etc/skel/. /mnt/etc/skel/ 2>/dev/null || true
cp /etc/systemd/system/cerberix-*.service /mnt/etc/systemd/system/ 2>/dev/null || true
cp /etc/systemd/system/cerberix-*.timer /mnt/etc/systemd/system/ 2>/dev/null || true
cp /usr/share/applications/cerberix-*.desktop /mnt/usr/share/applications/ 2>/dev/null || true
[ -f /etc/rkhunter.conf.local ] && cp /etc/rkhunter.conf.local /mnt/etc/rkhunter.conf.local
# Greeter background (only; /etc/lightdm/lightdm.conf is written later in the chroot block)
mkdir -p /mnt/etc/lightdm
[ -f /etc/lightdm/lightdm-gtk-greeter.conf ] && cp /etc/lightdm/lightdm-gtk-greeter.conf /mnt/etc/lightdm/

msg "Generating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

msg "Configuring system (locale, hostname, time)..."
arch-chroot /mnt /bin/bash <<CHROOT
ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime
hwclock --systohc
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen
echo "LANG=en_US.UTF-8" > /etc/locale.conf
echo "cerberix" > /etc/hostname
cat > /etc/hosts <<HOSTSEOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   cerberix.localdomain cerberix
HOSTSEOF
CHROOT

# ---- User creation — done OUTSIDE the chroot heredoc so variable expansion is clean ----
msg "Creating groups..."
for g in wheel video audio input docker autologin; do
    arch-chroot /mnt getent group "$g" >/dev/null 2>&1 || arch-chroot /mnt groupadd -r "$g"
done

msg "Creating user ${USERNAME}..."
if ! arch-chroot /mnt useradd -m -G wheel,video,audio,input,docker,autologin -s /bin/bash "${USERNAME}"; then
    err "useradd failed for ${USERNAME} — aborting"
    exit 1
fi

msg "Setting password for ${USERNAME}..."
if ! printf '%s:%s\n' "${USERNAME}" "${USERPASS}" | arch-chroot /mnt chpasswd; then
    err "chpasswd failed for ${USERNAME} — aborting"
    exit 1
fi

msg "Setting password for root..."
if ! printf '%s:%s\n' "root" "${USERPASS}" | arch-chroot /mnt chpasswd; then
    err "chpasswd failed for root — aborting"
    exit 1
fi

# ---- Sanity check: confirm the account is usable before we continue ----
msg "Verifying user account..."
if ! arch-chroot /mnt getent passwd "${USERNAME}" >/dev/null; then
    err "CRITICAL: ${USERNAME} not in /etc/passwd"; exit 1
fi
USER_HASH=$(arch-chroot /mnt awk -F: -v u="${USERNAME}" '$1==u{print $2}' /etc/shadow)
case "$USER_HASH" in
    ''|'!'|'*'|'!!')
        err "CRITICAL: ${USERNAME} has no valid password hash in /etc/shadow (got: '$USER_HASH')"
        err "This means chpasswd failed. Aborting so you don't boot into a broken install."
        exit 1 ;;
esac
msg "User ${USERNAME} verified: valid shadow hash present"

msg "Configuring sudo, autologin, lightdm..."
arch-chroot /mnt /bin/bash <<CHROOT
echo "%wheel ALL=(ALL:ALL) ALL" > /etc/sudoers.d/wheel
chmod 440 /etc/sudoers.d/wheel

mkdir -p /etc/lightdm
cat > /etc/lightdm/lightdm.conf <<LDMEOF2
[LightDM]
logind-check-graphical=true

[Seat:*]
user-session=xfce
session-wrapper=/etc/lightdm/Xsession
greeter-session=lightdm-gtk-greeter
LDMEOF2

# GRUB
sed -i 's/GRUB_DISTRIBUTOR=.*/GRUB_DISTRIBUTOR="Cerberix"/' /etc/default/grub
if [[ "$BOOT_MODE" == "uefi" ]]; then
    grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=Cerberix
else
    grub-install --target=i386-pc ${DISK}
fi
grub-mkconfig -o /boot/grub/grub.cfg

# Enable services
systemctl enable NetworkManager
systemctl enable lightdm
systemctl enable bluetooth
systemctl enable sshd
systemctl enable docker
systemctl enable vmtoolsd 2>/dev/null || true

# Enable Cerberix timers (daily rkhunter scan, weekly update check)
systemctl enable cerberix-rkhunter.timer 2>/dev/null || true
systemctl enable cerberix-update.timer 2>/dev/null || true

# OS branding
cat > /etc/os-release <<OSEOF2
NAME="Cerberix Linux"
ID=cerberix
ID_LIKE=arch
VERSION="0.1.0 (Styx)"
VERSION_ID=0.1.0
PRETTY_NAME="Cerberix Linux 0.1.0 (Styx)"
HOME_URL="https://cerberix.org"
OSEOF2
rm -f /etc/arch-release

# SSH hardening (drop-in so upstream updates don't clobber it)
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-cerberix-hardening.conf <<'SSHEOF'
# Cerberix SSH hardening
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
SSHEOF

# AppArmor (enable service + kernel LSM order)
systemctl enable apparmor.service 2>/dev/null || true
if [ -f /etc/default/grub ]; then
    if ! grep -q 'apparmor' /etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf"/' /etc/default/grub
        grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
    fi
fi

# NetworkManager MAC address randomization
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/00-cerberix-mac-randomization.conf <<'NMEOF'
[connection-mac-randomization]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random

[device-mac-randomization]
wifi.scan-rand-mac-address=yes
NMEOF

# Chaotic-AUR (trust key + register repo on installed system)
pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com
pacman-key --lsign-key 3056513887B78AEB
if ! grep -q '^\[chaotic-aur\]' /etc/pacman.conf; then
    cat >> /etc/pacman.conf <<'CHAOTICEOF2'

[chaotic-aur]
Include = /etc/pacman.d/chaotic-mirrorlist
CHAOTICEOF2
fi
CHROOT

msg "Cleaning up..."
umount -R /mnt

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Cerberix Linux installed!${NC}"
echo -e "${GREEN} Remove ISO and reboot.${NC}"
echo -e "${GREEN} Username: ${USERNAME}${NC}"
echo -e "${GREEN} Auto-login + XFCE desktop${NC}"
echo -e "${GREEN}============================================${NC}"
INSTEOF
chmod 755 "${ARCHISO_PROFILE}/airootfs/usr/local/bin/cerberix-install"

# VMware support
mkdir -p "${ARCHISO_PROFILE}/airootfs/etc/modprobe.d"
cat > "${ARCHISO_PROFILE}/airootfs/etc/modprobe.d/vmware.conf" << 'VMEOF'
options vmwgfx enable_fbdev=1
VMEOF

# Chaotic-AUR bootstrap (host keyring + profile pacman.conf)
echo ""
echo "Setting up Chaotic-AUR..."
pacman-key --init 2>/dev/null || true
pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com
pacman-key --lsign-key 3056513887B78AEB
pacman -U --noconfirm \
    'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst' \
    'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst'

if ! grep -q '^\[chaotic-aur\]' "${ARCHISO_PROFILE}/pacman.conf"; then
    cat >> "${ARCHISO_PROFILE}/pacman.conf" <<'CHAOTICEOF'

[chaotic-aur]
Include = /etc/pacman.d/chaotic-mirrorlist
CHAOTICEOF
fi

echo ""
echo "Building ISO..."
mkarchiso -v -w "${WORK_DIR}" -o "${OUT_DIR}" "${ARCHISO_PROFILE}"

echo ""
cd "${OUT_DIR}"
for f in cerberix-linux-*.iso; do
    [ -f "$f" ] && mv "$f" "cerberix-linux-0.1.0-x86_64.iso" 2>/dev/null
done

echo "============================================"
echo " Cerberix Linux XFCE ISO built!"
ls -lh "${OUT_DIR}/"cerberix-linux-*
echo "============================================"
