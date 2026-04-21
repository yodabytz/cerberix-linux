#!/usr/bin/env bash
# shellcheck disable=SC2034
# Cerberix Linux — archiso profile definition

iso_name="cerberix-linux"
iso_label="CERBERIX_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="Cerberus Systems <https://cerberix.io>"
iso_application="Cerberix Linux Live"
iso_version="0.1.0"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux'
           'uefi.systemd-boot')
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/usr/local/bin/cerberix-install"]="0:0:755"
  ["/usr/local/bin/cerberix-firstboot"]="0:0:755"
  ["/usr/local/bin/cerberix-update"]="0:0:755"
)
