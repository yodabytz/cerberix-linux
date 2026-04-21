---
title: Day one testing notes — what we caught and shipped
date: 2026-04-19
description: Real install-test cycles from launch day. What broke, why, and what's in the latest ISO.
---

Between the 0.1.0 "Styx" tag yesterday and the ISO that's on the site right
now, the installer was rebuilt and re-signed **seven times**. Every rebuild
came from either an install-it-yourself regression or a Cerberix Shield
check that wasn't matching reality. Documenting here because the iteration
is the product — if you download the ISO today, here's what you're getting
that the first upload didn't have.

## Install-flow fixes

**Password handling rewritten.** The first installer piped `${USERPASS}`
through an unquoted heredoc inside `arch-chroot`. Any password with `$`,
`` ` ``, `\`, or a space got eaten by shell expansion before reaching
`chpasswd`, and the user ended up with a stored hash that didn't match what
they'd typed. Now the installer calls `arch-chroot /mnt chpasswd` directly
with the password on stdin — zero shell quoting involved. Same idiom the
Arch install scripts themselves use.

**Post-install hash verification.** After creating the user, the installer
now reads `/etc/shadow` and confirms there's a valid hash on the account.
If the hash is empty, `!`, or `*`, the install *refuses to finish* and
prints exactly what's wrong. No more "install succeeds, login fails."

**Explicit group creation.** pacstrap hooks can race — if the `docker`
post-install hook hadn't completed by the time `useradd -G ...,docker`
ran, the whole user creation silently failed and the script exited
partway. Now groups are created explicitly first, so useradd has what it
needs no matter when hooks land.

**Executable bits preserved.** `mkarchiso` only keeps exec bits on files
listed in `profiledef.sh`'s `file_permissions` array. `cerberix-install`,
Shield, Connect, and the grep/egrep/fgrep shims are all explicitly listed
now. The first ISO shipped with 644 on all of them, which meant you had
to `chmod +x` just to run the installer. That's obviously gone.

**Chaotic-AUR bootstrap moved into the installer.** The live ISO builds
with Chaotic-AUR in the builder's pacman.conf, but the *runtime* pacman
config inside the ISO didn't have it. `pacstrap` choked on Chaotic-only
packages (ghostty, nikto, torbrowser-launcher). The installer now
bootstraps Chaotic-AUR on the live ISO just before calling pacstrap, so
the target picks it up cleanly.

## LightDM / login fixes

**Login shell is bash, not fish.** I'd wanted the installed system to
match the experience of an existing Cerberix VM, so I set `useradd -s
/usr/bin/fish`. Bad call. When fish is a login shell, any init-time
hiccup (Fisher race, plugin sourcing, missing terminfo) makes the shell
exit non-zero, and LightDM treats that as "session failed" → bounce to
greeter. Rolling it back to `/bin/bash` for login, keeping fish for
interactive terminals via `/etc/skel/.config/fish/`. Users who want
fish as login shell can `chsh -s /usr/bin/fish` after they've verified
their session boots.

**Autologin is off by default.** The installer was configuring LightDM
autologin, which depends on a PAM stack, group membership, a matching
`autologin-session` name, and several other moving parts. Removed in
favor of the standard greeter flow — matches the config running on the
build maintainer's own daily-driver VM. Zero login loops since the
change.

## Desktop fixes

**Backgrounds actually ship now.** `/usr/share/backgrounds/cerberix/`
was in the live ISO but the installer didn't copy it to the target, so
new installs booted into a black desktop (the skel's
`xfce4-desktop.xml` pointed at a non-existent wallpaper path). The
seven included wallpapers are now bundled and present on the installed
system — new users boot into the Cerberix wallpaper by default.

**Terminal-launching apps actually open in a terminal.** Skel shipped
`TerminalEmulator=custom-TerminalEmulator` as a placeholder, which made
clicking `htop` or `btop` from the menu throw an XFCE error dialog.
Fixed to `TerminalEmulator=ghostty` with a matching helper file so
`exo-open --launch TerminalEmulator <cmd>` resolves correctly.

## Cerberix Shield accuracy

Shield checks *look* like they should work by inspection, but running as
a non-root desktop user, half of them quietly returned "Unknown." Each
check got rewritten to read from world-readable sources, not privileged
commands:

- **Firewall:** was `sudo -n ufw status` → fails without passwordless
  sudo. Now `systemctl is-active ufw` (no privilege needed) with
  `/etc/ufw/ufw.conf` fallback.
- **VPN:** was hard-coded to `wg0`. Now matches any WireGuard-type
  interface via `ip -o link show type wireguard` — works for `wg0`,
  `cerberix-vpn`, `mullvad-*`, anything.
- **VPN toggle:** was `sudo wg-quick`. Now prefers NetworkManager-
  managed connections via `nmcli` (no sudo), falls back to `wg-quick`
  for `/etc/wireguard/*.conf` setups.

## AppArmor actually loads

The `apparmor` package was installed, but the kernel needs a specific
LSM order in the bootloader to activate it. The installer now appends
`lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to
`GRUB_CMDLINE_LINUX_DEFAULT` and enables `apparmor.service`. After the
first reboot post-install, `/sys/module/apparmor/parameters/enabled`
reads `Y` and Shield goes green on that check.

## SSH hardening drop-in

Old installer was actively making sshd *less* secure — enabling
`PermitRootLogin` and `PasswordAuthentication`. Replaced with a proper
drop-in at `/etc/ssh/sshd_config.d/50-cerberix-hardening.conf`:

```
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
```

Shield's SSH check greps for `MaxAuthTries` in the drop-in directory, so
this satisfies it while keeping the config in a pacman-safe location.

## NetworkManager MAC randomization

Added `/etc/NetworkManager/conf.d/00-cerberix-mac-randomization.conf`
with `wifi.cloned-mac-address=random` and
`ethernet.cloned-mac-address=random`. Every new connection gets a
fresh MAC. Shield's MAC check greps that conf.d directory.

## What's next

The ISO you'd download right now (SHA256 published on the
[download section](/#download) next to the signature) has all of the
above. Rkhunter and AIDE baselines get populated on first overnight run
via the existing systemd timer.

If you install it and hit something that's still broken — mail
[hello@cerberix.org](mailto:hello@cerberix.org). Testing notes for the
first real user-reported issues will show up here as its own post.

A decent distro takes iteration. Thanks for running it with us.
