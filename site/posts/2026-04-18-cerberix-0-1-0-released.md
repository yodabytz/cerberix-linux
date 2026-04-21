---
title: Cerberix Linux 0.1.0 "Styx" is here
date: 2026-04-18
description: The first public release of Cerberix Linux. Hardened Arch with a desktop that boots ready — security tooling, privacy stack, and a polished XFCE experience out of the box.
---

Cerberix Linux **0.1.0 "Styx"** is now available for download.

This is the first public release. If you've been following the build-out on this
site: thank you for your patience. If you're new: welcome to what we hope is a
more humane take on what a "security-focused Linux distribution" can look like.

## What Cerberix is

Cerberix is an **Arch-based, desktop-first** Linux distribution with the
security plumbing preconfigured on first boot. It's not a pentester's live CD,
and it's not a hardened headless server spin — it's a normal XFCE desktop where
the firewall is already on, fail2ban already has sane jails, file integrity
monitoring is already running, and your update, VPN, and privacy tooling is
installed and ready.

The underlying system is Arch. `pacman` works, the Arch Wiki applies, the AUR
is one `yay` away. The difference is the first boot, not the fork.

## What you get, out of the box

- **XFCE 4.20** with Tokyo Night Moon theming, Plank dock, and preloaded
  dotfiles so every new user inherits the same polished environment.
- **fish shell** as the default, with the Tide prompt, zoxide, fzf.fish, and
  Fisher already wired up.
- **Security stack:** nftables, fail2ban, ufw/gufw, rkhunter, lynis, apparmor,
  arch-audit, keepassxc, gnome-keyring, bleachbit.
- **Privacy & VPN:** tor, torbrowser-launcher, wireguard-tools, openvpn,
  openconnect, proxychains-ng.
- **Offensive / audit toolkit:** hydra, hashcat, nikto, radare2, sqlmap.
- **Modern CLI:** starship, tmux, eza, bat, fd, fzf, ripgrep, lazygit, neovim,
  plocate.
- **Cerberix-native tools:**
    - **Cerberix Shield** — system tray indicator for security posture
    - **Cerberix Connect** — firewall appliance dashboard
    - **Cerberix Update** and **rkhunter** scans as systemd timers

## Installing

Boot the ISO, log in, and run one command:

```
sudo cerberix-install
```

The installer is a single Bash script — open it before you run it if you want
to see exactly what it will do. UEFI and BIOS are both supported. Install time
is about six minutes on modern hardware.

New users created on the installed system automatically pick up the themed
dotfiles through `/etc/skel/`, so adding someone via `useradd` gives them the
same experience as the install account.

## Download and verify

Head to the [download section](/#download) for the ISO, SHA256 checksum, and
detached GPG signature.

```
curl https://cerberix.org/gpg.asc | gpg --import
gpg --verify cerberix-linux-0.1.0-x86_64.iso.sig \
            cerberix-linux-0.1.0-x86_64.iso
sha256sum -c cerberix-linux-0.1.0-x86_64.iso.sha256
```

## Known caveats

0.1.0 is a young release. A few things to be aware of:

- **English locale only** at install — other locales work after setup but
  aren't presented in the installer yet.
- **Desktop only.** There's no server variant yet.
- **`aide` and `hexchat`** are AUR-only packages and don't ship on the ISO;
  add them with `yay -S aide hexchat` after install.
- **Rolling release.** Expect frequent small updates — `pacman -Syu` is the
  same as on Arch, and the same caveats apply.

## What's next

Subscribe to the [RSS feed](/feed.xml) or check back here for updates. The
short-term roadmap:

- DKIM-signed mail for `cerberix.org`
- Locale selection in the installer
- A server / headless variant
- A signed package repository for `cerberix-shield`, `cerberix-connect`, and
  friends so they upgrade with `pacman -Syu` rather than requiring a full
  reinstall

If you find something broken or weird, mail
[hello@cerberix.org](mailto:hello@cerberix.org). Bug reports for a young
distribution are a gift — please be generous with them.

Boot it, break it, tell us about it.
