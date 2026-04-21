# Cerberix Linux

[![Download Cerberix Linux](https://img.shields.io/sourceforge/dt/cerberix-linux.svg)](https://sourceforge.net/projects/cerberix-linux/files/latest/download)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A security-focused, desktop-ready Arch Linux derivative.

**Homepage:** [cerberix.org](https://cerberix.org)

---

## Downloads

> **Downloads are not on GitHub Releases.**
> The ISO, checksum, and detached signature are hosted on our own
> infrastructure and mirrored through SourceForge's global network.

- **ISO download:** [sourceforge.net/projects/cerberix-linux/files/](https://sourceforge.net/projects/cerberix-linux/files/)
- **Signing key:** [cerberix.org/gpg.asc](https://cerberix.org/gpg.asc)

### Verify

```bash
curl https://cerberix.org/gpg.asc | gpg --import
gpg --verify cerberix-linux-0.1.0-x86_64.iso.sig \
            cerberix-linux-0.1.0-x86_64.iso
sha256sum -c cerberix-linux-0.1.0-x86_64.iso.sha256
```

---

## What's in Cerberix

- **Base:** Arch Linux (rolling), with `linux` and `linux-hardened` kernels
- **Desktop:** XFCE 4.20, Tokyo Night Moon theming, Plank dock, preloaded dotfiles via `/etc/skel/`
- **Shell:** fish default, with Tide prompt, zoxide, fzf.fish, Fisher
- **Security stack:** nftables, ufw, fail2ban, AppArmor, rkhunter, lynis, arch-audit, keepassxc, gnome-keyring, bleachbit
- **Privacy / VPN:** tor, torbrowser-launcher, wireguard-tools, openvpn, openconnect, proxychains-ng
- **Offensive / audit toolkit:** hydra, hashcat, nikto, radare2, sqlmap
- **Modern CLI:** starship, tmux, eza, bat, fd, fzf, ripgrep, lazygit, neovim, plocate
- **Cerberix-native tools:**
  - **Cerberix Shield** — system tray security-status indicator
  - **Cerberix Connect** — optional firewall-appliance dashboard client
  - **Cerberix Update** / **Cerberix rkhunter** — systemd timers for unattended scans

---

## Install

Boot the ISO, log in, and run:

```
sudo cerberix-install
```

The installer is a single Bash script. UEFI and BIOS both supported.
About six minutes on modern hardware.

---

## Repository contents

This repo contains **source only** — no release artifacts.

| Path | What's there |
|---|---|
| `distro/` | ISO build scripts (`build-iso.sh`, `build.sh`, `Dockerfile.iso`, `packages.x86_64`) |
| `rootfs/` | Overlay shipped into the ISO's airootfs + installed system (systemd units, `/etc/skel/`, `cerberix-*` scripts) |
| `installer/` | Helper scripts used during install |
| `site/` | Source for [cerberix.org](https://cerberix.org) — Markdown blog posts, HTML, CSS, static-site generator |
| `ai/` | In-house threat analyzer (Suricata signature correlation used by the firewall appliance) |
| `web/` | Flask app backing the Connect dashboard |
| `config/` | Default configurations (dnsmasq, nftables, fail2ban, suricata, etc.) |
| `servers/` | Optional supporting services |
| `scripts/` | One-off utilities |

---

## Building

Requires Docker.

```
git clone https://github.com/yodabytz/cerberix-linux.git
cd cerberix-linux
make iso
```

Output lands in `output/cerberix-linux-<date>-x86_64.iso`. The build
runs `archiso` inside a throwaway Arch container — host OS irrelevant.

Publishing the website:

```
make site      # regenerate blog + RSS from site/posts/
make publish   # rsync to /var/www/cerberix.org/
```

---

## Community & support

- **Matrix space:** [#cerberix:matrix.quantumbytz.com](https://matrix.to/#/#cerberix:matrix.quantumbytz.com)
- **Bug reports:** [bugs@cerberix.org](mailto:bugs@cerberix.org)
- **General contact:** [hello@cerberix.org](mailto:hello@cerberix.org)
- **Blog & release notes:** [cerberix.org/blog/](https://cerberix.org/blog/)
- **RSS:** [cerberix.org/feed.xml](https://cerberix.org/feed.xml)

---

## License

[MIT](LICENSE) for the Cerberix-authored code (installer, Shield, Connect,
build system, site). Every bundled third-party package retains its own
upstream license.

---

## A note on GitHub

This repository is deliberately source-only. Cerberix ISOs are never
attached to GitHub Releases — they live on [cerberix.org](https://cerberix.org)
and [SourceForge](https://sourceforge.net/projects/cerberix-linux/files/).
If you're looking for a downloadable ISO, that's where to get it.
