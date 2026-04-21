---
title: Day two — Shield toggles, login background, fewer false alarms
date: 2026-04-20
description: What landed in the ISO today — the Firewall button now actually configures the firewall, the login screen has a background, and the failed-units list is empty.
---

Quick round of fixes from dogfooding the install. Fresh ISO on the site
(new SHA256 published alongside the signature as always).

## The Firewall button in Cerberix Shield actually does something

Before today, clicking the Firewall button in Shield ran
`sudo -n ufw` — passwordless sudo that almost nobody has configured, so
the click failed silently. Frustrating because the indicator *looked*
like a toggle but wasn't wired to a usable privilege escalation path.

Now it works:

- Click while UFW is inactive → polkit authentication popup (the same
  one you already see for other privileged GUI actions) → a single
  escalation runs:
    - `ufw default deny incoming`
    - `ufw default allow outgoing`
    - `ufw allow ssh`
    - `ufw --force enable`
    - `systemctl enable ufw`

  Then Shield re-checks and the Firewall row flips green.

- Click while UFW is active → polkit popup → `ufw disable`.

No passwordless sudo rules required, no terminal needed. Implementation
is a new helper at `/usr/local/bin/cerberix-fw-setup` invoked via
`pkexec`, so the auth flow plays nicely with XFCE's polkit agent.

## LightDM login screen has a background

The greeter was just a flat color before — passable but not great as a
first impression. Now it loads one of the bundled Cerberix wallpapers
(`cerberix-desktop-background-moon.png` by default) via
`/etc/lightdm/lightdm-gtk-greeter.conf`.

This is a separate file from `lightdm.conf` by design: greeter
appearance settings shouldn't live in the session-manager config, and
keeping them apart means future tweaks to one don't risk breaking the
other.

Defaults in the greeter conf:

- Background: Cerberix moon wallpaper
- Theme: Adwaita-dark
- Icons: Papirus-Dark
- Font: Inter 11

Change any of these by editing `/etc/lightdm/lightdm-gtk-greeter.conf`
and logging out.

## `cerberix-update.service` no longer shows as failed

If you checked `systemctl --failed` on a fresh install you'd see
`cerberix-update.service` in red. Not actually broken — just a systemd
quirk. `pacman-contrib`'s `checkupdates` tool exits with status 2 when
there are no pending updates. That's intentional behavior from the tool
author (exit 0 = "updates found", exit 2 = "no updates"). systemd
interprets any non-zero exit as failure by default.

One-line fix — the service unit now has:

```
SuccessExitStatus=0 2
```

systemd treats both as success. The failed-units list stays empty when
there are no updates, and the timer still works for when there are.

## New default wallpaper + three new options

The default desktop wallpaper now matches the site's palette more
directly. Three additional wallpapers ship in
`/usr/share/backgrounds/cerberix/` so right-clicking the desktop →
*Desktop Settings* gives you real choices instead of one option.

## Shield VPN check: works with any WireGuard interface

Shield was hardcoded to look for `wg0`. If your NetworkManager-managed
WireGuard connection ended up named `cerberix-vpn`, `mullvad-*`, or
anything else, Shield reported "Disconnected" even when the tunnel was
up. Fixed — Shield now runs `ip -o link show type wireguard` to catch
anything the kernel tags as WireGuard, regardless of name. Toggle logic
prefers NetworkManager (`nmcli connection up/down`) and falls back to
`wg-quick` for `/etc/wireguard/*.conf` setups.

## What's still in progress

- **Tokyo Night Firefox theme as default** — want this shipped as part
  of the install, blocked on getting the theme's `.xpi` identified.
  Next build.

If something breaks on your end, mail [hello@cerberix.org](mailto:hello@cerberix.org)
— bug reports in the first couple weeks are how this gets genuinely
polished.
