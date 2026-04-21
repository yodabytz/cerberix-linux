---
title: What's next — pacman repo, source transparency, and the next wave of work
date: 2026-04-21
description: A plain-English roadmap for Cerberix after launch week. The biggest item is a dedicated pacman repository so updates ship without reinstalls.
---

Three days in, the first wave of launch-week feedback is landing, the
ISO is mirrored globally, and it's time to outline what's coming next.
This isn't a wishlist — it's the concrete work queue.

## A dedicated pacman repository

The single most important piece of infrastructure Cerberix doesn't
have yet is its own **signed pacman repository**. Right now, if a bug
in Cerberix Shield or a tuning improvement in the installer needs to
reach users, the only distribution mechanism is cutting a new ISO.
That's slow, wasteful, and out of line with what users rightly expect
from an Arch-based system.

The plan:

```
repo.cerberix.org/x86_64/
  cerberix-shield-<version>.pkg.tar.zst
  cerberix-connect-<version>.pkg.tar.zst
  cerberix-install-<version>.pkg.tar.zst
  cerberix-fw-setup-<version>.pkg.tar.zst
  cerberix-firstboot-<version>.pkg.tar.zst
  cerberix-backgrounds-<version>.pkg.tar.zst
  cerberix-branding-<version>.pkg.tar.zst
  cerberix.db.tar.gz
  ... and detached .sig files for each
```

The repo will be hosted through SourceForge's global mirror network
(the same infrastructure that serves the ISO) and signed with the
same GPG key published at [cerberix.org/gpg.asc](/gpg.asc). Every
Cerberix install will ship with a `[cerberix]` section already in
`/etc/pacman.conf`, so `pacman -Syu` Just Works from day one.

Practical result: a Shield fix no longer requires a reinstall. It
becomes a 30-second `pacman -Syu` for everyone.

Beyond the Cerberix-branded tooling, the repo will also carry a
small set of in-house utilities (netscope, swapwatch, and others
currently living only in `/usr/local/bin/` on the maintainer's own
systems). Shipping them as proper packages makes them installable,
upgradeable, and removable like any other Arch software.

## Source transparency on GitHub

Cerberix is already reproducible — the build is a short Bash script,
the rootfs is a simple overlay, and the ISO is signed. What's
missing is a public, read-only source tree so anyone curious can
inspect the code without a download.

A GitHub repo is coming, strictly as an inspection mirror. Rules:

- Source code only. No ISOs, no signatures, no release artifacts.
- Downloads stay on cerberix.org and the SourceForge mirror — the
  GitHub repo's README will point users there, not to GitHub Releases.
- No GitHub Actions that create releases. Tags will be pushed only
  as lightweight references, never with attached binaries.

This split — transparent source on GitHub, artifacts on infrastructure
we own — keeps Cerberix's distribution independent of any single
platform's policy changes.

## Smaller items in the queue

- **Firefox default theme** — shipping the Tokyo Night theme as a
  default via Firefox's distribution policies, so new installs open
  the browser already themed.
- **DKIM signing for `cerberix.org` mail** — announcement and update
  emails from the domain currently pass SPF but don't carry DKIM
  signatures. This is a configuration-only change on the mail server
  and will land before the next release.
- **Installer locale selection** — English-only at install time today.
  The installer will get a locale picker in 0.1.1.
- **A server / headless variant** — Cerberix is explicitly desktop-
  first, but a minimal server spin (no XFCE, keeps the security
  stack) is a natural sibling and will appear once the desktop build
  is stable enough to share a base.

## What's intentionally not on the list

- A paid tier, donation drive, or sponsorship campaign. Not on launch
  week. Infrastructure comes first; asking people to support the
  project comes later, if at all, and never before the work has
  demonstrated sustained value.
- A move to any other desktop environment. XFCE is the choice, not a
  placeholder.
- A Wayland-by-default switch. When XFCE's Wayland story stabilizes
  upstream, so will ours. Not before.

---

If any of this is broken or misaligned with what you want from a
security-focused distribution, tell us — [bugs@cerberix.org](mailto:bugs@cerberix.org)
for reproducible issues, [hello@cerberix.org](mailto:hello@cerberix.org)
for everything else.

The next release-notes post will land when the first point-release
ships. Subscribe via [RSS](/feed.xml) if you want to be notified.
