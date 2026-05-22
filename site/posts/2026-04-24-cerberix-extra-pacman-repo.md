---
title: A pacman repo for the Cerberix personal toolbox
date: 2026-04-24
description: cerberix-extra is live — a signed pacman repo with netscope, swapwatch, modsentry, fuzzytail, and snitch. Here's how to add it and what's actually in there.
---

Shipped something I've wanted for a while: a proper pacman repository
for the personal tools that used to get copy-pasted into every
Cerberix install.

The repo is called **`cerberix-extra`**. It's a sibling to the (still
empty) `cerberix` repo that'll eventually hold the distro's own
packages once Shield, Connect and the installer get proper
PKGBUILDs. Everything is GPG-signed with the same key that signs the
ISOs.

## What's in it

Five tools, all my own, all things I actually use:

- **[netscope](https://github.com/yodabytz/netscope)** &mdash; a
  network-and-process monitor TUI. Think htop crossed with netstat,
  with theming and 58 distro logos for the sysinfo page.
- **[swapwatch](https://github.com/yodabytz/swapwatch)** &mdash;
  smart swap monitor that actually identifies the real culprit
  process before blindly restarting monitored services.
  Tokyo Night theme out of the box.
- **[modsentry](https://github.com/yodabytz/modsentry)** &mdash; a
  real-time ModSecurity log monitor that lets you block abusive IPs
  via iptables right from the terminal, with an audit trail.
- **[fuzzytail](https://github.com/yodabytz/fuzzytail)** &mdash;
  `tail` replacement in Rust with split-pane monitoring, syntax
  highlighting, and drop-in compatibility. Binary is called `ft`.
- **[snitch](https://github.com/yodabytz/snitch)** &mdash; Fail2Ban
  companion that emails netblock admins when their space is the
  source of repeated abuse.

Versions pinned, tagged upstream, signed, and verified against a
clean Arch container end-to-end before anything was promoted.

## How to add the repo

One-time trust bootstrap:

```
sudo pacman-key --init
curl -s https://cerberix.org/gpg.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key 49840314FFF3DFE2D6E75439577040DEDD8E521E
```

Then append this to `/etc/pacman.conf`:

```
[cerberix-extra]
SigLevel = Required DatabaseOptional
Server = https://repo.cerberix.org/$arch/
Server = https://downloads.sourceforge.net/project/cerberix-linux/cerberix/cerberix-extra/$arch/
```

Then:

```
sudo pacman -Sy
sudo pacman -S netscope swapwatch modsentry fuzzytail snitch
```

The first `Server` line (cerberix.org) is the primary. SF is a
secondary mirror &mdash; I tried to make SF primary first and their
CDN was inconsistent serving `.db` and `.sig` pairs, which pacman
reasonably refuses. Lesson there: for pacman repos, own the bytes.

## One-time wrinkle if you're already on 0.1.x

The 0.1.0 and 0.1.1 ISOs installed these tools as manually-copied
files, not pacman-tracked packages. That means when you `pacman -S`
one for the first time, pacman will refuse with "file exists in
filesystem" &mdash; it won't overwrite files it didn't install. The
one-line migration fix:

```
sudo pacman -S --overwrite '*' netscope swapwatch modsentry fuzzytail snitch
```

(the single quotes around `*` matter &mdash; without them your shell
expands it before pacman sees it). That single command takes
ownership of the existing files and migrates them into pacman's
tracking. After that, normal `pacman -Syu` updates work.

For 0.2.0 (Acheron, coming up) I'll rip the manual `cp` lines out of
the installer and have the ISO install these through the repo
directly, so nobody hits this again.

## Why not just AUR?

AUR would have been the lazy answer but it puts the trust decision on
every user individually and doesn't help me keep the build inside the
distro's signing chain. Having these in a distro-signed repo means
anyone on Cerberix gets the same cryptographic trust story they get
for ISO downloads. That's the whole point.

&mdash; yodabytz
