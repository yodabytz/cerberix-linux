---
title: Known issue — installer hang on low-entropy VMs (fix in the next build)
date: 2026-04-22
description: A user report surfaced a real bug — pacman-key init can hang for hours on headless VMs with little entropy. Fix is prepared; the next ISO ships haveged to prevent it.
---

A user writing in from the DistroWatch listing reported a clean-install
failure: their session hung for two hours on the messages
*"Generating Pacman Master Key / Updating Trust Database,"* with no
further progress. Thanks to that report, we found the root cause
quickly and wanted to be transparent about the fix.

## What's happening

The installer calls `pacman-key --init` to set up the keyring used to
verify downloaded packages. That command generates a fresh GPG keyring
on the fly, which depends on the kernel's entropy pool. On a physical
machine with a keyboard, mouse, and active network, the pool fills in
seconds. On a **headless VM** — especially a cold boot with minimal
background activity — entropy accumulates painfully slowly, and
`pacman-key --init` can sit there for hours waiting on randomness.

Arch's own install media works around this by bundling the
[`haveged`](https://wiki.archlinux.org/title/Haveged) daemon, which
deliberately accelerates entropy generation. The 0.1.0 ISO does not
ship `haveged` — an oversight on our end. That's the bug.

## The fix (staged, not yet deployed)

The next ISO will:

- Ship `haveged` as part of the default package set
- Auto-start it on the live-ISO boot (via a systemd symlink in
  `/etc/systemd/system/sysinit.target.wants/haveged.service`)
- Defensively `systemctl start haveged` inside the installer, right
  before `pacman-key --init`, so it's running even if anyone disables
  the service
- Enable `haveged` permanently on the installed system

Four layers of defense for a problem that should never have reached
a user.

## Workaround for anyone stuck on the current 0.1.0 ISO

If you're mid-install and the installer is stalled at the
pacman-key step, **don't kill it**. Instead open a second virtual
terminal (`Ctrl+Alt+F2`) and run:

```
find / >/dev/null 2>&1
```

That generates enough filesystem activity to push the kernel's
entropy pool past the threshold, and `pacman-key --init` on the
original terminal will usually finish within a minute of kicking this
off. Let the installer continue normally after that. Not pretty, but
it works.

## When the new ISO ships

The rebuilt ISO with this fix is already built and verified — it will
drop on cerberix.org and the SourceForge mirror shortly. The new
SHA256 and detached signature will be published alongside it as
always. Subscribe to the [RSS feed](/feed.xml) or watch
[@CerberixLinux](https://x.com/CerberixLinux) to get the notification
the moment it's live.

## Thank-you

Bug reports with enough detail to reproduce — like this one — are the
single most useful thing we receive. If you hit something rough, write
to [bugs@cerberix.org](mailto:bugs@cerberix.org). We read every
message.
