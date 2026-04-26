---
title: krellix remote-mode fixes, and the docker0 puzzle
date: 2026-04-26
description: A round of fixes for krellix in --host mode (idle disconnect, stale-data spikes, CPU/Net panels stuck on the placeholder), plus a deep dive into why docker0 looks dead even when containers are busy — and the plan to fix it properly.
---

Spent today on [krellix](https://github.com/yodabytz/krellix) — the Qt 6 system
monitor I've been rebuilding in the spirit of GKrellM. A handful of
real bugs surfaced once I started actually using `--host` mode in
anger to watch the VPS from cerberix, plus a more interesting puzzle
around how Linux bridges count traffic that's worth writing up.

## What landed today

One commit, seven files, all addressing things that were quietly
broken in `--host` mode.

### The 5-minute disconnect loop

The daemon (`krellixd`) was kicking every healthy client every
5 minutes. The protocol is one-way — server pushes JSON samples on a
timer, client never replies — so the server's idle timer (which only
reset on *client → server* reads) always fired, and the connection
got force-closed with `idle timeout`. The client reconnected, the
cycle repeated.

Fix: reset the idle timer on the socket's `bytesWritten` signal
instead. When the kernel actually flushes a sample to the client,
that's proof of life. A *hung* client whose kernel buffer fills up
still doesn't fire `bytesWritten`, so we still kick those — which is
the whole point of having an idle timer.

### "no /proc/stat" forever

`CpuMonitor::createWidget()` ran once at construction and called
`CpuStat::read()` to figure out how many cores to lay out. In
`--host` mode the first remote sample lands a tick *after*
construction, so the read came back empty, and the monitor
permanently locked itself into the `(no /proc/stat)` placeholder. The
real CPU panels never got built.

Fix: defer panel construction until the first non-empty sample
arrives. The placeholder now says `(waiting for data...)` and gets
ripped out and replaced with the real per-core panels in `tick()`
once samples start landing. NetMonitor already had this pattern;
CpuMonitor now matches.

### Stale-data spikes after a reconnect

`RemoteSource` cached the last sample so that reads through the
sysdep override returned something synchronously. But on disconnect
it never cleared the cache. After a multi-minute outage, the very
first new sample would diff against pre-disconnect counters and the
NetMonitor would fabricate a giant rate spike (5 minutes of
accumulated bytes / 1 second).

Fix: clear cached samples on disconnect. The chart shows zero for one
tick instead of a fake spike. Uptime falls back to `-1` so its decal
renders `?` rather than the misleading `00:00`.

### Wedged on initial connect failure

`onSocketError` only logged. Subsequent reconnect was scheduled from
`onSocketDisconnected` — which never fires if you never made it to
`ConnectedState` in the first place. So a one-time outage at startup
left the client wedged with no retry.

Fix: schedule the reconnect from `onSocketError` too, when the socket
is in `UnconnectedState`. Backoff is unchanged.

### Plus a couple of smaller cleanups

- `RemoteSource::onReadyRead` bails out the moment `parseLine` aborts
  the socket — we were touching post-abort state in the loop tail.
- NetMonitor's `(waiting for data...)` placeholder now actually gets
  removed when the first interface lazy-arrives, instead of sitting
  above the live data forever.

## The docker0 puzzle

This one was meant to be the third bullet of an unrelated bug list
and turned into the most interesting thing of the day.

The original report: the box running krellixd has Docker, krellix
shows the `docker0` panel fine, but it never shows any *traffic*.
Just zeros, forever.

First instinct: there's a parser bug in `NetStat`. There wasn't.
`docker0` parses fine; `cat /proc/net/dev | grep docker0` gives the
same numbers krellixd is sending. The bytes value just… doesn't
move.

```
$ grep docker0 /proc/net/dev; sleep 5; grep docker0 /proc/net/dev
docker0:    106069651    1044044   ...   58775111737    2155297   ...
docker0:    106069651    1044044   ...   58775111737    2155297   ...
```

Frozen. 58 GB on TX from way back, but no current activity counted —
even though containers were definitely doing things.

### Why a Linux bridge counter goes silent

The `docker0` interface only counts traffic that crosses *its own*
bridge boundary into the host's IP stack. Pure forwarding *between*
member ports (or — much more importantly — traffic that gets
intercepted by the iptables `FORWARD` chain because Docker NAT'd it)
does not increment the bridge interface's RX/TX. With Docker's
default `MASQUERADE` rules, that's basically *all* container traffic.

You can see the same effect on user-defined Compose networks:
`br-cad87d883e4a`, `br-f6739fab5f74`, etc. all show large historical
counters that aren't moving, while the `veth*` member ports of those
bridges *are* moving.

### First fix (shipped today)

In `NetStat::read()`, after parsing `/proc/net/dev`, check
`/sys/class/net/<iface>/brif/` for each interface. If the directory
exists, the interface is a Linux bridge — replace its counters with
the sum of its member ports' counters.

Because this lives in shared sysdep code, the daemon does the
aggregation server-side, and the client just renders whatever the
daemon sends. No client-side awareness needed.

Verified live on the VPS:

```
/proc/net/dev   docker0:        106069651 / 58775111737   (frozen)
/proc/net/dev   veth2d339ec:     21849675 /     1949031   (the only member)
daemon JSON     docker0: rx=21849675 tx=1949031           ✓
```

`docker0` now reports its single attached container's actual
throughput.

### …but it's not the whole story

Then I went to look at *all* the bridges on this host, and the real
picture became clear:

| bridge | docker network | members | active? |
|---|---|---|---|
| `docker0` | `bridge` (default) | 1 (portainer) | idle |
| `br-f6739fab5f74` | **`internal`** | matrix-monolith, postgres | ✓ pushing ~100 KB/s |
| `br-cad87d883e4a` | `matrix_internal` | 3 containers | quiet |
| `br-82fd7b48ecfe` | `wwwcelthauscom_default` | 2 containers | quiet |
| `br-fc8be0e11cb2` | `testingapparixapp_default` | 2 containers | quiet |
| `br-8a9594c0792f` | `apparixapp_default` | 1 container | quiet |

`docker0` is genuinely idle on this host — its only attached
container is portainer, which mostly sits there. Everything actually
*doing* something is on a Compose-created user-defined bridge with
an unintelligible `br-<hash>` name.

So the user-visible problem isn't "docker0 doesn't show data" — it's
"the bridge that *does* have my data has a name nobody can read, and
isn't enabled by default."

### The plan

Three phases, smallest-and-most-valuable first.

**Phase 1 — Friendly bridge names.** Resolve `br-<hash>` to its
docker network name (`internal`, `matrix_internal`, etc.) by reading
`/var/run/docker.sock` and adding an optional `alias` field to the
daemon's net-sample JSON. Client renders the alias when present,
falls back to the raw name. Cache the lookup for ~30 s.

**Phase 2 — A "Docker total" pseudo-interface.** A synthetic entry
that aggregates every docker-managed bridge into one number, so a
user can answer "what is Docker doing right now?" without enabling
each bridge individually. Default-enabled; individual bridges stay
default-disabled.

**Phase 3 — Cleanup.** Drop `docker` and `br-` from the
"virtual prefix" filter in `isMainInterface()` once the synthetic
entry exists, so the synthetic shows up by default while the noisy
individual bridges don't.

Phase 1 alone is probably 80% of the value with 20% of the risk —
the *numbers* are already correct after this morning's aggregation
patch; the bridges just need to be legible. Phase 2 needs a bit more
thought about how the synthetic interacts with NetMonitor's lazy-add
path and how settings persist for an entry that doesn't exist in
`/proc/net/dev`.

Starting on Phase 1 now. The daemon needs read access to
`docker.sock` (gid `docker`), so the systemd unit gets a
`SupplementaryGroups=docker` line, gated behind a config flag so
hosts that don't run Docker don't pull in any extra perms.

— yodabytz
