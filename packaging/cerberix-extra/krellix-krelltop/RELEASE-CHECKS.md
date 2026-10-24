# KrellTop release checks

KrellTop 0.1.2-2 compiled an inline RemoteSource::topProcesses() accessor
against a locally patched header. Krellix 0.1.2-25 did not contain that field,
so enabling remote monitoring dereferenced unrelated memory and crashed.

The replacement uses exported RemoteSource methods only to obtain connection
state/address, then fetches process rows over the existing JSON-lines protocol.
It uses one short-lived additional connection per five-second refresh, with a
four-second timeout and a one-MiB response limit. The server needs one available
client slot beyond the normal monitor connection. Unsupported servers show an
unavailable message; disconnected remote monitors never show local processes.

Do not restore add-remote-top-processes.patch to this plugin's build. Patching a
host header while shipping only the plugin does not patch the installed host.

Before publishing either a Krellix host update or a KrellTop update:

1. Build the plugin from this PKGBUILD and verified source checksums.
2. Install both candidate packages in a test VM (not just the plugin alone).
3. Run `python3 test-installed-host.py /usr/lib/krellix/plugins/libkrelltop.so`.
   This exercises real installed-host loading, valid and missing process data,
   connection loss and reconnects. A nonzero result blocks release.
4. Run two real remote instances with KrellTop enabled and confirm process rows
   update without new coredumps. Check local monitoring as well.

The test deliberately does not use a user-plugin override: the current loader
loads both the user and system copies, which can exercise the obsolete plugin
instead of the candidate and give misleading results.
