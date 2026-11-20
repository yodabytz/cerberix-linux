# Krellix Windows Plugin Priority

Agreed order: 2026-11-14. This is the newly agreed ranking, not a recovered
copy of the earlier conversation's list.

1. KrellTop - CPU/memory process monitoring. COMPLETE: 0.1.4-windows.2.
2. KrellHealth - overall system health. COMPLETE: 0.1.1-windows.2.
3. KrellWiFi - wireless monitoring and analysis. RELEASED: 0.1.3-windows.1 (physical-radio validation pending).
4. KrellBT / KrellBluetooth - Bluetooth devices and batteries. RELEASED: 0.1.2-windows.1 (live device/battery validation pending).
5. KrellPkg - available package updates. RELEASED: 0.1.2-windows.1.
6. KrellStack - container monitoring. RELEASED: 0.1.1-windows.3.
7. KrellMail - POP3/IMAP mail counts. RELEASED: 0.1.0-windows.1 (real account authentication not tested).
8. Krelldacious - Audacious playback and volume controls. RELEASED: 0.1.0-windows.1.
9. KrellStock - stock and cryptocurrency quotes. RELEASED: 0.1.2-windows.2.
10. KrellWeather - weather conditions.
11. KrellWire - RSS headlines.
12. KrellSpectrum - audio spectrum visualization.
13. KrellKam - webcam/image display.
14. KrellMoon - moon phase.

## Requirements For Every Plugin

- Preserve existing Linux and macOS code and behavior.
- Add Windows-specific support separately.
- Local Windows instances use Windows data sources.
- Remote instances use only the selected server's data. Missing data or a
  disconnected server must never fall back to local Windows information.
- Preserve independent per-instance settings, themes, and window positions.
- KrellHealth must retain its heart icon when checks are clear. Unknown or
  missing data must not show the healthy heart.
- Test the actual packaged host/plugin combination on the Windows VM.
- Never install or update the Cerberix Linux VM without explicit permission.
- Complete releases through GitHub, signed local repository artifacts, and
  signed Cloudflare artifacts. Publish packages before repository metadata.
- Never downgrade or overwrite an already published versioned artifact.

## KrellStock Windows Release - 2026-11-20

- Plugin 0.1.2-windows.2, source `39071d7`, tag `krellstock-v0.1.2-windows.2`.
  The Windows plugin fetches Yahoo Finance quotes without an API key.
  Existing Linux and macOS plugin packages were not changed.
- Packaged Windows preview.5 and the existing VM host both received live
  equity and crypto quotes. Verified symbol saving, ticker display, remote
  isolation, and install of the exact tested DLL without replacing the host.
- Signed ZIP, source, and repository metadata verified on the local and
  Cloudflare Windows repositories. Next: KrellWeather.

## Windows Font Rendering Mitigation - 2026-11-20

- Host 0.1.2-windows-preview.5, source `83f95fe`. The Quantumbytz
  preview.3 minidump places the `RtlFreeHeap` access violation in
  DirectWrite glyph measurement called from Qt text shaping.
- Qt supports a FreeType Windows font backend. The preview defaults to it
  for Krellix only, preserving saved theme settings, explicit Qt platform
  arguments, and the parent environment for child processes. Qt and C++
  runtime files are unchanged. The original heap corruption is unconfirmed.
- Four targeted Windows tests passed. The extracted ZIP selected FreeType
  in local and remote windows, loaded existing plugins, reconnected to the
  loopback fixture, and received live Quantumbytz telemetry for 45 seconds.
  All test windows shut down cleanly; no installed instances were updated.
- GitHub tag and signed local and Cloudflare packages and metadata verified.
  Preview.5 matching host symbols are retained privately for future dumps.

## Windows Reliability Preview - 2026-11-20

- Host 0.1.2-windows-preview.4, source `33f06a0`, tagged on GitHub and
  published with verified signatures and checksums to the local and Cloudflare
  Windows repositories. No installed VM instances or profiles were changed.
- Disabled monitors now stop work before being removed. Windows teardown
  stops sensor-helper and socket callbacks before destroying their state.
  These are verified lifecycle fixes, not a confirmed cause of the overnight
  heap errors in the local and Quantumbytz instances.
- Four targeted Windows tests and the extracted ZIP desktop test passed:
  panel retirement, local plugin UI, loopback reconnect, and clean shutdown.
  The ZIP retains the previous Qt and C++ runtime files.
- The ZIP includes `crash-report.ps1`. It read the original error events
  without including settings or command lines. The VM's existing local dump
  override was left intact. Matching preview.4 host symbols are retained
  under `~/.local/share/krellix/windows-symbols/0.1.2-windows-preview.4/`.

## Krelldacious Windows Release - 2026-11-19

- Plugin 0.1.0-windows.1, GitHub tag `krelldacious-v0.1.0-windows.1`,
  source `767a55f`. Requires Krellix Windows preview.3.
- Tested the packaged DLL against Audacious 4.6.1 on the Windows desktop:
  launch, play, pause, resume, previous/next, track title, volume and remote
  isolation. Used a separate test playlist; the user's playlist was not changed.
- Installed and enabled on the local Windows window. Verified it loaded the
  released DLL and exposed its transport buttons. The two existing remote
  windows, Krellix host binary and Linux/macOS backends were left unchanged.
- Published signed ZIP, source and metadata to both local copies and Cloudflare.
  Current public index and metadata match the local copies. The release links
  include a query to bypass cached pre-upload errors; the published links passed
  download, SHA-256 and GPG checks.
- Next: KrellStock.

## Windows Crash Mitigation and KrellMail Release - 2026-11-19

- Host 0.1.2-windows-preview.3, source `7d43f86`, and KrellMail
  0.1.0-windows.1, source `21bfe56`. GitHub tags, signed local artifact
  copies and Cloudflare publication verified. All 13 public release files
  returned HTTP 200; bytes, SHA-256 and signatures matched.
- The vibrixmedia crash backtrace pointed to Qt settings construction in
  `Decal::onScrollTick()`. Preview.3 removes that access from the Windows
  animation timer and preserves profile/live scroll settings. The underlying
  Qt failure was not independently reproduced or proven fixed.
- All 20 Windows tests passed. The real vibrixmedia Windows window retained
  its original settings, connected and remained responsive for over an hour.
  The unchanged daemon has a four-client cap; a second copy of this remote
  window cannot fit while the existing one holds three sessions.
- The two extracted release ZIPs displayed three unread loopback IMAP
  messages on the Windows desktop. KrellMail is installed and enabled on
  the local window, with no account added. The remote windows cannot use
  the Windows mail plugin for local accounts. Linux/macOS and Cerberix VM
  were not updated.
- New Windows shortcut launches use preview.3. The already running
  Quantumbytz window was not restarted. The old optional-plugin standalone
  installers still target preview.2; retain installed DLLs and helpers when
  updating the host.
- Next: Krelldacious.

## Completed Windows Release - Preview.2

- Host: 0.1.2-windows-preview.2.
- KrellTop: 0.1.4-windows.2.
- Source commit: c81fe4ab2560b5c3ab7d6bb34b51e65db1370d58.
- GitHub: https://github.com/yodabytz/krellix
- Public repository: https://repo.cerberix.org/windows/index.html
- Local artifacts: packaging/repo/windows/
- Local web mirror: /var/www/cerberix.org/repo/windows/
- Verified: seven Windows tests, three running desktop instances, matching
  installed/packaged binaries, preserved settings, public HTTP 200 downloads,
  SHA-256 checksums and GPG signatures.
- Linux/macOS sources and packages were not changed.

## Completed KrellHealth Release

- Plugin: 0.1.1-windows.2, source commit
  cc7951df400a2b68d0b67b313f91ac6f015c95ba.
- Published to GitHub, the local Windows repository and Cloudflare, with
  verified public downloads, SHA-256 checksums and GPG signatures.
- Installed and verified in all three Windows instances. Existing host and
  KrellTop binaries are unchanged; per-instance settings are preserved.
- Nine Windows tests pass, including healthy-heart rendering, unknown data,
  malformed/oversized remote messages, timeout clearing, reconnects, and shutdown.
- Local read-only helper checks fixed-drive space, memory pressure, Windows
  Update reboot requirements, and automatic services stopped with an error.
- SMART, backup age, certificates and event-log history are not covered by
  this Windows probe. Unavailable checks are reported, not treated as healthy.
- Remote instances consume only the selected daemon's health. Missing data or
  disconnection never shows a healthy heart or falls back to Windows checks.
- Original Linux/macOS plugin source files remain byte-for-byte unchanged.
- Healthy heart was visually verified in the Vibrixmedia Windows instance.

## Released KrellWiFi Windows Preview

- Plugin: 0.1.3-windows.1; source commit
  32d2a6b185e1c25851c3059f98a03c5d8122f9dc.
- Installed and visibly enabled in the local Windows VM instance. Existing
  host, KrellTop and KrellHealth hashes are unchanged. All three instances
  restarted gracefully and are responsive. Remote configurations are identical;
  the only local configuration change enables KrellWiFi.
- Eleven Windows tests pass, including native buffer validation, AP fixtures,
  escaped SSIDs, missing hardware, permissions/service/radio errors, malformed
  and oversized output, timeout, shutdown and remote-instance isolation.
- Native WLAN helper runs every 60 seconds, off the UI thread. It changes no
  connections, services or privacy permissions and reads no saved passwords.
- This VM exposes virtual Ethernet, not a Wi-Fi radio: the panel correctly
  shows "No Wi-Fi adapter". Live RF scanning remains unverified until a Wi-Fi
  adapter is exposed to Windows. Synthetic scans are not a substitute for that.
- Local-only: daemon Wi-Fi telemetry is not supported; remote windows do not
  show Windows or Mac wireless data.
- GitHub source/tag, signed local repository and Cloudflare artifacts published.
  Public downloads return HTTP 200; SHA-256 and GPG verification pass. Existing
  versioned artifacts are preserved. Linux/macOS sources and packages unchanged.

## Released KrellBluetooth Windows Preview

- Plugin: 0.1.2-windows.1; source commit
  84012314abb9709524ac31f730a4536e99d6327f.
- Installed and visibly enabled in the local Windows instance. Three instances
  restarted gracefully and remained responsive. Existing host/Top/Health/WiFi
  hashes are unchanged. Settings values are preserved except enabling local
  Bluetooth; QSettings reserialized one remote INI without changing its values.
- Fourteen Windows tests pass: native battery property conversion, zero/unknown/
  full levels, invalid data, 120px layout, escaped names, cross-DLL theme changes,
  failed-refresh stale-row clearing, timeout, shutdown and remote isolation.
- Connected devices are enumerated through Windows WinRT. Uses the documented
  System.Devices.BatteryLife property when available, with standard BLE Battery
  Service fallback. Unknown batteries stay unknown; no invented averages.
- Queries run every 15 seconds in a bounded .NET helper with a private STA
  message loop. No pairing, radio/service changes, driver installation or
  elevation. No local readings appear in remote windows.
- The VM exposes a Bluetooth adapter but reports no connected devices. That
  state and fixture data were verified; live connected-device battery accuracy
  remains unverified until a compatible device is connected to Windows.
- GitHub source/tag and signed local/Cloudflare artifacts published. Public ZIP,
  source, metadata and index return HTTP 200; SHA-256 and GPG verification pass.
- Linux/macOS Bluetooth sources and packages are untouched. No host code change,
  Windows restart, or Cerberix Linux VM package update was performed.
- VM hostname is now BlueScreen; deployment tasks use the current account SID
  rather than the old desktop hostname.

## Released KrellPkg Windows Preview

- Plugin: 0.1.2-windows.1; source commit
  1567430bdf53f0653581216831fdfb6c1f013fb4.
- Installed from the release ZIP and enabled in all three Windows instances.
  Visually verified local WinGet 3, Quantumbytz apt 55, and Vibrixmedia apt 46.
  These are observed counts, not fixed expected values for future checks.
- Sixteen Windows tests pass, including actual DLL loading, live filters,
  schema bounds, deduplication, escaped tooltips, empty/error/malformed/oversized
  replies, timeout, shutdown, remote-only data and disconnect clearing.
- Local checks use the structured WinGet COM API in a bounded separate helper,
  every five minutes with a 60-second deadline. No localized table parsing,
  package installation/upgrades, source resets, automatic agreement acceptance,
  elevation or development-runtime PATH dependencies.
- Existing include/exclude patterns match package IDs or names immediately.
  Windows automatically uses WinGet; Unix backend selectors do not apply.
  Covers the community source, not Windows Update or Microsoft Store. Requires
  Microsoft App Installer registered for the logged-in desktop user. Tested
  with WinGet 1.29.380; other WinGet versions have not been exercised here.
- Remote instances reuse core daemon telemetry and do not run WinGet or add
  connections. Cached server metadata freshness and supported backends apply.
- Host and previous plugin hashes unchanged. Settings values unchanged except
  enabling KrellPkg. No Linux/macOS source or package changes; no Linux VM update.
- GitHub source/tag, signed local repository and Cloudflare artifacts published.
  Public ZIP/source/metadata/index return HTTP 200; SHA-256 and GPG checks pass.

## KrellStack Release Checkpoint - 2026-11-18

This supersedes the checkpoints below.

- Final Windows version 0.1.1-windows.3 is installed and published. Source
  commit 0957cc8ac0403a28fc447afb5ca2f3af10b7ce6e and tag
  krellstack-v0.1.1-windows.3 are on GitHub. Signed ZIP/source and signed metadata
  are published to local and Cloudflare repositories, artifacts before metadata.
- All nine public release downloads returned HTTP 200; both artifact SHA256
  values and four GPG signatures verified. Public/local-web/latest.json match.
  Windows also downloaded the public ZIP and verified its advertised .3 hash.
  Existing host, other plugins and Linux/macOS implementations are unchanged.
- Final .3 data/native/integration tests passed; earlier complete host/plugin
  suite coverage is preserved. Four shorter rows avoid the combined-label
  scrolling observed in .2. Source-specific errors replace generic check-failed
  where possible. No-Docker remote state and no-local-fallback tests pass.
- .3 installed helper was verified without SDK PATH after Docker removal and
  correctly returned missing-runtime status. Live local engines remain untested
  because WSL failed; that limitation is documented publicly, not hidden.
- Docker and test WSL package uninstallers reported success. WslService stopped;
  test-only .wslconfig removed from profile with backup in C:\krellix-work.
  Locked installer files may require next reboot. VMware nested virtualization
  and optional Windows virtualization features still need baseline-aware cleanup
  at an authorized shutdown/restart; do not interrupt the VM automatically.
- After network recovery the user's saved launch list contained duplicate
  quantumbytz instances. Shortcuts were correct. Closed only duplicate PID 7064
  gracefully and started vibrixmedia PID 8536, which responded for 30 seconds
  but subsequently exited again. Last observed local/quantumbytz PIDs: 6912/10520.
  Do not claim vibrixmedia stability fixed; earlier Qt6Core crash predated Stack.
  PID 8536 crash confirmed at 21:09:15: Qt6Core.dll 6.12.0, 0xc0000005,
  offset 0xf4bb6, report 86586c06-ba61-4e06-994a-e3f63f5ef67f. Root cause unknown.
- User needs to shut down for bed. Do not restart or relaunch more instances
  tonight. Resume stability diagnosis next time; avoid hiding failures by
  weakening test assertions. Next planned new plugin remains KrellMail.

## Superseded KrellStack Checkpoint - 2026-11-18

This supersedes the historical checkpoint below.

- Windows 0.1.1-windows.2 installed and all three instances verified responsive,
  with matching package hashes, existing host/plugins unchanged and settings
  preserved. Quantumbytz visibly showed 13/21 containers, 23 images, 7 projects;
  vibrixmedia (no Docker installed) safely showed zero. Remote data stays remote.
- All 19 tests passed across runs; the final three Stack tests passed again for
  .2, covering real DLL loading, native runtime fixtures, cleanup, no-Docker
  remote telemetry, reconnect, errors and source-specific failure labels.
- Visual check showed .2 combined labels scroll in the user's narrow theme.
  Pending .3 splits images/projects into separate rows, using Stopped/alerts
  instead of bad. .3 is NOT built/verified/published yet. Linux/macOS unchanged.
- .2 source commit d5630d83a3eb67fd16841ee6813ea13428575b70 and tag
  krellstack-v0.1.1-windows.2 are pushed. Signed .2 ZIP/source are in local
  packaging/repo/windows and /var/www/cerberix.org/repo/windows. Only the .2 ZIP
  was uploaded to Cloudflare. Do not overwrite that versioned artifact.
  Draft latest.json/index/SHA256SUMS have NOT been published to web mirrors.
- User authorized temporary Docker/WSL and VMware nested virtualization, then
  asked to remove Docker. Docker 4.99.0/WSL 3.0.5 installed but WSL CreateVm
  timed out twice. No test container ran. Live local Docker/Podman/Kubernetes
  enumeration remains explicitly unverified; remote integration is verified.
- Docker uninstall logs confirm success, with locked files deferred to reboot.
  WSL uninstall could not execute because SSH failed. New .wslconfig remains:
  memory=3GB, processors=2, swap=512MB, nestedVirtualization=false.
  VMware vhv.enable=TRUE remains; remove only after authorized clean shutdown.
  Firewall stays enabled; do not force-reset/reboot without permission.
- Current blocker: 192.168.78.164 does not answer SSH/ping; Mac ARP incomplete;
  Fusion logs E1000 receive-ring-full messages. User was asked about desktop
  and network responsiveness. vmrun requires encrypted VM password; no bypass.
- Pending .3 sources: /tmp/krellstack-windows/src and stage, canonical worktree
  /home/yodabytz/MyCode/krellix. Latest scp may be incomplete: re-upload before
  building. .3 target package directory: C:\krellix-work\stack-release-compact.
  activate.ps1/verify.ps1 target .3. Temporary Docker setup and backup files are
  under /tmp/krellstack-docker-20261118 and C:\krellix-work.
- Resume: recover connectivity safely; finish .3 tests/package/install/visual
  check and cleanup; commit/tag/push; publish signed artifacts BEFORE metadata
  locally and on Cloudflare; verify public downloads. Then next is KrellMail.
- Separate issues: vibrixmedia crashed in Qt6Core at 7:03 PM before Stack install;
  no retained dump. Restarted and passed subsequent installed checks. Quantumbytz
  attention=7 is six stopped build/test containers and restarting rb_mysql.
  No server containers were changed.

## Historical KrellStack Checkpoint - 2026-11-15

- User suspended the Windows VM; leave it suspended until the user resumes it.
- Windows-only 0.1.1-windows.1 implementation and packaging files are staged in
  /home/yodabytz/MyCode/krellix, not committed or published. Linux/macOS sources,
  host code and installed binaries remain unchanged.
- Work and deployment scripts: /tmp/krellstack-windows/. Source staging matches
  the canonical repository. Windows build/source remain under C:\krellix-work.
- First complete run: all 19 Windows tests passed, including native helper
  cleanup, actual DLL, runtime fixtures, remote isolation and reconnect.
- Final warning-cleanup build completed; final-build.ps1 was rerunning the full
  suite when the VM was suspended (last observed test: krellhealth-integration).
  SSH execution session 81286 may have disconnected. Inspect process/test logs
  after resume before rerunning or assuming packaging completed.
- final-build.ps1 creates stack-release-final only after all tests pass. No
  activation was requested or performed. activate.ps1 and verify.ps1 on Windows
  are now the Stack scripts; they install from the ZIP and preserve prior
  binaries/settings except enabling KrellStack in the three instances.
- VM has no Docker/Podman/kubectl. Do not install a runtime automatically.
  Verify missing-runtime behavior plus actual remote server counts; retain the
  documented limitation that live local Windows runtime checks remain untested.
- Local packaging/repo/windows/index.html has an UNPUBLISHED draft Stack section.
  Public/local web mirrors and release metadata have NOT been updated for Stack.
- Resume: finish final tests, package, install/verify/screenshot all three
  instances, commit/tag/push scoped source, publish signed ZIP/source before
  metadata to local and Cloudflare repos, verify public downloads from Windows,
  then record release completion. Never overwrite published versioned files.
- Separate read-only observation: server container /rb_mysql reported restarting
  and unhealthy. User was informed; no container or application changes made.

Next plugin in the agreed order: KrellStack. Do not skip or reorder without
the user's direction.
