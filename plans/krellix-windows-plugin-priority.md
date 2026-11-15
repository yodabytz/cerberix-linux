# Krellix Windows Plugin Priority

Agreed order: 2026-11-14. This is the newly agreed ranking, not a recovered
copy of the earlier conversation's list.

1. KrellTop - CPU/memory process monitoring. COMPLETE: 0.1.4-windows.2.
2. KrellHealth - overall system health. COMPLETE: 0.1.1-windows.2.
3. KrellWiFi - wireless monitoring and analysis. RELEASED: 0.1.3-windows.1 (physical-radio validation pending).
4. KrellBT / KrellBluetooth - Bluetooth devices and batteries. RELEASED: 0.1.2-windows.1 (live device/battery validation pending).
5. KrellPkg - available package updates.
6. KrellStack - container monitoring.
7. KrellMail - POP3/IMAP mail counts.
8. Krelldacious - Audacious playback and volume controls.
9. KrellStock - stock and cryptocurrency quotes.
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

## Completed Windows Release

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

Next plugin in the agreed order: KrellPkg. Do not skip or reorder without
the user's direction.
