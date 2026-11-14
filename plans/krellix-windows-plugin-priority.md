# Krellix Windows Plugin Priority

Agreed order: 2026-11-14. This is the newly agreed ranking, not a recovered
copy of the earlier conversation's list.

1. KrellTop - CPU/memory process monitoring. COMPLETE: 0.1.4-windows.2.
2. KrellHealth - overall system health. COMPLETE: 0.1.1-windows.2.
3. KrellWiFi - wireless monitoring and analysis.
4. KrellBT / KrellBluetooth - Bluetooth devices and batteries.
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

Next plugin in the agreed order: KrellWiFi. Do not skip or reorder without
the user's direction.
