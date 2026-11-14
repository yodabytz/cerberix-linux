# Krellix Windows Plugin Priority

Agreed order: 2026-11-14. This is the newly agreed ranking, not a recovered
copy of the earlier conversation's list.

1. KrellTop - CPU/memory process monitoring. COMPLETE: 0.1.4-windows.2.
2. KrellHealth - overall system health. IN PROGRESS.
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

## KrellHealth Starting Point

The existing plugin uses Unix local probes and the remote daemon's health
findings. Windows needs native read-only health probes and explicit unknown
states for checks that cannot be performed. Do not report healthy merely
because remote health data is missing or the connection is down.
