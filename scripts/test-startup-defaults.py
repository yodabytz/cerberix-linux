#!/usr/bin/env python3
"""Offline regression tests for the ISO and installer startup defaults."""
import pathlib, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
class StartupDefaults(unittest.TestCase):
    def check_overlay(self, root):
        return subprocess.run(["bash", str(ROOT / "distro/check-image-state.sh"), str(root)], capture_output=True).returncode
    def test_clean_overlay(self):
        self.assertEqual(self.check_overlay(ROOT / "rootfs"), 0)
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "etc/machine-id"
            p.parent.mkdir(); p.touch()
            self.assertEqual(self.check_overlay(tmp), 0)
    def test_runtime_state_rejected_without_deletion(self):
        for name in ("var/log/journal/test/system.journal", "var/lib/syslog-ng/syslog-ng.persist", "etc/machine-id"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                p = pathlib.Path(tmp) / name
                p.parent.mkdir(parents=True); p.write_text("runtime-state")
                self.assertNotEqual(self.check_overlay(tmp), 0)
                self.assertEqual(p.read_text(), "runtime-state")
    def test_both_build_entrypoints_check_overlays(self):
        for name in ("distro/build.sh", "distro/build-iso.sh"):
            s = (ROOT / name).read_text()
            self.assertIn("/check-image-state.sh", s)
            self.assertLess(s.index("/check-image-state.sh"), s.index("cp -a"))
    def test_installer_copies_retention(self):
        build = (ROOT / "distro/build-iso.sh").read_text()
        generated = build.split("<< 'INSTEOF'\n", 1)[1].split("\nINSTEOF", 1)[0]
        legacy = (ROOT / "distro/airootfs/usr/local/bin/cerberix-install").read_text()
        for s in (generated, legacy):
            self.assertIn("install -Dm644 /etc/systemd/journald.conf.d/60-cerberix-retention.conf", s)
            self.assertIn("/mnt/etc/systemd/journald.conf.d/60-cerberix-retention.conf", s)
            subprocess.run(["bash", "-n"], input=s, text=True, check=True)
    def test_retention_and_scan_schedule(self):
        s = (ROOT / "rootfs/etc/systemd/journald.conf.d/60-cerberix-retention.conf").read_text()
        self.assertIn("SystemMaxUse=128M", s); self.assertIn("RuntimeMaxUse=64M", s)
        timer = (ROOT / "rootfs/etc/systemd/system/cerberix-rkhunter.timer").read_text()
        self.assertIn("OnBootSec=30min", timer); self.assertIn("OnUnitActiveSec=1d", timer)
        self.assertNotIn("Persistent=true", timer); self.assertNotIn("OnCalendar=", timer)
        self.assertNotIn("tomorrow 03:00", (ROOT / "rootfs/usr/local/bin/cerberix-rkhunter-check").read_text())
    def test_shell_syntax(self):
        for name in ("distro/build.sh", "distro/build-iso.sh", "distro/check-image-state.sh", "rootfs/usr/local/bin/cerberix-rkhunter-check"):
            subprocess.run(["bash", "-n", str(ROOT / name)], check=True)
if __name__ == "__main__":
    unittest.main(verbosity=2)
