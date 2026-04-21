"""
Cerberix AI — Daily Security Report

Generates a comprehensive security summary using Claude,
covering all detections, blocks, and anomalies from the past 24 hours.
"""

import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger("cerberix-ai")

REPORT_DIR = "/var/lib/cerberix/ai/reports"
LOG_DIR = "/var/log/cerberix"


class DailyReportGenerator:
    """Generates daily security reports using Claude."""

    def __init__(self, claude_analyzer=None, notification_engine=None):
        self.claude = claude_analyzer
        self.notifications = notification_engine
        os.makedirs(REPORT_DIR, exist_ok=True)

    def generate(self, force: bool = False) -> Optional[dict]:
        """Generate a daily report if one hasn't been made today."""
        today = time.strftime("%Y-%m-%d")
        report_path = os.path.join(REPORT_DIR, f"report-{today}.json")

        if os.path.exists(report_path) and not force:
            try:
                with open(report_path) as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        log.info("Generating daily security report...")
        report = self._build_report()

        # Use Claude for analysis if available
        if self.claude and self.claude.available:
            report["ai_analysis"] = self._claude_analysis(report)

        # Save
        try:
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
        except OSError:
            pass

        # Notify
        if self.notifications:
            self.notifications.notify({
                "severity": "medium",
                "detector": "daily_report",
                "target": "system",
                "reason": f"Daily Report: {report['summary']['total_threats']} threats, "
                          f"{report['summary']['ips_blocked']} IPs blocked",
                "timestamp": report["generated_at"],
            })

        log.info(f"Daily report generated: {report['summary']}")
        return report

    def get_latest(self) -> Optional[dict]:
        """Get the most recent report."""
        try:
            reports = sorted(
                [f for f in os.listdir(REPORT_DIR) if f.startswith("report-")],
                reverse=True,
            )
            if reports:
                with open(os.path.join(REPORT_DIR, reports[0])) as f:
                    return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _build_report(self) -> dict:
        """Collect all security data from the past 24 hours."""
        now = time.time()
        cutoff = now - 86400
        today = time.strftime("%Y-%m-%d")

        # Collect threats
        threats = []
        threat_log = os.path.join(LOG_DIR, "ai-threats.log")
        if os.path.exists(threat_log):
            try:
                with open(threat_log) as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get("epoch", 0) > cutoff:
                                threats.append(entry)
                        except json.JSONDecodeError:
                            pass
            except OSError:
                pass

        # Severity breakdown
        severity_counts = {}
        detector_counts = {}
        unique_ips = set()
        for t in threats:
            sev = t.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            det = t.get("detector", "unknown")
            detector_counts[det] = detector_counts.get(det, 0) + 1
            target = t.get("target", "")
            if target:
                unique_ips.add(target)

        # Blocked IPs
        blocked = {}
        bl_path = "/var/lib/cerberix/ai/blocklist.json"
        if os.path.exists(bl_path):
            try:
                with open(bl_path) as f:
                    blocked = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        # Suricata alerts
        suricata_alerts = 0
        eve_path = os.path.join(LOG_DIR, "suricata/eve.json")
        if os.path.exists(eve_path):
            try:
                import subprocess
                result = subprocess.run(
                    ["grep", "-c", '"event_type":"alert"', eve_path],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    suricata_alerts = int(result.stdout.strip())
            except (subprocess.SubprocessError, ValueError):
                pass

        # fail2ban bans
        f2b_bans = 0
        try:
            import subprocess
            result = subprocess.run(
                ["fail2ban-client", "status"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Number of jail:" in line:
                        pass  # just checking it runs
        except (subprocess.SubprocessError, ValueError):
            pass

        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "period": today,
            "summary": {
                "total_threats": len(threats),
                "unique_source_ips": len(unique_ips),
                "ips_blocked": len(blocked),
                "suricata_alerts": suricata_alerts,
                "severity": severity_counts,
                "by_detector": detector_counts,
            },
            "top_threats": threats[-20:],
            "blocked_ips": list(blocked.keys())[:20],
        }

    def _claude_analysis(self, report: dict) -> dict:
        """Get Claude's analysis of the daily report."""
        try:
            prompt = (
                "Analyze this daily security report from a Cerberix Firewall firewall appliance. "
                "Provide a brief executive summary, highlight the most concerning findings, "
                "and recommend specific actions.\n\n"
                f"Report data:\n{json.dumps(report['summary'], indent=2)}\n\n"
                f"Top threats:\n{json.dumps(report['top_threats'][-10:], indent=2, default=str)}"
            )
            result = self.claude.analyze_threat(
                [{"summary": report["summary"]}],
                context={"type": "daily_report", "period": report["period"]},
            )
            return result or {"summary": "Claude analysis unavailable"}
        except Exception as e:
            return {"summary": f"Analysis error: {str(e)}"}
