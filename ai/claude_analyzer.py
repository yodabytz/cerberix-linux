"""
Cerberix AI — Claude API Deep Analyzer

Uses Claude for advanced threat analysis that exceeds local ML capabilities:
- Correlating multi-vector attacks
- Analyzing novel attack patterns
- Generating human-readable threat reports
- Recommending firewall rule changes
"""

import json
import time
import os
from dataclasses import asdict
from typing import Optional

SYSTEM_PROMPT = """You are Cerberix AI, the security intelligence engine for a Cerberix Firewall \
firewall appliance. You analyze network security events and provide actionable intelligence.

Your responsibilities:
1. Analyze threat events and determine if they represent real attacks or false positives
2. Correlate events across detectors to identify multi-stage attacks
3. Recommend specific nftables rules or configuration changes
4. Provide concise, actionable threat reports

Response format — always return valid JSON:
{
  "threat_assessment": "critical|high|medium|low|false_positive",
  "confidence": 0.0-1.0,
  "summary": "One-line summary",
  "analysis": "Detailed analysis paragraph",
  "correlations": ["Related patterns observed"],
  "recommendations": [
    {
      "action": "block_ip|block_subnet|block_domain|add_rule|rate_limit|monitor",
      "target": "IP/subnet/domain/rule",
      "reason": "Why this action",
      "nft_rule": "Optional: exact nftables rule to add"
    }
  ],
  "false_positive_indicators": ["Why this might be benign"]
}"""


class ClaudeAnalyzer:
    """
    Deep threat analysis via Claude API.
    Runs periodically or on-demand for critical alerts.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-6",
        log_dir: str = "/var/log/cerberix",
    ):
        self.api_key = api_key or os.environ.get("CERBERIX_AI_API_KEY")
        self.model = model
        self.log_dir = log_dir
        self._client = None
        self._last_analysis_time = 0.0
        self._event_buffer: list[dict] = []
        self._max_buffer = 50

        if self.api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                pass

    @property
    def available(self) -> bool:
        return self._client is not None

    def buffer_event(self, event: dict):
        """Buffer an event for batch analysis."""
        self._event_buffer.append(event)
        if len(self._event_buffer) > self._max_buffer:
            self._event_buffer = self._event_buffer[-self._max_buffer:]

    def analyze_threat(
        self,
        alerts: list[dict],
        context: Optional[dict] = None,
    ) -> Optional[dict]:
        """
        Send alerts to Claude for deep analysis.
        Returns structured threat assessment.
        """
        if not self.available:
            return self._fallback_analysis(alerts)

        # Build the analysis prompt
        prompt = self._build_prompt(alerts, context)

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            result_text = response.content[0].text

            # Parse JSON response
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                start = result_text.find("{")
                end = result_text.rfind("}") + 1
                if start >= 0 and end > start:
                    result = json.loads(result_text[start:end])
                else:
                    result = {
                        "threat_assessment": "unknown",
                        "confidence": 0.5,
                        "summary": "Failed to parse AI response",
                        "analysis": result_text,
                        "recommendations": [],
                    }

            self._last_analysis_time = time.time()
            self._log_analysis(alerts, result)
            return result

        except Exception as e:
            self._log_error(str(e))
            return self._fallback_analysis(alerts)

    def analyze_periodic(
        self,
        interval_sec: int = 300,
        force: bool = False,
    ) -> Optional[dict]:
        """Run periodic deep analysis on buffered events."""
        now = time.time()
        if not force and now - self._last_analysis_time < interval_sec:
            return None

        if not self._event_buffer:
            return None

        alerts = self._event_buffer.copy()
        self._event_buffer.clear()

        return self.analyze_threat(alerts)

    def _build_prompt(
        self, alerts: list[dict], context: Optional[dict] = None
    ) -> str:
        """Build the analysis prompt for Claude."""
        prompt_parts = [
            "Analyze the following security events from our Cerberix Firewall firewall.\n",
            f"Current time: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n",
        ]

        if context:
            prompt_parts.append(
                f"Network context: {json.dumps(context, indent=2)}\n"
            )

        prompt_parts.append(f"Events ({len(alerts)} total):\n")
        prompt_parts.append("```json\n")
        prompt_parts.append(json.dumps(alerts[:30], indent=2, default=str))
        prompt_parts.append("\n```\n")

        prompt_parts.append(
            "\nProvide your threat assessment as JSON. "
            "Focus on: Are these real threats or false positives? "
            "Are there correlated attack patterns? "
            "What specific nftables rules should be added?"
        )

        return "\n".join(prompt_parts)

    def _fallback_analysis(self, alerts: list[dict]) -> dict:
        """Local analysis when Claude API is unavailable."""
        severity_counts = {}
        for alert in alerts:
            sev = alert.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        highest = "low"
        for sev in ["critical", "high", "medium"]:
            if severity_counts.get(sev, 0) > 0:
                highest = sev
                break

        unique_ips = set()
        for alert in alerts:
            for key in ["src_ip", "client_ip", "ip"]:
                if key in alert:
                    unique_ips.add(alert[key])

        recommendations = []
        for ip in unique_ips:
            ip_alerts = [
                a for a in alerts
                if any(a.get(k) == ip for k in ["src_ip", "client_ip", "ip"])
            ]
            if len(ip_alerts) >= 3:
                recommendations.append({
                    "action": "block_ip",
                    "target": ip,
                    "reason": f"Multiple threat detections ({len(ip_alerts)} events)",
                })

        return {
            "threat_assessment": highest,
            "confidence": 0.6,
            "summary": (
                f"Local analysis: {len(alerts)} events, "
                f"{len(unique_ips)} unique sources, "
                f"highest severity: {highest}"
            ),
            "analysis": "Claude API unavailable — using local heuristic analysis.",
            "recommendations": recommendations,
            "note": "Enable Claude API for deeper analysis (set CERBERIX_AI_API_KEY)",
        }

    def _log_analysis(self, alerts: list[dict], result: dict):
        """Log the analysis result."""
        log_path = os.path.join(self.log_dir, "ai-analysis.log")
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "alert_count": len(alerts),
            "assessment": result.get("threat_assessment"),
            "confidence": result.get("confidence"),
            "summary": result.get("summary"),
            "recommendation_count": len(result.get("recommendations", [])),
        }
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _log_error(self, error: str):
        log_path = os.path.join(self.log_dir, "ai-errors.log")
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "error": error,
        }
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
