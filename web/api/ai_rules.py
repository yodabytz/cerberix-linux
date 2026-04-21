"""
Cerberix Web API — AI Natural Language Firewall Rules

User describes a rule in plain English, Claude generates the nftables rule.
"""

import json
import logging
import os
import re
import subprocess
import time

log = logging.getLogger("cerberix-web")

AI_RULES_LOG = "/var/lib/cerberix/ai/rules-history.json"


def _get_current_ruleset() -> str:
    """Get current nftables ruleset summary."""
    try:
        r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5)
        return r.stdout[:2000] if r.returncode == 0 else ""
    except subprocess.SubprocessError:
        return ""


def _load_history() -> list:
    if not os.path.exists(AI_RULES_LOG):
        return []
    try:
        with open(AI_RULES_LOG) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_history(history: list):
    os.makedirs(os.path.dirname(AI_RULES_LOG), exist_ok=True)
    with open(AI_RULES_LOG, "w") as f:
        json.dump(history[-50:], f, indent=2)  # Keep last 50


def generate_rule(description: str) -> dict:
    """Use Claude to generate an nftables rule from plain English."""
    if not description or len(description) < 5:
        return {"success": False, "error": "Description too short"}
    if len(description) > 500:
        return {"success": False, "error": "Description too long (max 500 chars)"}

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        # Try loading from .env or config
        for path in ["/etc/cerberix/.env", "/opt/cerberix/.env"]:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        for line in f:
                            if line.startswith("ANTHROPIC_API_KEY="):
                                api_key = line.split("=", 1)[1].strip().strip('"')
                except OSError:
                    pass

    if not api_key:
        return {"success": False, "error": "No API key configured. Set ANTHROPIC_API_KEY."}

    current_rules = _get_current_ruleset()

    prompt = f"""You are a network security expert. Generate an nftables rule based on the user's description.

Current nftables ruleset (summary):
{current_rules[:1500]}

User request: {description}

Respond with ONLY a JSON object containing:
- "nft_command": the exact nft command(s) to run (as a string, multiple commands separated by semicolons)
- "explanation": a brief explanation of what the rule does
- "warning": any security warnings (empty string if none)
- "reversible": true/false — whether this can be safely undone

Do NOT include any other text. Only the JSON object."""

    try:
        import urllib.request
        data = json.dumps({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode())

        # Extract the text content
        content = result.get("content", [{}])[0].get("text", "")

        # Parse JSON from response
        # Try to find JSON in the response
        json_match = re.search(r'\{[^{}]*"nft_command"[^{}]*\}', content, re.DOTALL)
        if json_match:
            rule_data = json.loads(json_match.group())
        else:
            rule_data = json.loads(content)

        return {
            "success": True,
            "nft_command": rule_data.get("nft_command", ""),
            "explanation": rule_data.get("explanation", ""),
            "warning": rule_data.get("warning", ""),
            "reversible": rule_data.get("reversible", True),
            "description": description,
        }

    except Exception as e:
        log.warning(f"AI rule generation failed: {e}")
        return {"success": False, "error": f"AI generation failed: {str(e)[:100]}"}


def apply_rule(nft_command: str, description: str) -> dict:
    """Apply a generated nftables rule."""
    if not nft_command:
        return {"success": False, "error": "No command provided"}

    # Safety checks
    dangerous = ["flush ruleset", "delete table", "destroy", "policy drop"]
    for d in dangerous:
        if d in nft_command.lower():
            return {"success": False, "error": f"Blocked: command contains '{d}'"}

    # Execute each command
    commands = [c.strip() for c in nft_command.split(";") if c.strip()]
    results = []
    for cmd in commands:
        if not cmd.startswith("nft "):
            cmd = f"nft {cmd}"
        parts = cmd.split()
        try:
            r = subprocess.run(parts, capture_output=True, text=True, timeout=10)
            results.append({
                "command": cmd,
                "success": r.returncode == 0,
                "output": r.stdout + r.stderr,
            })
            if r.returncode != 0:
                return {"success": False, "error": f"Command failed: {r.stderr}", "results": results}
        except subprocess.SubprocessError as e:
            return {"success": False, "error": str(e), "results": results}

    # Save to history
    history = _load_history()
    history.append({
        "description": description,
        "command": nft_command,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "applied": True,
    })
    _save_history(history)

    return {"success": True, "results": results}


def get_history() -> dict:
    """Get rule generation history."""
    return {"history": _load_history()}
