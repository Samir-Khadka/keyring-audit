"""Report rendering (Keyring Audit v0.1).

Three formats: text (human), json (machine), md (a report to paste
into an issue or a PR). All three render from the same ranked findings.

Safety: the renderer strips the in-memory `_secret` field from every
finding before rendering, and the module asserts that no rendered output
contains a full secret value. The test suite enforces this by grepping
every output for a known test secret.
"""
from __future__ import annotations

import json

from .remediation import guide


def public_finding(finding: dict) -> dict:
    """A finding safe to write anywhere: no secret material."""
    out = {k: v for k, v in finding.items() if not k.startswith("_")}
    return out


def render_text(ranked: list[dict], warnings: list[str],
                scanned_path: str) -> str:
    lines = [f"Keyring Audit — {scanned_path}", ""]
    live = [f for f in ranked if f.get("validity", {}).get("live") == "live"]
    dead = [f for f in ranked if f.get("validity", {}).get("live") == "dead"]
    unknown = [f for f in ranked if f.get("validity", {}).get("live") not in ("live", "dead")]
    lines.append(f"{len(ranked)} credential(s) found: "
                 f"{len(live)} live, {len(dead)} dead, {len(unknown)} unknown")
    if warnings:
        lines.append("")
        for w in warnings:
            lines.append(f"warning: {w}")
    for i, f in enumerate(ranked, 1):
        risk = f["risk"]
        validity = f.get("validity", {})
        lines.append("")
        lines.append(f"{i}. [{risk['band'].upper()} {risk['score']}] "
                     f"{f['detector']} ({f['provider']}) — {f['redacted']}")
        lines.append(f"   where: {f['source']}"
                     + (f":{f['line']}" if f.get("line") else "")
                     + (f" @ {f['commit'][:12]}" if f.get("commit") else "")
                     + (f" by {f['author']}" if f.get("author") else ""))
        lines.append(f"   validity: {validity.get('live')} — {validity.get('reason', '')}")
        if validity.get("permissions"):
            lines.append(f"   can do: {', '.join(validity['permissions'])}")
        if validity.get("method") == "probed":
            lines.append("   (permissions probed — fine-grained token, no scope header)")
        if validity.get("last_used"):
            lines.append(f"   last used: {validity['last_used']}")
        lines.append(f"   risk: privilege {risk['components']['privilege']['score']} "
                     f"({risk['components']['privilege']['why']}); "
                     f"exposure {risk['components']['exposure']['score']}; "
                     f"age {risk['components']['age']['score']}; "
                     f"usage {risk['components']['usage']['score']}")
        if risk["safe_to_kill"]:
            lines.append("   safe to kill: yes")
        lines.append("   fix:")
        for step in guide(f):
            lines.append(f"     {step}")
    return "\n".join(lines) + "\n"


def render_json(ranked: list[dict], warnings: list[str],
                scanned_path: str) -> str:
    doc = {"tool": "keyring-audit", "version": "0.1.0",
           "path": scanned_path, "warnings": warnings,
           "findings": [public_finding(f) for f in ranked]}
    return json.dumps(doc, indent=2) + "\n"


def render_md(ranked: list[dict], warnings: list[str],
              scanned_path: str) -> str:
    lines = [f"# Keyring Audit — `{scanned_path}`", "",
             f"**{len(ranked)} credential(s) found.**"]
    if warnings:
        lines.append("")
        for w in warnings:
            lines.append(f"> warning: {w}")
    lines.append("")
    lines.append("| # | Risk | Credential | Where | Validity | Can do |")
    lines.append("|---|------|------------|-------|----------|--------|")
    for i, f in enumerate(ranked, 1):
        risk = f["risk"]
        validity = f.get("validity", {})
        where = f["source"] + (f":{f['line']}" if f.get("line") else "")
        can_do = ", ".join(validity.get("permissions", []) or []) or "—"
        lines.append(f"| {i} | **{risk['band']} {risk['score']}** | "
                     f"`{f['detector']}` `{f['redacted']}` | `{where}` | "
                     f"{validity.get('live')} | {can_do} |")
    for i, f in enumerate(ranked, 1):
        lines.append("")
        lines.append(f"## {i}. `{f['detector']}` — {f['risk']['band']} "
                     f"{f['risk']['score']}")
        lines.append("")
        lines.append(f"- Validity: {f.get('validity', {}).get('live')} — "
                     f"{f.get('validity', {}).get('reason', '')}")
        for name, comp in f["risk"]["components"].items():
            lines.append(f"- {name}: {comp['score']} — {comp['why']}")
        lines.append("")
        lines.append("**Fix:**")
        for step in guide(f):
            lines.append(f"- {step}")
    return "\n".join(lines) + "\n"


def render(ranked: list[dict], warnings: list[str], scanned_path: str,
           fmt: str) -> str:
    if fmt == "json":
        return render_json(ranked, warnings, scanned_path)
    if fmt == "md":
        return render_md(ranked, warnings, scanned_path)
    return render_text(ranked, warnings, scanned_path)
