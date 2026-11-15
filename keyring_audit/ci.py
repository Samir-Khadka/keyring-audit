"""CI/CD variables (Keyring Audit v1.1, Phase 6 coverage).

GitHub Actions secrets are credentials that live in the CI store, not
in code — the repo scan never sees them. `ci-secrets` lists them via
the GitHub API and cross-references them with the repo's workflow
files, so the report can say which secrets are actually used and
which are dead weight.

The honest limits of this command, stated up front:
- GitHub never returns a secret's VALUE — not to anyone, not even the
  repo owner. So a CI secret's liveness cannot be checked; it is
  always "unknown", and the ranking scores its privilege in the
  middle (20) rather than assuming it is safe.
- What the API does return is the metadata: the name, `created_at`,
  and `updated_at` (the last time the secret was set — the closest
  thing to a rotation date). The age component is measured from
  `updated_at`.
- "Used" means a workflow file references `${{ secrets.NAME }}`. A
  secret that no workflow references is unused — safe to remove, and
  the report says so. A secret that IS referenced is in use; the
  report names the workflows. Whether a workflow actually runs is not
  something the API says, so the usage score does not claim it.

The token needs the `repo` scope (or the fine-grained Secrets: read
permission) and comes from `GITHUB_TOKEN` or a prompt, used once.
The secret NAMES are public metadata — the report shows them, because
that is what the user needs to act on. No value is ever read, because
no value can be read.
"""
from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from . import github as github_mod
from .detectors import fingerprint

SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _parse_ts(value: str | None) -> int | None:
    """An ISO timestamp to a unix epoch (for the ranking's age)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except ValueError:
        return None


def list_actions_secrets(owner: str, repo: str, token: str,
                         request=github_mod.request) -> list[dict]:
    """GET /repos/{owner}/{repo}/actions/secrets, paginated. Returns
    [{name, created_at, updated_at}]. Raises ValueError (via the
    client) on a bad repo or token."""
    secrets: list[dict] = []
    page = 1
    while True:
        doc = request(token, "GET",
                      f"/repos/{owner}/{repo}/actions/secrets"
                      f"?per_page=100&page={page}")
        batch = doc.get("secrets", [])
        secrets.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return secrets


def workflow_secret_refs(text: str) -> set[str]:
    """The secret names a workflow file references."""
    return set(SECRET_REF_RE.findall(text))


def load_workflows_local(path: Path) -> dict[str, str]:
    """filename -> content for .github/workflows/*.yml|*.yaml."""
    out: dict[str, str] = {}
    wf_dir = Path(path) / ".github" / "workflows"
    if not wf_dir.is_dir():
        return out
    for f in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        try:
            out[f.name] = f.read_text()
        except OSError:
            continue
    return out


def load_workflows_api(owner: str, repo: str, token: str,
                       request=github_mod.request) -> dict[str, str]:
    """The workflow files, via the GitHub contents API (base64)."""
    out: dict[str, str] = {}
    try:
        listing = request(token, "GET",
                          f"/repos/{owner}/{repo}/contents/.github/workflows")
    except ValueError:
        return out  # no workflows directory — not an error
    if not isinstance(listing, list):
        return out
    for entry in listing:
        name = entry.get("name", "")
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            continue
        try:
            doc = request(token, "GET",
                          f"/repos/{owner}/{repo}/contents/.github/workflows/{name}")
            content = doc.get("content", "")
            out[name] = base64.b64decode(content).decode("utf-8",
                                                          errors="replace")
        except (ValueError, KeyError):
            continue
    return out


def build_ci_findings(owner: str, repo: str, secrets: list[dict],
                      workflows: dict[str, str]) -> list[dict]:
    """One finding per Actions secret, with its workflow usage."""
    refs: dict[str, list[str]] = {}
    for fname, text in workflows.items():
        for name in workflow_secret_refs(text):
            refs.setdefault(name, []).append(fname)
    findings: list[dict] = []
    for s in secrets:
        name = s.get("name", "")
        used_in = sorted(refs.get(name, []))
        if used_in:
            usage_override = (8, f"referenced in {len(used_in)} "
                                 "workflow(s) — in use, last run unknown")
        else:
            usage_override = (15, "not referenced in any workflow — "
                                  "safe to remove")
        findings.append({
            "detector": "actions-secret", "provider": "github-actions",
            # The NAME is public metadata, not secret material.
            "redacted": name,
            "fingerprint": fingerprint(
                f"github-actions:{owner}/{repo}:{name}"),
            "source": f"GitHub Actions secrets — {owner}/{repo}",
            "line": None, "commit": None, "author": None,
            "date": _parse_ts(s.get("updated_at")),
            "owner": {"name": None, "source": "none"},
            "exposure_source": "ci",
            "usage_override": usage_override,
            "used_in": used_in,
            "created_at": s.get("created_at"),
            "updated_at": s.get("updated_at"),
            "validity": {"live": "unknown",
                         "reason": "GitHub never returns a secret's "
                                   "value, so liveness cannot be checked",
                         "permissions": [], "method": "github-actions-api",
                         "last_used": None},
        })
    return findings


def render_ci(ranked: list[dict], owner: str, repo: str,
              fmt: str = "text") -> str:
    """The CI secrets report. The names are shown (they are metadata);
    no value is ever shown, because no value can be read."""
    if fmt == "json":
        return json.dumps({"repo": f"{owner}/{repo}",
                           "findings": ranked}, indent=2)
    if fmt == "md":
        lines = [f"# GitHub Actions secrets — {owner}/{repo}", ""]
        for f in ranked:
            lines.append(f"## {f['redacted']} "
                         f"[{f['risk']['band']} {f['risk']['score']}]")
            lines.append(f"- Updated: {f.get('updated_at') or 'unknown'}")
            lines.append("- Used in: "
                         + (", ".join(f["used_in"]) if f["used_in"]
                            else "no workflow — safe to remove"))
            lines.append(f"- Safe to remove: "
                         f"{'yes' if f['risk']['safe_to_kill'] else 'no'}")
            lines.append("")
        return "\n".join(lines)
    lines = [f"GitHub Actions secrets — {owner}/{repo}",
             f"{len(ranked)} secret(s)", ""]
    for f in ranked:
        lines.append(f"{f['redacted']} [{f['risk']['band']} "
                     f"{f['risk']['score']}] — updated "
                     f"{f.get('updated_at') or 'unknown'}")
        lines.append("  used in: "
                     + (", ".join(f["used_in"]) if f["used_in"]
                        else "no workflow — safe to remove"))
        lines.append("  safe to remove: "
                     f"{'yes' if f['risk']['safe_to_kill'] else 'no'}")
        lines.append("")
    return "\n".join(lines)
