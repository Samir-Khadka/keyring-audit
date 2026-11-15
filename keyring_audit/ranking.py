"""Risk ranking (Keyring Audit v0.5).

Score 0–100, higher = riskier, from five measured inputs. Every
component is shown in the output so the score is auditable, not a black
box. The weights are the plan's v1 as rebalanced in Phase 3 (privilege
40, exposure 20, age 15, usage 15, ownership 10); they are a starting
point, and the components are what matters — a wrong weight is visible
and fixable.

Bands: Low <30, Medium 30–59, High 60–79, Critical 80+.
A finding is "safe to kill" when it is dead, or live but unused for 90+
days with low privilege — the report flags it, and the remediation guide
says so. A finding with no owner scores 10 on ownership: nobody to ask
to rotate it is itself a risk factor, not a missing field.
"""
from __future__ import annotations

import time

# GitHub scopes that mean full account/repo control.
GITHUB_ADMIN_SCOPES = {"repo", "delete_repo", "admin:org", "admin:public_key",
                       "admin:repo_hook", "admin:org_hook", "admin:enterprise",
                       "admin:gpg_key", "admin:ssh_signing_key", "workflow"}
GITHUB_WRITE_SCOPES = {"write:org", "write:public_key", "write:repo_hook",
                       "write:discussion", "gist", "user", "admin:public_key"}

AWS_ADMIN_POLICIES = ("AdministratorAccess",)

# Simulated actions that let a key escalate its own privilege.
AWS_PRIVESC_ACTIONS = {"iam:CreateUser", "iam:AttachUserPolicy",
                       "iam:PutUserPolicy", "iam:CreateAccessKey",
                       "iam:PassRole"}
# Simulated actions that destroy resources without escalating privilege.
AWS_DESTRUCTIVE_ACTIONS = {"s3:DeleteBucket", "ec2:TerminateInstances",
                           "rds:DeleteDBInstance"}

# GitLab scopes that mean full account control.
GITLAB_ADMIN_SCOPES = {"api", "sudo", "admin_mode"}
GITLAB_WRITE_SCOPES = {"write_repository", "write_registry", "write_user",
                       "create_runner", "manage_runner", "ai_features"}


def _privilege(finding: dict) -> tuple[int, str]:
    """0–40. What the credential can do."""
    validity = finding.get("validity", {})
    live = validity.get("live")
    permissions = validity.get("permissions", []) or []
    provider = finding["provider"]
    if live == "dead":
        return 0, "dead credential — nothing to do with it"
    if live in ("unknown", "skipped"):
        return 20, "privilege unknown — scored in the middle, not assumed safe"
    if provider == "github":
        scopes = set(permissions)
        if scopes & GITHUB_ADMIN_SCOPES:
            return 40, f"admin scope: {sorted(scopes & GITHUB_ADMIN_SCOPES)}"
        if scopes:
            return 25, f"scopes: {', '.join(sorted(scopes))}"
        # Fine-grained, probed: the permission descriptions name the access.
        if any("list own repositories" in p for p in permissions):
            return 25, "fine-grained token with repository access"
        if permissions:
            return 15, f"probed permissions: {', '.join(permissions)}"
        return 5, "public information only"
    if provider == "aws":
        # The simulation is the strongest evidence: it evaluates the
        # effective policy. A key that can escalate its own privilege
        # is effectively admin, whatever its policy names say.
        blast = validity.get("blast_radius") or {}
        if blast.get("method") == "simulate":
            allowed = set(blast.get("allowed") or [])
            privesc = allowed & AWS_PRIVESC_ACTIONS
            if privesc:
                return 40, ("can escalate privilege (simulation): "
                            f"{', '.join(sorted(privesc))}")
            destructive = allowed & AWS_DESTRUCTIVE_ACTIONS
            if destructive:
                return 35, ("can destroy resources (simulation): "
                            f"{', '.join(sorted(destructive))}")
            return 10, "simulation: no high-risk actions allowed"
        joined = " ".join(permissions)
        if any(a in joined for a in AWS_ADMIN_POLICIES):
            return 40, "AdministratorAccess attached"
        if "inline policy" in joined or "managed policy" in joined:
            return 30, "policies attached (see permissions)"
        if not permissions:
            return 20, "permissions unknown (IAM read denied)"
        return 15, "limited permissions listed"
    if provider == "slack":
        scopes = set(permissions)
        if not scopes:
            return 15, "scopes not listed by Slack"
        if any(s.endswith(":write") or s.startswith("admin") for s in scopes):
            return 35, f"write scopes: {', '.join(sorted(scopes))}"
        return 20, f"read-only scopes: {', '.join(sorted(scopes))}"
    if provider == "gitlab":
        scopes = set(permissions)
        if scopes & GITLAB_ADMIN_SCOPES:
            return 40, f"admin scope: {sorted(scopes & GITLAB_ADMIN_SCOPES)}"
        if scopes & GITLAB_WRITE_SCOPES:
            return 30, f"write scopes: {sorted(scopes & GITLAB_WRITE_SCOPES)}"
        if scopes:
            return 15, f"read scopes: {', '.join(sorted(scopes))}"
        return 20, "scopes not listed (group/project token or older GitLab)"
    if provider == "stripe":
        if "full secret key" in permissions:
            return 40, "full secret key — can do anything in the account"
        if "restricted key" in permissions:
            return 25, "restricted key — limited, exact limits not visible via the API"
        return 20, "key type unknown"
    return 20, "privilege unknown for this provider"


def _exposure(finding: dict) -> tuple[int, str]:
    """0–20. Where the credential was found."""
    if finding.get("commit"):
        return 17, "in git history — committed, possibly pushed"
    return 7, "in the working tree only — not committed"


def _age(finding: dict) -> tuple[int, str]:
    """0–15. How old the credential is (commit date, or file time)."""
    ts = finding.get("date")
    if not ts:
        return 5, "age unknown"
    days = (time.time() - ts) / 86400
    if days > 730:
        return 15, f"over 2 years old ({int(days)} days)"
    if days > 365:
        return 10, f"over 1 year old ({int(days)} days)"
    if days > 90:
        return 5, f"{int(days)} days old"
    return 0, f"{int(days)} days old"


def _usage(finding: dict) -> tuple[int, str]:
    """0–15. Is it still being used? Recently used = riskier (live and
    active); long-unused = safer to kill but still sprawl."""
    validity = finding.get("validity", {})
    last_used = validity.get("last_used")
    if not last_used:
        return 8, "usage unknown"
    try:
        from datetime import datetime
        used = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
        days = (datetime.now(used.tzinfo) - used).days
    except (ValueError, TypeError):
        return 8, "usage unknown"
    if days <= 1:
        return 15, "used in the last 24 hours — live and active"
    if days <= 90:
        return 10, f"last used {days} days ago"
    return 5, f"unused for {days} days — safe to kill"


def _ownership(finding: dict) -> tuple[int, str]:
    """0–10. Is there someone to ask to rotate it? A finding with no
    owner scores the full 10 — nobody to ask is itself a risk factor,
    not a missing field."""
    owner = finding.get("owner") or {}
    if owner.get("name"):
        return 0, f"owned by {owner['name']} ({owner.get('source', '?')})"
    return 10, "no owner found — nobody to ask to rotate this"


def rank(finding: dict) -> dict:
    """Score one finding. Returns the finding with a 'risk' dict."""
    p, p_why = _privilege(finding)
    e, e_why = _exposure(finding)
    a, a_why = _age(finding)
    u, u_why = _usage(finding)
    o, o_why = _ownership(finding)
    total = p + e + a + u + o
    band = ("Critical" if total >= 80 else "High" if total >= 60
            else "Medium" if total >= 30 else "Low")
    live = finding.get("validity", {}).get("live")
    safe_to_kill = live == "dead" or (live == "live" and u <= 5 and p <= 20)
    out = dict(finding)
    out["risk"] = {"score": total, "band": band,
                   "components": {"privilege": {"score": p, "why": p_why},
                                  "exposure": {"score": e, "why": e_why},
                                  "age": {"score": a, "why": a_why},
                                  "usage": {"score": u, "why": u_why},
                                  "ownership": {"score": o, "why": o_why}},
                   "safe_to_kill": safe_to_kill}
    return out


def rank_all(findings: list[dict]) -> list[dict]:
    """Rank every finding, highest risk first."""
    return sorted((rank(f) for f in findings),
                  key=lambda f: f["risk"]["score"], reverse=True)
