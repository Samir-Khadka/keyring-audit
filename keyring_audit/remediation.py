"""Safe remediation (Keyring Audit v0.6, Phase 4).

v0.1–v0.5 only told the owner what to do (`guide()` below). v0.6
executes the AWS two-key rollover, with dry runs and approvals:
`rotate` prints the plan and changes nothing; `--execute` performs
the first half (create + verify the new key) only with the explicit
`--approve` flag; `--complete` deletes the old key only after the
user has deployed the new one; `--verify` re-checks the old
credential afterwards.

The safety contract (plan §4.5):
- Never store a secret. The old secret is read from the terminal and
  used once, in memory. The new secret is printed once by AWS and
  shown to the user; it is never written to a file, a log, or a report.
- A credential used in the last 24 hours is a "rotate with care"
  candidate: the plan says so loudly, and --execute still requires
  the explicit --approve flag.
- Verify nothing broke: --complete checks the old key is gone from
  the user's key list, and --verify re-checks last-used against the
  rotation time — any use after rotation means something still holds
  the old key.
- Only AWS has a create/delete API usable from the CLI. GitHub, Slack,
  GitLab and Stripe tokens are rotated in the provider's web UI; the
  tool gives the exact manual steps and --verify confirms the old
  token is dead afterwards. It never pretends to automate what it
  cannot.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import aws_sign
from .validity import (
    check_aws,
    check_github,
    check_gitlab,
    check_slack,
    check_stripe,
)

CARE_WINDOW = timedelta(hours=24)


def _parse_time(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def rotate_with_care(finding: dict) -> bool:
    """True when the credential was used in the last 24 hours — a
    "rotate with care" candidate (plan §4.4)."""
    last_used = _parse_time(finding.get("validity", {}).get("last_used"))
    if not last_used:
        return False
    return datetime.now(timezone.utc) - last_used < CARE_WINDOW


def iam_user_name(finding: dict) -> str | None:
    """The IAM user name from the validity identity ARN, or None for
    an assumed role / federated principal (which has no access keys)."""
    arn = finding.get("validity", {}).get("identity", {}).get("arn", "")
    if ":user/" in arn:
        parts = arn.split("/")
        return parts[1] if len(parts) > 1 else None
    return None


def build_plan(finding: dict) -> dict:
    """The remediation plan for one finding. A dry run: nothing here
    changes anything."""
    provider = finding.get("provider")
    validity = finding.get("validity", {})
    live = validity.get("live")
    owner = (finding.get("owner") or {}).get("name")
    care = rotate_with_care(finding)
    automated = (provider == "aws" and live == "live"
                 and iam_user_name(finding) is not None)
    warnings: list[str] = []
    if care:
        warnings.append("ROTATE WITH CARE — this credential was used in "
                        "the last 24 hours. Check what called it before "
                        "rotating (CloudTrail for AWS), and have the owner "
                        "ready to update every caller.")
    if live == "live":
        warnings.append("Never delete the old credential before the new "
                        "one is verified and deployed — two-key rollover, "
                        "not delete-first.")
    if provider == "aws" and live == "live":
        warnings.append("Check CloudTrail for the key's recent callers "
                        "before rotating, so the owner knows what to update.")
    if automated:
        user = iam_user_name(finding)
        steps = [
            "Create a new access key for the IAM user (the old key stays "
            f"live): aws iam create-access-key --user-name {user}",
            "Verify the new key: it must answer sts:GetCallerIdentity. "
            "The new secret is shown ONCE — save it now.",
            "Update every application and config that uses the old key "
            "to the new key, and confirm it works.",
            "Delete the old key only after the new one is deployed: "
            "aws iam delete-access-key --user-name "
            f"{user} --access-key-id <OLD-KEY-ID>",
            "Verify the old key is dead: it must no longer answer "
            "sts:GetCallerIdentity, and its last-used time must not "
            "move after the rotation.",
        ]
    elif provider == "aws":
        steps = [
            "This key is dead or is an assumed-role credential, so there "
            "is no rollover to perform.",
            "Delete the key from the AWS console (IAM → Users → "
            "Security credentials) if it still exists.",
            "Remove the value from the repo and its history — a dead key "
            "in history is still a leak to clean up.",
        ]
    elif provider == "github":
        steps = [
            "Revoke the old token at github.com → Settings → Developer "
            "settings → Personal access tokens.",
            "Create a new fine-grained token with the same scopes "
            "(GitHub has no API for this — it is a web-UI step).",
            "Update every application and config that uses the old token.",
            "Verify the old token is dead: keyring-audit rotate "
            "--fingerprint <fp> --verify (paste the old token when asked).",
            "Remove the value from the repo and its history.",
        ]
    elif provider == "slack":
        steps = [
            "Revoke the old token in the Slack app settings "
            "(api.slack.com → your app → OAuth & Permissions) or with "
            "auth.revoke.",
            "Install a new token with the same scopes and update every "
            "application that uses the old one.",
            "Verify the old token is dead with rotate --verify.",
            "Remove the value from the repo and its history.",
        ]
    elif provider == "gitlab":
        steps = [
            "Revoke the old token at GitLab → Preferences → Access "
            "Tokens (or the group/project token settings).",
            "Create a new token with the same scopes and update every "
            "application that uses the old one.",
            "Verify the old token is dead with rotate --verify.",
            "Remove the value from the repo and its history.",
        ]
    elif provider == "stripe":
        steps = [
            "Roll the key in the Stripe Dashboard → Developers → API "
            "keys (Stripe has no API to create a secret key).",
            "Update every application that uses the old key, and "
            "confirm charges still work.",
            "Verify the old key is dead with rotate --verify.",
            "Remove the value from the repo and its history.",
        ]
    else:
        steps = [
            "This provider has no automated rotation. Revoke the "
            "credential at the provider, create a replacement, update "
            "every caller, then remove the value from the repo.",
        ]
    return {"fingerprint": finding.get("fingerprint"),
            "provider": provider, "redacted": finding.get("redacted"),
            "live": live, "owner": owner, "rotate_with_care": care,
            "automated": automated, "steps": steps, "warnings": warnings}


def render_plan(plan: dict, fmt: str = "text") -> str:
    """Render a plan. Text for the terminal, md for handing to the
    owner, json for scripting."""
    if fmt == "json":
        return json.dumps(plan, indent=2)
    if fmt == "md":
        lines = [f"# Rotation plan — {plan['redacted']} "
                 f"({plan['provider']})", "",
                 f"- Live: {plan['live']}",
                 f"- Owner: {plan['owner'] or 'none found'}",
                 "- Automated (AWS rollover): "
                 + ("yes" if plan["automated"]
                    else "no — manual steps")]
        for w in plan["warnings"]:
            lines.append(f"- ⚠️ {w}")
        lines.append("")
        for i, s in enumerate(plan["steps"], 1):
            lines.append(f"{i}. {s}")
        return "\n".join(lines) + "\n"
    lines = [f"Rotation plan — {plan['redacted']} ({plan['provider']})",
             f"  live: {plan['live']}",
             f"  owner: {plan['owner'] or 'none found'}",
             "  automated: "
             + ("yes — AWS two-key rollover" if plan["automated"]
                else "no — manual steps")]
    for w in plan["warnings"]:
        lines.append(f"  ⚠️ {w}")
    for i, s in enumerate(plan["steps"], 1):
        lines.append(f"  {i}. {s}")
    return "\n".join(lines) + "\n"


def execute_aws_rollover(finding: dict, old_key_id: str,
                         old_secret: str) -> dict:
    """First half of the rollover: create a new key and verify it
    works. The old key is NOT touched. Returns the new key id and
    secret — the caller shows the secret to the user ONCE and never
    stores it."""
    user = iam_user_name(finding)
    if not user:
        raise ValueError("not an IAM user — access keys cannot be "
                         "created for an assumed role")
    new = aws_sign.create_access_key(old_key_id, old_secret, user)
    identity = aws_sign.sts_get_caller_identity(new["key_id"],
                                                new["secret"])
    return {"new_key_id": new["key_id"], "new_secret": new["secret"],
            "new_identity": identity}


def complete_aws_rollover(finding: dict, old_key_id: str, new_key_id: str,
                          new_secret: str) -> dict:
    """Second half: delete the old key with the new key's credentials,
    then confirm it is gone from the user's key list."""
    user = iam_user_name(finding)
    if not user:
        raise ValueError("not an IAM user — nothing to delete")
    aws_sign.delete_access_key(new_key_id, new_secret, user, old_key_id)
    remaining = aws_sign.list_access_keys(new_key_id, new_secret, user)
    if old_key_id in remaining:
        return {"deleted": False, "verified_gone": False,
                "reason": "the old key is still listed after the delete "
                          "— delete it from the AWS console"}
    return {"deleted": True, "verified_gone": True, "reason": None}


def verify_old_credential(finding: dict, value: str,
                          old_key_id: str | None = None,
                          rotated_at: str | None = None) -> dict:
    """Re-check the old credential after rotation. Returns whether it
    is dead, and — for AWS — whether it was used after the rotation
    time (any use after rotation means something still holds it)."""
    provider = finding.get("provider")
    if provider == "aws":
        if not old_key_id:
            raise ValueError("AWS verification needs --old-key-id")
        result = check_aws(old_key_id, value)
    elif provider == "github":
        result = check_github(value)
    elif provider == "slack":
        result = check_slack(value)
    elif provider == "gitlab":
        result = check_gitlab(value)
    elif provider == "stripe":
        result = check_stripe(value)
    else:
        return {"dead": None,
                "reason": f"cannot verify {provider} credentials"}
    dead = result.get("live") == "dead"
    out: dict = {"dead": dead, "live": result.get("live"),
                 "reason": result.get("reason")}
    if provider == "aws" and rotated_at:
        last_used = _parse_time(result.get("last_used"))
        rotated = _parse_time(rotated_at)
        if last_used and rotated and last_used > rotated:
            out["used_after_rotation"] = True
            out["last_used"] = result.get("last_used")
        else:
            out["used_after_rotation"] = False
            out["last_used"] = result.get("last_used")
    return out


def guide(finding: dict) -> list[str]:
    """Ordered steps to revoke or rotate this credential."""
    provider = finding["provider"]
    validity = finding.get("validity", {})
    live = validity.get("live")
    safe = finding.get("risk", {}).get("safe_to_kill", False)
    if live == "dead":
        return ["Already dead — no rotation needed. Remove it from the code "
                "and from git history (git filter-repo or BFG) so it stops "
                "appearing in scans."]
    if provider == "github":
        steps = [
            "1. Revoke the token: https://github.com/settings/tokens "
            "(classic) or https://github.com/settings/tokens?type=beta "
            "(fine-grained).",
            "2. Create a replacement as a fine-grained PAT, scoped to only "
            "the repositories it needs, with an expiry date.",
            "3. Update every place that used the old token, then re-run "
            "`keyring-audit scan` to confirm the old value is gone.",
        ]
        if safe:
            steps.insert(0, "Safe to kill: this credential has not been used "
                            "recently. Revoke it now.")
        return steps
    if provider == "aws":
        key_id = finding.get("key_id", "<KEY_ID>")
        steps = [
            "1. Create a replacement key (two-key rollover — never delete "
            "first):",
            f"   aws iam create-access-key --user-name <USER>",
            "2. Update the application to use the new key, and confirm it "
            "works.",
            "3. Delete the old key:",
            f"   aws iam delete-access-key --user-name <USER> "
            f"--access-key-id {key_id}",
            "4. Re-run `keyring-audit scan` to confirm the old key is gone.",
        ]
        if safe:
            steps.insert(0, "Safe to kill: this key has not been used "
                            "recently. Delete it after confirming nothing "
                            "references it.")
        return steps
    if provider == "slack":
        return [
            "1. Revoke the token in Slack: https://api.slack.com/apps → your "
            "app → OAuth & Permissions → Revoke Token.",
            "2. Create a replacement token and update every place that used "
            "the old one.",
        ]
    if provider == "gitlab":
        return [
            "1. Revoke the token: GitLab → Preferences → Access Tokens → "
            "Revoke.",
            "2. Create a replacement with the minimum scopes, and update "
            "every place that used the old one.",
        ]
    if provider == "stripe":
        return [
            "1. Roll the key in the Stripe Dashboard → Developers → API "
            "keys → Roll key.",
            "2. Update every place that used the old key.",
        ]
    return [
        "1. Revoke this credential at the provider, and replace it with a "
        "new one with the minimum permissions.",
        "2. Update every place that used the old value, then re-run the scan.",
    ]
