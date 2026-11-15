"""Revoke / rotate guides (Keyring Audit v0.1).

The MVP does not rotate anything itself — that is Phase 4, and it needs
dry runs and approvals. What v0.1 does is tell the owner exactly what to
do, in order, with the exact commands or links. A guide is honest about
what the tool cannot do: GitHub cannot create a PAT via the API, so the
guide says to create the replacement in the web UI.
"""
from __future__ import annotations


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
