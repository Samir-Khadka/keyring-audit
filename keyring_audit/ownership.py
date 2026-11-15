"""Owner mapping (Keyring Audit v0.5, Phase 3).

Every finding gets an owner: a person or team responsible for the
credential, or "no owner" when none can be found. Sources, in order:

1. Cloud tags — for an AWS finding whose key can read IAM, the
   `ListUserTags` call in the validity check looks for Owner/Team tags.
   Attached during validation, while the secret is available; applied
   over the other sources afterwards (the tag names who owns the IAM
   user, which is who can rotate the key).
2. Commit author — the finding's commit (who introduced the secret).
3. git blame — for working-tree / staged findings, who last touched
   the line. For an uncommitted line, git blame names the local git
   user ("Not Committed Yet"), which is the person with the change.
4. None — "no owner", which is itself a risk factor (10 points in the
   score), not a missing field.

An owner is {"name": ..., "source": "aws-tag" | "commit" | "blame"}
or {"name": None, "source": "none"}.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True, timeout=60)


def _format_owner(name: str | None, email: str | None) -> str | None:
    name = (name or "").strip()
    email = (email or "").strip()
    if not name and not email:
        return None
    if email and email not in ("<not.committed.yet>",):
        return f"{name} <{email}>" if name else email
    return name or None


def owner_from_blame(root: Path, source: str,
                     line_no: int | None) -> dict | None:
    """Who last touched this line, via git blame. Returns an owner dict
    or None. For an uncommitted line, blame names the local git user;
    for a file git cannot blame at all (untracked), the local git user
    is the fallback — they hold the working tree. No local user
    configured means no owner."""
    if not line_no:
        return None
    blame = _git(["blame", "-L", f"{line_no},{line_no}", "--porcelain",
                  "--", source], root)
    if blame.returncode == 0:
        author = email = None
        for raw in blame.stdout.splitlines():
            if raw.startswith("author "):
                author = raw[len("author "):]
            elif raw.startswith("author-mail "):
                email = raw[len("author-mail "):].strip("<>")
            if author is not None and email is not None:
                break
        if author and author != "Not Committed Yet":
            owner = _format_owner(author, email)
            return {"name": owner, "source": "blame"} if owner else None
    # Uncommitted line, or a file git cannot blame: the local user.
    name = _git(["config", "user.name"], root).stdout.strip()
    mail = _git(["config", "user.email"], root).stdout.strip()
    owner = _format_owner(name or None, mail or None)
    return {"name": owner, "source": "blame"} if owner else None


def assign_owner(finding: dict, root: Path) -> dict:
    """Attach an owner to one finding, from commit author or blame.
    Cloud-tag owners (from the validity check) are applied afterwards
    by apply_tag_owner — they win because they name who can rotate it."""
    out = dict(finding)
    author = finding.get("author")
    if author:
        out["owner"] = {"name": author, "source": "commit"}
        return out
    blame = owner_from_blame(root, finding["source"], finding.get("line"))
    if blame:
        out["owner"] = blame
        return out
    out["owner"] = {"name": None, "source": "none"}
    return out


def assign_owners(findings: list[dict], root: Path) -> list[dict]:
    """Attach owners to every finding in a scan."""
    return [assign_owner(f, root) for f in findings]


def apply_tag_owner(finding: dict) -> dict:
    """If the validity check found an owner in cloud tags, it wins over
    the commit author / blame owner."""
    tag_owner = finding.get("validity", {}).get("owner")
    if tag_owner:
        out = dict(finding)
        out["owner"] = tag_owner
        return out
    return finding
