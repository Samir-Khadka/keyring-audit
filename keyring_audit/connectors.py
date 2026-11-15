"""Slack and GitLab connectors (Keyring Audit v1.4, Phase 6 coverage).

The last Phase 6 piece: enumerate the non-human identities that live
*inside* a Slack workspace or a GitLab instance, rather than a single
token found in code.

- GitLab: given a personal access token, list the groups and projects
  it can maintain, then the group access tokens, project access tokens
  and deploy tokens in each. Each token is reported with its name,
  scopes, expiry and revoked status, and ranked with the shared
  scoring (privilege from scopes, exposure from "in GitLab", age from
  creation, usage from last-used when the API reports it). A token
  with no expiry is flagged — it is a sprawl risk, not a feature.
- Slack: given a token, identify it (auth.test — workspace, bot or
  user) and list the installed apps (apps.list — name, id, whether it
  is a bot). Slack never returns an app's token, so the report names
  the apps and says the token itself cannot be listed — check each
  app's token in the Slack app settings.

Honest limits, stated in the report:
- GitLab never returns a token's VALUE after creation, so the report
  lists the tokens, not their secrets. A token the API says is revoked
  or expired is dead; anything else is live. The caller needs
  Maintainer (40) or higher on a group or project to list its tokens —
  a token that cannot see a group simply does not report it, and the
  report says how many groups and projects were visible.
- Slack's apps.list needs the apps:read scope (a user token scope).
  A bot token usually does not have it, so the report falls back to
  the auth.test identity and says the apps could not be listed.
  admin.apps.approved.list is Enterprise-only and is not used.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .cloud import _opener

GITLAB_DEFAULT_HOST = "https://gitlab.com"


def _request(method: str, url: str, headers: dict,
             body: dict | None = None) -> dict:
    """One JSON request. Returns the parsed body. Raises ValueError
    with the HTTP status on a non-2xx response."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers)
    try:
        with _opener().open(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ValueError(f"network error: {e}") from e


def _paged_get(base: str, headers: dict, params: dict | None = None) -> list:
    """GET a paginated list endpoint (?page=N&per_page=100), following
    pages until one returns fewer than 100 items."""
    out: list = []
    page = 1
    while True:
        q = dict(params or {})
        q.update({"page": page, "per_page": 100})
        url = base + "?" + urllib.parse.urlencode(q)
        batch = _request("GET", url, headers)
        if not isinstance(batch, list):
            raise ValueError("expected a list from " + base)
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


# ---------------------------------------------------------------- GitLab

def _gitlab_token_state(tok: dict) -> tuple[str, str]:
    """(live, reason) from a GitLab access/deploy token record."""
    if tok.get("revoked"):
        return "dead", "revoked in GitLab"
    expires = tok.get("expires_at")
    if expires:
        try:
            exp = time.mktime(time.strptime(expires, "%Y-%m-%d"))
            if exp < time.time():
                return "dead", f"expired on {expires}"
        except ValueError:
            pass
    if not expires:
        return "live", "live, and it never expires — a sprawl risk"
    return "live", f"live, expires {expires}"


def _gitlab_finding(kind: str, tok: dict, owner_name: str) -> dict:
    """A finding-shaped dict for a GitLab access or deploy token, so
    the shared ranking can score it."""
    live, reason = _gitlab_token_state(tok)
    scopes = tok.get("scopes", []) or []
    date = None
    created = tok.get("created_at")
    if created:
        try:
            date = int(time.mktime(
                time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")))
        except ValueError:
            date = None
    last_used = None
    lu = tok.get("last_used_at")
    if lu:
        try:
            last_used = int(time.mktime(
                time.strptime(lu[:19], "%Y-%m-%dT%H:%M:%S")))
        except ValueError:
            last_used = None
    return {"detector": kind, "provider": "gitlab",
            "redacted": tok.get("name", f"token {tok.get('id')}"),
            "fingerprint": f"gitlab:{kind}:{tok.get('id')}",
            "source": f"GitLab — {owner_name}", "line": None,
            "commit": None, "author": None, "date": date,
            "owner": {"name": owner_name, "source": "gitlab"},
            "exposure_source": "gitlab-platform",
            "validity": {"live": live, "reason": reason,
                         "permissions": scopes,
                         "method": "gitlab-api", "last_used": last_used},
            "scopes": scopes, "expires_at": tok.get("expires_at"),
            "revoked": bool(tok.get("revoked"))}


def gitlab_connectors(token: str, host: str = GITLAB_DEFAULT_HOST) -> dict:
    """Enumerate the access and deploy tokens visible to a GitLab
    personal access token. Returns {identity, groups, projects,
    findings, warnings}."""
    host = host.rstrip("/")
    headers = {"PRIVATE-TOKEN": token}
    api = host + "/api/v4"
    warnings: list[str] = []
    try:
        me = _request("GET", api + "/user", headers)
    except ValueError as e:
        raise ValueError(f"GitLab rejected the token ({e})") from e
    identity = {"username": me.get("username"), "name": me.get("name")}
    groups = _paged_get(api + "/groups", headers,
                        {"min_access_level": 40})
    projects = _paged_get(api + "/projects", headers,
                          {"membership": "true", "min_access_level": 40})
    findings: list[dict] = []
    for g in groups:
        gid = g["id"]
        gname = g.get("full_path", f"group {gid}")
        for kind, path in (("gitlab-group-access-token",
                            f"/groups/{gid}/access_tokens"),
                           ("gitlab-group-deploy-token",
                            f"/groups/{gid}/deploy_tokens")):
            try:
                toks = _paged_get(api + path, headers)
            except ValueError as e:
                warnings.append(f"could not list {kind} for {gname} ({e})")
                continue
            findings.extend(_gitlab_finding(kind, t, gname) for t in toks)
    for p in projects:
        pid = p["id"]
        pname = p.get("path_with_namespace", f"project {pid}")
        for kind, path in (("gitlab-project-access-token",
                            f"/projects/{pid}/access_tokens"),
                           ("gitlab-project-deploy-token",
                            f"/projects/{pid}/deploy_tokens")):
            try:
                toks = _paged_get(api + path, headers)
            except ValueError as e:
                warnings.append(f"could not list {kind} for {pname} ({e})")
                continue
            findings.extend(_gitlab_finding(kind, t, pname) for t in toks)
    return {"identity": identity, "groups": len(groups),
            "projects": len(projects), "findings": findings,
            "warnings": warnings}


# ---------------------------------------------------------------- Slack

def slack_connectors(token: str) -> dict:
    """Identify a Slack token and list the workspace's installed apps.
    Returns {identity, apps, apps_error}."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        auth = _request("POST", "https://slack.com/api/auth.test",
                        headers)
    except ValueError as e:
        raise ValueError(f"Slack rejected the token ({e})") from e
    if not auth.get("ok"):
        raise ValueError(f"Slack rejected the token ({auth.get('error')})")
    identity = {"team": auth.get("team"), "user": auth.get("user"),
                "bot_id": auth.get("bot_id"),
                "url": auth.get("url")}
    apps: list[dict] = []
    apps_error: str | None = None
    try:
        doc = _request("GET", "https://slack.com/api/apps.list", headers)
    except ValueError as e:
        apps_error = str(e)
        doc = {"ok": False, "error": apps_error}
    if doc.get("ok"):
        for a in doc.get("apps", []) or []:
            apps.append({"id": a.get("id"), "name": a.get("name"),
                         "is_bot": bool(a.get("is_bot") or a.get("bot_id")),
                         "scopes": a.get("scopes", []) or []})
    else:
        err = doc.get("error", apps_error or "unknown")
        if err == "missing_scope":
            apps_error = ("the token lacks the apps:read scope, so the "
                          "installed apps could not be listed")
        else:
            apps_error = f"apps.list failed: {err}"
    return {"identity": identity, "apps": apps, "apps_error": apps_error}


def render_connectors(result: dict, kind: str, fmt: str) -> str:
    """Render a connectors result as text, Markdown or JSON."""
    if fmt == "json":
        return json.dumps(result, indent=2, default=str)
    if kind == "gitlab":
        lines = [f"# GitLab tokens — {result['identity'].get('username')}"]
        lines.append("")
        lines.append(f"{result['groups']} group(s), {result['projects']} "
                     f"project(s) visible to this token.")
        if result["warnings"]:
            lines.append("")
            for w in result["warnings"]:
                lines.append(f"warning: {w}")
        findings = result["findings"]
        lines.append("")
        lines.append(f"{len(findings)} token(s) found.")
        for f in findings:
            v = f["validity"]
            lines.append("")
            lines.append(f"- {f['detector']} — {f['redacted']} "
                         f"({f['source']})")
            lines.append(f"  scopes: {', '.join(f['scopes']) or 'none'}; "
                         f"expires: {f['expires_at'] or 'never'}; "
                         f"validity: {v['live']} — {v['reason']}")
            if f.get("risk"):
                lines.append(f"  risk: {f['risk']['score']} "
                             f"({f['risk']['band']})")
        if fmt == "md":
            return "\n".join(lines)
        # text: drop the Markdown heading.
        lines[0] = f"GitLab tokens — {result['identity'].get('username')}"
        return "\n".join(lines)
    # Slack.
    ident = result["identity"]
    who = ident.get("user") or ident.get("bot_id") or "unknown"
    lines = [f"# Slack apps — {ident.get('team')} (as {who})", ""]
    if result["apps_error"]:
        lines.append(f"note: {result['apps_error']}")
        lines.append("")
    lines.append(f"{len(result['apps'])} installed app(s).")
    for a in result["apps"]:
        lines.append(f"- {a['name']} ({a['id']})"
                     + (" — bot" if a["is_bot"] else ""))
    lines.append("")
    lines.append("Slack never returns an app's token, so the token itself "
                 "cannot be listed — check each app's token in the Slack "
                 "app settings.")
    if fmt == "md":
        return "\n".join(lines)
    lines[0] = f"Slack apps — {ident.get('team')} (as {who})"
    return "\n".join(lines)
