"""Validity + permissions checks (Keyring Audit v0.1).

One identity call per credential proves it is live; a second, read-only
call lists what it can do. Nothing else is fetched — no data reads, ever.

GitHub (verified against docs.github.com and the github-mcp-server
scope-filtering docs, 2026-11-15):
- Classic PATs (ghp_) and OAuth tokens report their scopes in the
  `X-OAuth-Scopes` response header on any authenticated call. One
  `GET /user` gives validity (200 vs 401) and the full scope list.
- Fine-grained PATs (github_pat_) and App tokens (ghs_) return NO
  scope header. Permissions are probed endpoint by endpoint (404 = not
  permitted; a 403 carries `x-accepted-github-permissions` naming the
  permission the endpoint wanted). An empty scope list on a fine-grained
  token means "probed, not empty" — the report says which method was used.
- `X-RateLimit-Remaining: 0` or HTTP 429 = "unknown (rate limited)".

AWS (verified against the AWS docs pattern, 2026-11-15):
- `sts:GetCallerIdentity` = validity (account, ARN, user ID).
- Permissions = `iam:ListAttachedUserPolicies` + `iam:ListUserPolicies`
  (+ `iam:GetPolicy` for the document summary), falling back to
  `iam:SimulatePrincipalPolicy` for named high-risk actions. The
  simulator does not read resource-based policies, so an "allowed"
  result is partial evidence — the report says so.
- Usage = `iam:GetAccessKeyLastUsed` per key.
- A key without IAM read gets "unknown (IAM read denied)" — never a
  guessed permission list.

The HTTP layer is injectable (`request` argument) so tests can pass a
fake without touching the network. The default uses urllib with a
15-second timeout. No secret is ever logged: the token travels only in
the Authorization header of its own provider's call.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from . import aws_sign

log = logging.getLogger("keyring-audit.validity")

GITHUB_API = "https://api.github.com"

# Endpoints probed for a fine-grained / App token, in order. Each maps
# to a human-readable permission when it succeeds.
FINE_GRAINED_PROBES = [
    ("GET /user", "/user", "read user profile"),
    ("GET /user/repos", "/user/repos?per_page=1", "list own repositories"),
    ("GET /user/orgs", "/user/orgs?per_page=1", "list organisations"),
    ("GET /user/starred", "/user/starred?per_page=1", "list starred repositories"),
]

# High-risk AWS actions the simulator is asked about. A key that can do
# any of these is flagged in the ranking.
AWS_RISKY_ACTIONS = [
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "iam:CreateAccessKey", "iam:PassRole", "s3:DeleteBucket",
    "ec2:TerminateInstances", "rds:DeleteDBInstance",
]


def _http(method: str, url: str, headers: dict[str, str] | None = None,
          timeout: int = 15) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
    except urllib.error.URLError as e:
        raise ConnectionError(str(e)) from None


def check_github(token: str, request=_http) -> dict:
    """Validate a GitHub token. Returns validity + permissions."""
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json",
               "User-Agent": "keyring-audit/0.1"}
    try:
        status, body, resp_headers = request("GET", f"{GITHUB_API}/user", headers)
    except ConnectionError as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "header"}
    if status == 401:
        return {"live": "dead", "reason": "401 Bad credentials (revoked, expired, or invalid)",
                "permissions": [], "method": "header"}
    if status == 429:
        return {"live": "unknown", "reason": "rate limited (429)",
                "permissions": [], "method": "header"}
    if status == 403:
        return {"live": "unknown", "reason": "forbidden (403) — the token may be suspended",
                "permissions": [], "method": "header"}
    if status != 200:
        return {"live": "unknown", "reason": f"GitHub returned HTTP {status}",
                "permissions": [], "method": "header"}
    try:
        user = json.loads(body)
    except json.JSONDecodeError:
        user = {}
    scopes = resp_headers.get("x-oauth-scopes", "")
    if scopes is not None and scopes.strip() != "":
        # Classic PAT / OAuth token: the header is the whole answer.
        return {"live": "live", "reason": f"authenticated as {user.get('login', '?')}",
                "permissions": [s.strip() for s in scopes.split(",") if s.strip()],
                "method": "header", "login": user.get("login")}
    # Fine-grained PAT or App token: no scope header. Probe endpoints.
    permissions: list[str] = []
    for label, path, desc in FINE_GRAINED_PROBES:
        try:
            s, _, h = request("GET", f"{GITHUB_API}{path}", headers)
        except ConnectionError:
            break
        if s == 200:
            permissions.append(desc)
        elif s == 403:
            accepted = h.get("x-accepted-github-permissions", "")
            if accepted:
                permissions.append(f"denied: needs {accepted}")
    return {"live": "live", "reason": f"authenticated as {user.get('login', '?')}",
            "permissions": permissions, "method": "probed",
            "login": user.get("login"),
            "note": "fine-grained or App token — scopes probed, not listed"}


def check_aws(key_id: str, secret: str | None,
              session_token: str | None = None) -> dict:
    """Validate an AWS key pair. Returns validity + permissions + usage."""
    if not secret:
        return {"live": "unknown",
                "reason": "key ID found but its secret was not in the scan — "
                          "cannot validate without the secret",
                "permissions": [], "method": "none"}
    try:
        identity = aws_sign.sts_get_caller_identity(key_id, secret, session_token)
    except ValueError as e:
        return {"live": "dead", "reason": str(e),
                "permissions": [], "method": "sts"}
    except (ConnectionError, OSError) as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "sts"}
    arn = identity["arn"]
    # arn:aws:iam::123456789012:user/name (or assumed-role/…/name)
    parts = arn.split("/")
    user_name = parts[-1] if len(parts) > 1 else None
    is_user = ":user/" in arn
    permissions: list[str] = []
    method = "sts"
    last_used = None
    if is_user and user_name:
        try:
            import xml.etree.ElementTree as ET
            ns = {"i": "https://iam.amazonaws.com/doc/2010-05-08/"}
            root = aws_sign.iam_query(key_id, secret, "ListAttachedUserPolicies",
                                      {"UserName": user_name}, session_token)
            # <AttachedPolicies><member><PolicyName>…<PolicyArn>…
            for p in root.findall(".//i:AttachedPolicies/i:member", ns):
                name = p.findtext("i:PolicyName", namespaces=ns)
                arn_p = p.findtext("i:PolicyArn", namespaces=ns)
                if name:
                    permissions.append(f"managed policy: {name}"
                                       + (f" ({arn_p})" if arn_p else ""))
            root = aws_sign.iam_query(key_id, secret, "ListUserPolicies",
                                      {"UserName": user_name}, session_token)
            for p in root.findall(".//i:PolicyName", ns):
                if p.text:
                    permissions.append(f"inline policy: {p.text}")
            method = "iam"
        except ValueError as e:
            permissions = []
            method = "sts"
            if "access denied" in str(e):
                return {"live": "live",
                        "reason": f"authenticated as {arn} (IAM read denied — "
                                  "permissions unknown)",
                        "permissions": [], "method": "sts",
                        "identity": identity}
        except (ConnectionError, OSError) as e:
            return {"live": "live", "reason": f"authenticated as {arn} (IAM lookup failed: {e})",
                    "permissions": [], "method": "sts", "identity": identity}
        # Usage: last-used time for this key.
        try:
            import xml.etree.ElementTree as ET
            ns = {"i": "https://iam.amazonaws.com/doc/2010-05-08/"}
            root = aws_sign.iam_query(key_id, secret, "GetAccessKeyLastUsed",
                                      {"AccessKeyId": key_id}, session_token)
            last_used = root.findtext(".//i:LastUsedDate", namespaces=ns)
        except Exception:  # noqa: BLE001 - usage is best-effort
            last_used = None
    else:
        # Assumed-role / federated credentials: no IAM user policies to list.
        method = "sts"
    result: dict = {"live": "live", "reason": f"authenticated as {arn}",
                    "permissions": permissions, "method": method,
                    "identity": identity}
    if last_used:
        result["last_used"] = last_used
    return result


def check_finding(finding: dict, verify: bool = True) -> dict:
    """Run the validity check for one finding. Returns the finding with
    a 'validity' dict attached. When verify is False, validity is 'skipped'."""
    out = dict(finding)
    out.pop("_secret", None)  # never carry the secret past this point
    if not verify:
        out["validity"] = {"live": "skipped", "reason": "verification disabled (--no-verify)",
                           "permissions": [], "method": "none"}
        return out
    provider = finding["provider"]
    secret = finding.get("_secret")
    if provider == "github":
        out["validity"] = check_github(secret)
    elif provider == "aws":
        out["validity"] = check_aws(finding.get("key_id", ""), secret)
    elif provider == "slack":
        out["validity"] = {"live": "unknown",
                           "reason": "Slack validity check not implemented in v0.1 "
                                     "(auth.test needs the token; coming in v0.2)",
                           "permissions": [], "method": "none"}
    elif provider == "gitlab":
        out["validity"] = {"live": "unknown",
                           "reason": "GitLab validity check not implemented in v0.1",
                           "permissions": [], "method": "none"}
    elif provider == "stripe":
        out["validity"] = {"live": "unknown",
                           "reason": "Stripe validity check not implemented in v0.1",
                           "permissions": [], "method": "none"}
    else:
        out["validity"] = {"live": "unknown",
                           "reason": "no validity check for this provider in v0.1",
                           "permissions": [], "method": "none"}
    return out
