"""Validity + permissions checks (Keyring Audit v0.5).

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
- Blast radius (v0.4): `iam:SimulatePrincipalPolicy` is called for the
  8 named high-risk actions (AWS_RISKY_ACTIONS) right after the
  identity call, for every principal type, so a key that cannot read
  IAM still gets its blast radius measured when simulation is allowed.
  The result is a `blast_radius` dict (method "simulate" with allowed /
  denied lists, or method "none" with the reason) and "simulated: can
  <action>" permission entries. The ranking scores a simulated
  privilege-escalation action at 40 — a key that can escalate is
  effectively admin, whatever its policy names say.

Slack (verified against Slack's OAuth docs, 2026-11-15):
- `POST /api/auth.test` = validity. Slack returns HTTP 200 even for a
  bad token, so the `ok` field decides: `ok: true` = live,
  `ok: false, error: invalid_auth` = dead.
- Every Web API response carries an `X-OAuth-Scopes` header listing the
  token's granted scopes — the permissions list. 429 = rate limited.

GitLab (verified against GitLab's API docs, 2026-11-15):
- `GET /api/v4/personal_access_tokens/self` = validity + permissions in
  one call: `scopes` (array), `active`, `revoked`, `expires_at`.
  Introduced in GitLab 15.5; verified on gitlab.com.
- Fallback for tokens the self endpoint cannot describe (group/project
  tokens, older GitLab): `GET /api/v4/user` — 200 = live, 401 = dead,
  scopes unlisted (the report says so).

Stripe (verified 2026-11-15):
- `GET /v1/account` = validity (the identity call). 200 = live, with
  the account id + livemode. 401 "Invalid API Key provided" = dead.
- 403 after authentication = the key is live but restricted and cannot
  read the account — reported as live, restricted. Stripe exposes no
  permissions list for a key via the API, so the report says the key
  type (full secret key vs restricted key) instead of inventing one.
- Auth is HTTP Basic (key as username) or Bearer; Basic is used here.

The HTTP layer is injectable (`request` argument) so tests can pass a
fake without touching the network. The default uses urllib with a
15-second timeout. No secret is ever logged: the token travels only in
the Authorization header of its own provider's call.
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request

from . import __version__, aws_sign

log = logging.getLogger("keyring-audit.validity")

USER_AGENT = f"keyring-audit/{__version__}"

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
    except (TimeoutError, OSError) as e:
        # A raw socket timeout escapes urlopen unwrapped — treat it like
        # any other network failure so a scan degrades to "unknown"
        # instead of crashing on one unreachable provider.
        raise ConnectionError(str(e)) from None


def check_github(token: str, request=_http) -> dict:
    """Validate a GitHub token. Returns validity + permissions."""
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json",
               "User-Agent": USER_AGENT}
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
    # Blast radius: simulate the named high-risk actions for this
    # principal (one call for all of them). Runs for every principal
    # type, before the policy listing, so a key that cannot read IAM
    # still gets its blast radius measured when simulation is allowed.
    blast_radius: dict = {"method": "none",
                          "note": "simulation not attempted"}
    sim_permissions: list[str] = []
    try:
        sim = aws_sign.simulate_principal_policy(
            key_id, secret, arn, AWS_RISKY_ACTIONS, session_token)
        allowed = [e["action"] for e in sim if e["decision"] == "allowed"]
        denied = [e["action"] for e in sim if e["decision"] != "allowed"]
        blast_radius = {"method": "simulate", "allowed": allowed,
                        "denied": denied,
                        "note": "simulation does not read resource-based "
                                "policies — 'allowed' is partial evidence"}
        sim_permissions = [f"simulated: can {a}" for a in allowed]
    except ValueError:
        blast_radius = {"method": "none",
                        "note": "simulation not permitted "
                                "(iam:SimulatePrincipalPolicy denied)"}
    except (ConnectionError, OSError) as e:
        blast_radius = {"method": "none",
                        "note": f"simulation failed: {e}"}
    permissions: list[str] = []
    method = "sts"
    last_used = None
    tag_owner: dict | None = None
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
            if "access denied" in str(e):
                if sim_permissions:
                    return {"live": "live",
                            "reason": f"authenticated as {arn} (IAM read "
                                      "denied; simulation found "
                                      f"{len(sim_permissions)} high-risk "
                                      "action(s) allowed)",
                            "permissions": sim_permissions,
                            "method": "simulate", "identity": identity,
                            "blast_radius": blast_radius}
                return {"live": "live",
                        "reason": f"authenticated as {arn} (IAM read denied — "
                                  "permissions unknown)",
                        "permissions": [], "method": "sts",
                        "identity": identity, "blast_radius": blast_radius}
            permissions = []
            method = "sts"
        except (ConnectionError, OSError) as e:
            return {"live": "live", "reason": f"authenticated as {arn} (IAM lookup failed: {e})",
                    "permissions": sim_permissions,
                    "method": "simulate" if sim_permissions else "sts",
                    "identity": identity, "blast_radius": blast_radius}
        # Owner from cloud tags (best-effort — a missing tag is not an
        # error, and a key that cannot read IAM never gets here because
        # the listing above returns early). Applied over the commit
        # author / blame owner afterwards: the tag names who owns the
        # IAM user, which is who can rotate the key.
        try:
            import xml.etree.ElementTree as ET
            ns = {"i": "https://iam.amazonaws.com/doc/2010-05-08/"}
            root = aws_sign.iam_query(key_id, secret, "ListUserTags",
                                      {"UserName": user_name}, session_token)
            for tag in root.findall(".//i:TagList/i:member", ns):
                key = tag.findtext("i:Key", namespaces=ns) or ""
                value = tag.findtext("i:Value", namespaces=ns) or ""
                if key.lower() in ("owner", "team") and value:
                    tag_owner = {"name": value, "source": "aws-tag"}
                    break
        except Exception:  # noqa: BLE001 - tags are best-effort
            tag_owner = None
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
        method = "simulate" if sim_permissions else "sts"
    if method == "sts" and sim_permissions:
        # The policy listing failed but the simulation provided evidence.
        method = "simulate"
    result: dict = {"live": "live", "reason": f"authenticated as {arn}",
                    "permissions": permissions + sim_permissions,
                    "method": method,
                    "identity": identity, "blast_radius": blast_radius}
    if tag_owner:
        result["owner"] = tag_owner
    if last_used:
        result["last_used"] = last_used
    return result


def check_slack(token: str, request=_http) -> dict:
    """Validate a Slack token via auth.test. Returns validity + scopes.

    Slack returns HTTP 200 even for a bad token — the `ok` field is the
    verdict. Scopes come from the X-OAuth-Scopes response header, the
    same mechanism Slack's own docs describe.
    """
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": USER_AGENT}
    try:
        status, body, resp_headers = request(
            "POST", "https://slack.com/api/auth.test", headers)
    except ConnectionError as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "auth.test"}
    if status == 429:
        return {"live": "unknown", "reason": "rate limited (429)",
                "permissions": [], "method": "auth.test"}
    if status != 200:
        return {"live": "unknown", "reason": f"Slack returned HTTP {status}",
                "permissions": [], "method": "auth.test"}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {"live": "unknown", "reason": "Slack returned an unreadable response",
                "permissions": [], "method": "auth.test"}
    if not data.get("ok"):
        error = data.get("error", "unknown error")
        if error == "invalid_auth":
            return {"live": "dead",
                    "reason": "invalid_auth (revoked, expired, or invalid)",
                    "permissions": [], "method": "auth.test"}
        return {"live": "unknown", "reason": f"Slack error: {error}",
                "permissions": [], "method": "auth.test"}
    scopes = resp_headers.get("x-oauth-scopes", "") or ""
    permissions = [s.strip() for s in scopes.split(",") if s.strip()]
    return {"live": "live",
            "reason": f"authenticated as {data.get('user', '?')} "
                      f"in team {data.get('team', '?')}",
            "permissions": permissions, "method": "auth.test",
            "team": data.get("team"), "user": data.get("user")}


def check_gitlab(token: str, request=_http) -> dict:
    """Validate a GitLab token. Returns validity + scopes.

    Primary: GET /personal_access_tokens/self (GitLab 15.5+) returns the
    token's scopes, active flag, revoked flag and expiry in one call.
    Fallback for tokens it cannot describe (group/project tokens, older
    GitLab): GET /user — 200 = live, 401 = dead, scopes unlisted.
    """
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": USER_AGENT}
    try:
        status, body, _ = request(
            "GET", "https://gitlab.com/api/v4/personal_access_tokens/self",
            headers)
    except ConnectionError as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "self"}
    if status == 401:
        return {"live": "dead",
                "reason": "401 Unauthorized (revoked, expired, or invalid)",
                "permissions": [], "method": "self"}
    if status == 429:
        return {"live": "unknown", "reason": "rate limited (429)",
                "permissions": [], "method": "self"}
    if status == 200:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return {"live": "unknown",
                    "reason": "GitLab returned an unreadable response",
                    "permissions": [], "method": "self"}
        if data.get("revoked") or data.get("active") is False:
            return {"live": "dead", "reason": "token is revoked or inactive",
                    "permissions": [], "method": "self"}
        result: dict = {
            "live": "live",
            "reason": f"authenticated (token '{data.get('name', '?')}')",
            "permissions": list(data.get("scopes") or []),
            "method": "self"}
        if data.get("expires_at"):
            result["expires_at"] = data["expires_at"]
        return result
    if status not in (403, 404):
        return {"live": "unknown", "reason": f"GitLab returned HTTP {status}",
                "permissions": [], "method": "self"}
    # The self endpoint cannot describe this token — fall back to /user.
    try:
        s2, b2, _ = request("GET", "https://gitlab.com/api/v4/user", headers)
    except ConnectionError as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "user"}
    if s2 == 401:
        return {"live": "dead", "reason": "401 Unauthorized",
                "permissions": [], "method": "user"}
    if s2 == 429:
        return {"live": "unknown", "reason": "rate limited (429)",
                "permissions": [], "method": "user"}
    if s2 != 200:
        return {"live": "unknown", "reason": f"GitLab returned HTTP {s2}",
                "permissions": [], "method": "user"}
    try:
        user = json.loads(b2)
    except json.JSONDecodeError:
        user = {}
    return {"live": "live",
            "reason": f"authenticated as {user.get('username', '?')} "
                      "(scopes not listed — group/project token or older GitLab)",
            "permissions": [], "method": "user",
            "login": user.get("username")}


def check_stripe(key: str, request=_http) -> dict:
    """Validate a Stripe secret/restricted key via GET /v1/account.

    200 = live (account id + livemode). 401 "Invalid API Key provided"
    = dead. 403 after authentication = the key is live but restricted
    and cannot read the account. Stripe exposes no permissions list for
    a key via the API, so the report names the key type (full secret key
    vs restricted key) instead of inventing one.
    """
    basic = base64.b64encode(f"{key}:".encode()).decode()
    headers = {"Authorization": f"Basic {basic}",
               "User-Agent": USER_AGENT}
    try:
        status, body, _ = request(
            "GET", "https://api.stripe.com/v1/account", headers)
    except ConnectionError as e:
        return {"live": "unknown", "reason": f"network error: {e}",
                "permissions": [], "method": "account"}
    if status == 401:
        return {"live": "dead",
                "reason": "401 Invalid API Key (revoked, rolled, or mistyped)",
                "permissions": [], "method": "account"}
    if status == 429:
        return {"live": "unknown", "reason": "rate limited (429)",
                "permissions": [], "method": "account"}
    if status == 403:
        return {"live": "live",
                "reason": "authenticated but restricted — this key cannot "
                          "read the account (restricted key)",
                "permissions": ["restricted key"], "method": "account"}
    if status != 200:
        return {"live": "unknown", "reason": f"Stripe returned HTTP {status}",
                "permissions": [], "method": "account"}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {"live": "unknown",
                "reason": "Stripe returned an unreadable response",
                "permissions": [], "method": "account"}
    key_type = "restricted key" if key.startswith("rk_") else "full secret key"
    return {"live": "live",
            "reason": f"authenticated (account {data.get('id', '?')}, "
                      f"{'live' if data.get('livemode') else 'test'} mode, "
                      f"{key_type})",
            "permissions": [key_type], "method": "account",
            "account": data.get("id")}


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
        out["validity"] = check_slack(secret)
    elif provider == "gitlab":
        out["validity"] = check_gitlab(secret)
    elif provider == "stripe":
        out["validity"] = check_stripe(secret)
    else:
        out["validity"] = {"live": "unknown",
                           "reason": "no validity check for this provider in v0.2",
                           "permissions": [], "method": "none"}
    return out
