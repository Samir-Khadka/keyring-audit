"""Cloud accounts (Keyring Audit v1.2, Phase 6 coverage).

Two cloud identity types, both validated by exchanging the credential
for a token — the plan's "token introspection" check (§2.4):

- GCP service-account keys. A service-account key is a JSON file with
  ``"type": "service_account"`` and a ``private_key`` (a PEM RSA key).
  Validity is the OAuth2 JWT grant: build a signed JWT (RS256) with
  the private key, POST it to ``oauth2.googleapis.com/token``, and
  read the access token. A 200 with an access token means the key is
  live; a 400 ``invalid_grant`` means it is dead (revoked, or the
  service account is disabled). The token's ``scope`` is the
  permission — a ``cloud-platform`` scope is full access.
- Azure service-principal client secrets. A client secret, a client
  id and a tenant id (the scanner pairs them, like the AWS key/secret
  pair). Validity is the client-credentials grant: POST to
  ``login.microsoftonline.com/{tenant}/oauth2/v2.0/token``. A 200 with
  an access token means the secret is live; a 400 ``invalid_client``
  means it is dead. The access token is a JWT — its ``roles`` claim
  (application permissions) is decoded (no signature check; the token
  came from Microsoft's own endpoint) and reported as the permission
  list.

RS256 is implemented here in the standard library on purpose: the
project is stdlib-only, and the ``cryptography`` package is not
installed. RSA PKCS#1 v1.5 signing is ``EM = 0x00 || 0x01 || PS ||
0x00 || DigestInfo || H`` and ``S = EM^d mod n`` — Python's built-in
``pow(m, d, n)`` does the modular exponentiation in C, and the
PKCS#8 PEM is parsed with a small DER reader. The implementation is
verified against OpenSSL's own signature (see ``tests/test_cloud.py``):
RSASSA-PKCS#1 v1.5 is deterministic, so the two signatures must match
byte for byte. A failure to parse the key, or a failed token exchange,
returns "unknown" — never a guessed live or dead.

A GCP API key (``AIza...``) is detected but its validity is always
"unknown": whether a key works depends on which APIs are enabled for
its project, so a 403 cannot tell a valid key from an invalid one.
The report says so.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

GCP_TOKEN_URL = "https://oauth2.googleapis.com/token"
GCP_SCOPE_CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"
AZURE_SCOPE_MANAGEMENT = "https://management.azure.com/.default"

# ASN.1 DER encoding of DigestInfo for SHA-256 (the 19 bytes before
# the 32-byte hash): SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1,
# NULL }, OCTET STRING }.
_SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")

# OID 1.2.840.113549.1.1.1 (rsaEncryption), the algorithm in a PKCS#8
# private key's AlgorithmIdentifier. The value bytes only (no tag or
# length — _der_read returns the content).
_RSA_OID = bytes.fromhex("2a864886f70d010101")


def _b64url(data: bytes) -> str:
    """base64url without padding (JWT encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """base64url with the padding restored."""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _der_read(data: bytes, i: int):
    """Read one DER TLV at offset i: (tag, value, next_offset)."""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, data[i:i + length], i + length


def _der_read_seq(data: bytes, i: int = 0):
    """Read a DER SEQUENCE at offset i: (children, next_offset)."""
    tag, value, nxt = _der_read(data, i)
    if tag != 0x30:
        raise ValueError("expected a DER SEQUENCE")
    children = []
    j = 0
    while j < len(value):
        children.append(_der_read(value, j))
        j = children[-1][2]
    return children, nxt


def parse_pkcs8_rsa_pem(pem: str) -> tuple[int, int]:
    """Extract (n, d) — modulus and private exponent — from a PKCS#8
    PEM RSA private key. Raises ValueError on a malformed key."""
    lines = [ln.strip() for ln in pem.strip().splitlines()
             if ln.strip() and "-----" not in ln]
    try:
        der = base64.b64decode("".join(lines))
    except Exception as e:
        raise ValueError(f"not base64: {e}") from e
    try:
        fields, _ = _der_read_seq(der)
        # fields: version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING.
        if len(fields) < 3 or fields[1][0] != 0x30:
            raise ValueError("not a PKCS#8 structure")
        alg = fields[1][1]
        oid_tag, oid, _ = _der_read(alg, 0)
        if oid != _RSA_OID:
            raise ValueError("not an RSA key")
        inner = fields[2][1]  # the OCTET STRING holds a PKCS#1 key
        rsa_fields, _ = _der_read_seq(inner)
        # PKCS#1 RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv.
        if len(rsa_fields) < 4:
            raise ValueError("not a PKCS#1 RSA key")
        n = int.from_bytes(rsa_fields[1][1], "big")
        d = int.from_bytes(rsa_fields[3][1], "big")
    except (ValueError, IndexError) as e:
        raise ValueError(f"malformed RSA key: {e}") from e
    return n, d


def rs256_sign(n: int, d: int, message: bytes) -> bytes:
    """RSASSA-PKCS#1 v1.5 signature of `message` with SHA-256."""
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGESTINFO_PREFIX + digest
    k = (n.bit_length() + 7) // 8
    if len(t) + 11 > k:
        raise ValueError("key too small for SHA-256")
    ps = b"\xff" * (k - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    m = int.from_bytes(em, "big")
    return pow(m, d, n).to_bytes(k, "big")


def gcp_jwt(private_key_pem: str, client_email: str,
            scope: str = GCP_SCOPE_CLOUD_PLATFORM) -> str:
    """Build the signed JWT for the OAuth2 service-account grant."""
    n, d = parse_pkcs8_rsa_pem(private_key_pem)
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": client_email, "scope": scope,
              "aud": GCP_TOKEN_URL, "exp": now + 3600, "iat": now}
    signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode())
                     + "." + _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    sig = rs256_sign(n, d, signing_input.encode("ascii"))
    return signing_input + "." + _b64url(sig)


def _opener() -> urllib.request.OpenerDirector:
    """An opener that honours HTTPS_PROXY and SSL_CERT_FILE — the same
    pattern as github.py. The default urlopen reads the proxy from the
    environment, but it does not reliably do so in every runtime, and
    a direct connection to the token endpoints hangs here."""
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
             or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    handlers: list = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    ca = os.environ.get("SSL_CERT_FILE")
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _post_form(url: str, fields: dict) -> dict:
    """POST a form and return the parsed JSON body. Raises ValueError
    on a non-2xx response (with the error body attached)."""
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type":
                                          "application/x-www-form-urlencoded"})
    try:
        with _opener().open(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read())
        except Exception:
            detail = {"error": f"HTTP {e.code}"}
        raise ValueError(detail.get("error", f"HTTP {e.code}")) from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ValueError(f"network error: {e}") from e


def _post_json(url: str, token: str, body: dict) -> dict:
    """POST a JSON body with a Bearer token and return the parsed
    body. Raises ValueError on a non-2xx response."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"})
    try:
        with _opener().open(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ValueError(f"network error: {e}") from e


def _get_json(url: str, token: str) -> dict:
    """GET a JSON body with a Bearer token. Raises ValueError on a
    non-2xx response."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with _opener().open(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ValueError(f"network error: {e}") from e


def gcp_access_token(private_key_pem: str, client_email: str,
                     scope: str = GCP_SCOPE_CLOUD_PLATFORM) -> dict:
    """Exchange a GCP service-account key for an access token. Returns
    the token response (access_token, scope, expires_in). Raises
    ValueError on a rejected grant (invalid_grant) or a network error."""
    jwt = gcp_jwt(private_key_pem, client_email, scope)
    return _post_form(GCP_TOKEN_URL, {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt})


def azure_access_token(tenant_id: str, client_id: str,
                       client_secret: str) -> dict:
    """Exchange an Azure service-principal client secret for an access
    token (client-credentials grant). Returns the token response.
    Raises ValueError on a rejected grant (invalid_client) or a
    network error."""
    url = (f"https://login.microsoftonline.com/{tenant_id}"
           f"/oauth2/v2.0/token")
    return _post_form(url, {
        "client_id": client_id, "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": AZURE_SCOPE_MANAGEMENT})


# The high-value IAM permissions tested for a GCP service account
# (v1.5). No wildcards are allowed by testIamPermissions, so each is
# named explicitly. The list is the blast radius that matters — the
# permissions that let an identity delete things, impersonate other
# service accounts, or grant itself more access. It is a floor, not a
# ceiling: a key that holds none of these may still hold others.
GCP_RISKY_PERMISSIONS = [
    "resourcemanager.projects.delete",
    "resourcemanager.projects.setIamPolicy",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.create",
    "iam.roles.update",
    "compute.instances.delete",
    "storage.buckets.delete",
    "storage.objects.delete",
    "cloudsql.instances.delete",
    "secretmanager.versions.access",
    "bigquery.datasets.delete",
]
# The subset that is effectively admin — the holder can grant itself
# anything, or impersonate another identity.
GCP_ADMIN_PERMISSIONS = {
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.projects.delete",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccountKeys.create",
    "iam.roles.update",
}

# Azure RBAC roles that are effectively admin at subscription scope.
AZURE_ADMIN_RBAC_ROLES = {"Owner", "User Access Administrator"}


def gcp_test_iam_permissions(token: str, project_id: str) -> list:
    """Test which of GCP_RISKY_PERMISSIONS the caller holds on a
    project (Resource Manager testIamPermissions — no IAM role is
    required to test your own permissions). Returns the held subset.
    Raises ValueError on a failed call."""
    url = ("https://cloudresourcemanager.googleapis.com/v1/projects/"
           f"{project_id}:testIamPermissions")
    doc = _post_json(url, token, {"permissions": GCP_RISKY_PERMISSIONS})
    return doc.get("permissions", []) or []


def azure_list_subscriptions(token: str) -> list:
    """List the subscriptions visible to an Azure token. Returns
    [{subscriptionId, displayName}]. A valid ARM token always gets a
    200, even with an empty list."""
    doc = _get_json("https://management.azure.com/subscriptions"
                    "?api-version=2020-01-01", token)
    return [{"subscriptionId": s.get("subscriptionId"),
             "displayName": s.get("displayName")}
            for s in doc.get("value", []) or []]


def azure_rbac_roles(token: str, object_id: str) -> list:
    """List the Azure RBAC role assignments for a service principal
    across every subscription the token can see. Returns
    [{subscription, role, scope}]. A principal with no Reader access
    on a subscription gets a 403 there — that subscription is
    reported as unreadable, not as empty. Raises ValueError when the
    subscriptions themselves cannot be listed."""
    subs = azure_list_subscriptions(token)
    out: list[dict] = []
    role_names: dict[str, str] = {}
    for sub in subs:
        sid = sub["subscriptionId"]
        url = (f"https://management.azure.com/subscriptions/{sid}/"
               "providers/Microsoft.Authorization/roleAssignments"
               "?api-version=2022-04-01"
               f"&$filter=principalId eq '{object_id}'")
        try:
            doc = _get_json(url, token)
        except ValueError as e:
            out.append({"subscription": sub["displayName"], "role": None,
                        "scope": f"role assignments could not be read ({e})"})
            continue
        for a in doc.get("value", []) or []:
            props = a.get("properties", {}) or {}
            role_id = (props.get("roleDefinitionId", "") or "").rsplit("/", 1)[-1]
            if role_id not in role_names:
                try:
                    rdoc = _get_json(
                        f"https://management.azure.com/subscriptions/{sid}/"
                        "providers/Microsoft.Authorization/roleDefinitions/"
                        f"{role_id}?api-version=2022-04-01", token)
                    role_names[role_id] = (
                        rdoc.get("properties", {}) or {}).get("roleName", role_id)
                except ValueError:
                    role_names[role_id] = role_id
            out.append({"subscription": sub["displayName"],
                        "role": role_names[role_id],
                        "scope": props.get("scope", "")})
    return out


def decode_jwt_payload(token: str) -> dict:
    """Decode a JWT's payload without verifying the signature. Used
    only to read the claims of a token that came from the provider's
    own endpoint. Returns {} on a malformed token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def check_gcp(private_key_pem: str, client_email: str,
              project_id: str | None = None) -> dict:
    """Validate a GCP service-account key by exchanging it for an
    access token. Returns the validity dict. When a project id is
    given, the token is also used to test which high-value IAM
    permissions the service account actually holds on that project
    (v1.5) — a measured permission list, not just the scope. A failed
    IAM read leaves the scope-based result intact and says so."""
    try:
        resp = gcp_access_token(private_key_pem, client_email)
    except ValueError as e:
        msg = str(e)
        if msg == "invalid_grant":
            return {"live": "dead",
                    "reason": "the token endpoint rejected the grant — "
                              "the key is revoked or the service account "
                              "is disabled",
                    "permissions": [], "method": "oauth2-jwt-grant",
                    "last_used": None}
        if msg.startswith("network error"):
            return {"live": "unknown",
                    "reason": f"the token endpoint could not be reached "
                              f"({msg})",
                    "permissions": [], "method": "oauth2-jwt-grant",
                    "last_used": None}
        return {"live": "unknown",
                "reason": f"the key could not be used ({msg})",
                "permissions": [], "method": "oauth2-jwt-grant",
                "last_used": None}
    scope = resp.get("scope", "")
    perms = ([scope] if scope else [])
    token = resp.get("access_token", "")
    iam_note = None
    if project_id and token:
        try:
            held = gcp_test_iam_permissions(token, project_id)
            if held:
                perms += [f"iam:{p}" for p in held]
            else:
                perms.append("iam: none of the 12 tested permissions held")
        except ValueError as e:
            iam_note = (f"the IAM policy could not be read ({e}) — the "
                        "score uses the token scope only")
    reason = ("the token endpoint issued an access token for this "
              "service-account key")
    if iam_note:
        reason += f"; {iam_note}"
    return {"live": "live", "reason": reason,
            "permissions": perms, "method": "oauth2-jwt-grant",
            "last_used": None}


def check_azure(tenant_id: str, client_id: str,
                client_secret: str) -> dict:
    """Validate an Azure service-principal client secret by exchanging
    it for an access token. Returns the validity dict."""
    try:
        resp = azure_access_token(tenant_id, client_id, client_secret)
    except ValueError as e:
        msg = str(e)
        if msg == "invalid_client":
            return {"live": "dead",
                    "reason": "the token endpoint rejected the client — "
                              "the secret is wrong or expired, or the "
                              "client id does not exist",
                    "permissions": [], "method": "client-credentials",
                    "last_used": None}
        if msg == "invalid_request":
            return {"live": "unknown",
                    "reason": "the token endpoint rejected the request "
                              "itself — the tenant id may not exist, so "
                              "the secret could not be checked",
                    "permissions": [], "method": "client-credentials",
                    "last_used": None}
        if msg.startswith("network error"):
            return {"live": "unknown",
                    "reason": f"the token endpoint could not be reached "
                              f"({msg})",
                    "permissions": [], "method": "client-credentials",
                    "last_used": None}
        return {"live": "unknown",
                "reason": f"the secret could not be used ({msg})",
                "permissions": [], "method": "client-credentials",
                "last_used": None}
    payload = decode_jwt_payload(resp.get("access_token", ""))
    roles = payload.get("roles", []) or []
    scp = payload.get("scp", "") or ""
    perms = list(roles) + ([f"scp:{s}" for s in scp.split()] if scp else [])
    # v1.5: read the Azure RBAC role assignments for this service
    # principal (the oid claim is its object id). A failed read leaves
    # the app-roles result intact and says so — the token is still
    # live, the RBAC roles are just unknown.
    rbac_note = None
    oid = payload.get("oid")
    token = resp.get("access_token", "")
    if oid and token:
        try:
            assignments = azure_rbac_roles(token, oid)
            for a in assignments:
                if a["role"]:
                    perms.append(f"rbac:{a['role']} on {a['subscription']}")
                else:
                    rbac_note = a["scope"]
        except ValueError as e:
            rbac_note = (f"the RBAC role assignments could not be read "
                         f"({e}) — the identity has no Reader access on "
                         "any subscription, so its RBAC roles are unknown")
    reason = ("the token endpoint issued an access token for this "
              "client secret")
    if rbac_note:
        reason += f"; {rbac_note}"
    return {"live": "live", "reason": reason,
            "permissions": perms, "method": "client-credentials",
            "last_used": None}
