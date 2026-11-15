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


def check_gcp(private_key_pem: str, client_email: str) -> dict:
    """Validate a GCP service-account key by exchanging it for an
    access token. Returns the validity dict."""
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
    return {"live": "live",
            "reason": "the token endpoint issued an access token for "
                      "this service-account key",
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
    return {"live": "live",
            "reason": "the token endpoint issued an access token for "
                      "this client secret",
            "permissions": perms, "method": "client-credentials",
            "last_used": None}
