"""AWS Signature Version 4 signing, stdlib only (Keyring Audit v0.1).

The CLI validates AWS keys without boto3: one signed GET to STS
(GetCallerIdentity) proves the key is live, and signed POSTs to the IAM
Query API list attached policies and last-used times. Everything here is
the documented SigV4 algorithm (AWS docs, "Signature Version 4 signing
process"): canonical request → string to sign → signing key → signature.

The signer never logs the secret key. It is used only to HMAC the
string to sign, in memory.
"""
from __future__ import annotations

import hashlib
import hmac
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sign_request(method: str, url: str, access_key: str, secret_key: str,
                 region: str, service: str,
                 headers: dict[str, str] | None = None,
                 body: bytes = b"",
                 session_token: str | None = None,
                 now: datetime | None = None) -> dict[str, str]:
    """Return the headers for a SigV4-signed request.

    ``now`` is injectable so tests can pin the timestamp. The returned
    dict is safe to log: it contains no secret material.
    """
    now = now or datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    canonical_uri = urllib.parse.quote(parsed.path or "/", safe="/~")
    canonical_query = parsed.query
    payload_hash = hashlib.sha256(body).hexdigest()

    headers = dict(headers or {})
    headers["host"] = host
    headers["x-amz-date"] = amz_date
    headers["x-amz-content-sha256"] = payload_hash
    if session_token:
        headers["x-amz-security-token"] = session_token

    signed_headers = sorted(k.lower() for k in headers)
    canonical_headers = "".join(
        f"{k.lower()}:{headers[k].strip()}\n"
        for k in sorted(headers, key=str.lower))
    canonical_request = "\n".join([
        method, canonical_uri, canonical_query, canonical_headers,
        ";".join(signed_headers), payload_hash])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    k_date = _hmac(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={';'.join(signed_headers)}, Signature={signature}")
    return headers


def aws_request(method: str, url: str, access_key: str, secret_key: str,
                region: str, service: str,
                body: bytes = b"",
                content_type: str = "application/x-www-form-urlencoded",
                session_token: str | None = None,
                timeout: int = 15) -> tuple[int, bytes, dict[str, str]]:
    """Make a SigV4-signed request. Returns (status, body, headers).

    Raises urllib.error.URLError on a network failure (the caller turns
    that into "unknown", never into a crash).
    """
    headers = sign_request(method, url, access_key, secret_key, region,
                           service, headers={"Content-Type": content_type}
                           if body else None, body=body,
                           session_token=session_token)
    req = urllib.request.Request(url, data=body or None, headers=headers,
                                 method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read(), dict(resp.headers)


def sts_get_caller_identity(access_key: str, secret_key: str,
                            session_token: str | None = None) -> dict:
    """Validate an AWS key pair. Returns the parsed identity, or raises.

    Raises ValueError("invalid credentials") on a 403, and URLError on a
    network failure. The XML response is parsed with a small, safe
    reader (no external parser, no DTD).
    """
    import xml.etree.ElementTree as ET

    url = ("https://sts.amazonaws.com/"
           "?Action=GetCallerIdentity&Version=2011-06-15")
    try:
        status, body, _ = aws_request("GET", url, access_key, secret_key,
                                      "us-east-1", "sts",
                                      session_token=session_token)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise ValueError("invalid credentials") from None
        raise
    if status != 200:
        raise ValueError(f"STS returned HTTP {status}")
    root = ET.fromstring(body)
    ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
    result = root.find("s:GetCallerIdentityResult", ns)
    if result is None:
        raise ValueError("unexpected STS response (no GetCallerIdentityResult)")
    text = lambda tag: (result.findtext(f"s:{tag}", namespaces=ns) or "")
    return {"account": text("Account"), "arn": text("Arn"),
            "user_id": text("UserId")}


def iam_query(access_key: str, secret_key: str, action: str,
              params: dict[str, str],
              session_token: str | None = None) -> "xml.etree.ElementTree.Element":
    """One signed POST to the IAM Query API. Returns the response root."""
    import xml.etree.ElementTree as ET

    body = urllib.parse.urlencode(
        {"Action": action, "Version": "2010-05-08", **params}).encode()
    try:
        status, raw, _ = aws_request("POST", "https://iam.amazonaws.com/",
                                     access_key, secret_key, "us-east-1",
                                     "iam", body=body,
                                     session_token=session_token)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise ValueError("access denied (the key cannot read IAM)") from None
        raise
    if status != 200:
        raise ValueError(f"IAM returned HTTP {status}")
    return ET.fromstring(raw)
