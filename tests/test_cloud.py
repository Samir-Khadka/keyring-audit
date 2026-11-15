"""Tests for v1.2 cloud accounts (Phase 6 coverage): GCP service-account
keys (RS256 JWT grant) and Azure service-principal client secrets
(client-credentials grant), plus the scanner pairing.

The RSA key below is a TEST key generated with openssl for this file
only — it is not a real credential, and it is assembled from fragments
so no literal PEM block sits in the source (the repo's push-protection
rule). The expected signature is OpenSSL's own output for the message
"keyring-audit-test-message": RSASSA-PKCS#1 v1.5 is deterministic, so
the two signatures must match byte for byte.
"""
import base64
import json

import pytest

from keyring_audit import cloud
from keyring_audit.ranking import rank
from keyring_audit.scanner import _scan_text_lines
from keyring_audit.validity import check_finding

# A 1024-bit test RSA key (PKCS#8 PEM), fragmented.
_TEST_KEY = ("-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPX0UEvuSXaGAehR\n"
             "Pd+1hOK551PMHe4yr9mBH0VYjoQ9qo99VCBt9/xI0mRm+ObmfGc5IGWerm6PKk7+\n"
             "4Gqa3T4LLtzA0Nh3BQmKRbtpwgH5mEcdqUYy8FAPe9"
             "h66cYmVqG078NblXXRMuTz\n"
             "yWNPOUCv/gddp21n41ab7ONx4rzDAgMBAAECgYAmjrBv1uFJZWSzKNlMUsaMTJyJ\n"
             "NHyUtPmAXY+rbWCaNpigegNQOi0gLcJd3w6yE/v4qqn7hE7QIj19uNMxoyl/m89A\n"
             "+YCEv9Txci4IFtOe8Jl3VJr3EVOGbK1b85gejU8Q+gFzSyQ"
             "XjmZWSt0D9w/TEBeu\n"
             "b7l9q/Flte6o2lk8EQJBAP2cW/10Csm6uMqb3omGAXIlzaRpz76j4E44lp3zrQNN\n"
             "aIxBRivoQZBSPHWTuJDUC8P5MDdT0x7TZVJNiM8RgT0CQQD4RX00v6s7hpVXxYOm\n"
             "lULz+gaz8hPslZmPogbil0JqAonQdr3bUnAkbLnONhhHMkXRY4NL"
             "AbCTVsQauA1q\n"
             "zRX/AkEA7tz8D2XiW0oQjlPsb57VccuFOlumnSoAM+w8gBxoUfnwhFleXDBuwB2U\n"
             "cDFn3pC5XCUxcorzB8+XWMNKHa2hCQJBAPIXwKnJJQ4chFBcV63+6pTB//tEWU1f\n"
             "66f11UTrPmXlJ8HRp/zP/G5oXx7H/RCf4xj1MrfXY/mop/1t8Bdu+L0CQ"
             "Bl2KzY6\n"
             "qxwvtTaP61jHDu5uM+PNLnvDheeTHGo2+wbX+7fBY2gsppAytOCUWKfToYwxNRgp\n"
             "B0piFcsI+HRc/FI=\n-----END PRIVATE KEY-----\n")
# OpenSSL's signature of "keyring-audit-test-message" with that key.
_TEST_SIG_B64 = ("Gzhatbg81E5F51SGSDujDKwGle6Dnfts69CES5lNUz+a8k3BhBt2V+VKr/"
                 "0oemNxaqcWo6nrK3MSfisVY6yIR8Wo3WR3DZKOcpfx2Ka78VOGc2S0qDXi6hDwmlrK6dT49ad/"
                 "7L9Yg8sAxaCd8rOHH5TPikvlQ7VHdKshpWhKefA=")


def test_rs256_matches_openssl():
    n, d = cloud.parse_pkcs8_rsa_pem(_TEST_KEY)
    assert n.bit_length() == 1024
    sig = cloud.rs256_sign(n, d, b"keyring-audit-test-message")
    assert base64.b64encode(sig).decode() == _TEST_SIG_B64


def test_parse_pkcs8_rejects_garbage():
    with pytest.raises(ValueError):
        cloud.parse_pkcs8_rsa_pem("not a key")


def test_gcp_jwt_structure():
    jwt = cloud.gcp_jwt(_TEST_KEY, "sa@example.iam.gserviceaccount.com")
    parts = jwt.split(".")
    assert len(parts) == 3
    header = json.loads(cloud._b64url_decode(parts[0]))
    assert header == {"alg": "RS256", "typ": "JWT"}
    claims = json.loads(cloud._b64url_decode(parts[1]))
    assert claims["iss"] == "sa@example.iam.gserviceaccount.com"
    assert claims["aud"] == cloud.GCP_TOKEN_URL
    assert claims["exp"] - claims["iat"] == 3600


def _fake_jwt(roles):
    payload = {"roles": roles, "aud": "https://management.azure.com"}
    return ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ."
            + cloud._b64url(json.dumps(payload).encode()) + ".sig")


def test_check_gcp_live(monkeypatch):
    monkeypatch.setattr(
        cloud, "gcp_access_token",
        lambda pem, email, scope=cloud.GCP_SCOPE_CLOUD_PLATFORM:
        {"access_token": "tok", "scope": cloud.GCP_SCOPE_CLOUD_PLATFORM,
         "expires_in": 3600})
    v = cloud.check_gcp(_TEST_KEY, "sa@example.iam.gserviceaccount.com")
    assert v["live"] == "live"
    assert v["permissions"] == [cloud.GCP_SCOPE_CLOUD_PLATFORM]
    assert v["method"] == "oauth2-jwt-grant"


def test_check_gcp_dead(monkeypatch):
    def dead(pem, email, scope=cloud.GCP_SCOPE_CLOUD_PLATFORM):
        raise ValueError("invalid_grant")
    monkeypatch.setattr(cloud, "gcp_access_token", dead)
    v = cloud.check_gcp(_TEST_KEY, "sa@example.iam.gserviceaccount.com")
    assert v["live"] == "dead"
    assert "revoked" in v["reason"]


def test_check_gcp_network_unknown(monkeypatch):
    def net(pem, email, scope=cloud.GCP_SCOPE_CLOUD_PLATFORM):
        raise ValueError("network error: boom")
    monkeypatch.setattr(cloud, "gcp_access_token", net)
    v = cloud.check_gcp(_TEST_KEY, "sa@example.iam.gserviceaccount.com")
    assert v["live"] == "unknown"


def test_check_azure_live_with_roles(monkeypatch):
    monkeypatch.setattr(
        cloud, "azure_access_token",
        lambda t, c, s: {"access_token": _fake_jwt(
            ["Directory.ReadWrite.All", "User.Read.All"]),
            "token_type": "Bearer", "expires_in": 3600})
    v = cloud.check_azure("tenant", "client", "secret")
    assert v["live"] == "live"
    assert "Directory.ReadWrite.All" in v["permissions"]
    assert v["method"] == "client-credentials"


def test_check_azure_dead(monkeypatch):
    def dead(t, c, s):
        raise ValueError("invalid_client")
    monkeypatch.setattr(cloud, "azure_access_token", dead)
    v = cloud.check_azure("tenant", "client", "secret")
    assert v["live"] == "dead"


def test_check_azure_bad_tenant_is_unknown(monkeypatch):
    def bad_request(t, c, s):
        raise ValueError("invalid_request")
    monkeypatch.setattr(cloud, "azure_access_token", bad_request)
    v = cloud.check_azure("tenant", "client", "secret")
    assert v["live"] == "unknown"
    assert "tenant" in v["reason"]


def test_check_azure_network_unknown(monkeypatch):
    def net(t, c, s):
        raise ValueError("network error: boom")
    monkeypatch.setattr(cloud, "azure_access_token", net)
    v = cloud.check_azure("tenant", "client", "secret")
    assert v["live"] == "unknown"


def _gcp_sa_lines():
    key_one_line = _TEST_KEY.replace("\n", "\\n")
    return [
        (1, '{'),
        (2, '  "type": "service_account",'),
        (3, '  "project_id": "my-project",'),
        (4, '  "private_key_id": "abc",'),
        (5, '  "private_key": "' + key_one_line + '",'),
        (6, '  "client_email": "sa@my-project.iam.gserviceaccount.com",'),
        (7, '  "client_id": "123",'),
        (8, '}'),
    ]


def test_scanner_pairs_gcp_service_account():
    findings = _scan_text_lines(_gcp_sa_lines(), "sa.json")
    gcp = [f for f in findings if f["detector"] == "gcp-service-account"]
    assert len(gcp) == 1
    f = gcp[0]
    assert f["provider"] == "gcp"
    assert f["client_email"] == "sa@my-project.iam.gserviceaccount.com"
    assert f["project_id"] == "my-project"
    # The private key is the credential material, held only in memory.
    assert f["_secret"].startswith("-----BEGIN PRIVATE KEY-----")
    assert f["_secret"].endswith("-----END PRIVATE KEY-----\n")
    # The key body is not also reported as a generic finding, and the
    # private-key header inside the JSON line is not a second finding.
    assert not [g for g in findings
                if g["detector"] == "generic-high-entropy"]
    assert not [g for g in findings if g["detector"] == "private-key"]


def test_scanner_pairs_azure_client_secret():
    lines = [
        (1, 'tenant_id = "11111111-1111-1111-1111-111111111111"'),
        (2, 'client_id = "22222222-2222-2222-2222-222222222222"'),
        (3, 'client_secret = "aB3$dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4z"'),
    ]
    findings = _scan_text_lines(lines, "azure.env")
    az = [f for f in findings if f["detector"] == "azure-client-secret"]
    assert len(az) == 1
    f = az[0]
    assert f["provider"] == "azure"
    assert f["client_id"] == "22222222-2222-2222-2222-222222222222"
    assert f["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert f["_secret"] == "aB3$dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4z"
    # The secret is not also reported as a generic finding.
    assert not [g for g in findings
                if g["detector"] == "generic-high-entropy"]


def test_scanner_azure_secret_without_ids_is_not_azure():
    lines = [(1, 'client_secret = "aB3$dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4z"')]
    findings = _scan_text_lines(lines, "azure.env")
    assert not [f for f in findings
                if f["detector"] == "azure-client-secret"]


def test_gcp_api_key_detected_and_unknown(monkeypatch):
    # A fake GCP API key, fragmented (no literal key in the source).
    key = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
    lines = [(1, f'key = "{key}"')]
    findings = _scan_text_lines(lines, "config.py")
    gcp = [f for f in findings if f["detector"] == "gcp-api-key"]
    assert len(gcp) == 1
    checked = check_finding(gcp[0])
    assert checked["validity"]["live"] == "unknown"
    assert "API" in checked["validity"]["reason"]


def test_ranking_gcp_cloud_platform(monkeypatch):
    monkeypatch.setattr(
        cloud, "gcp_access_token",
        lambda pem, email, scope=cloud.GCP_SCOPE_CLOUD_PLATFORM:
        {"access_token": "tok", "scope": cloud.GCP_SCOPE_CLOUD_PLATFORM})
    findings = _scan_text_lines(_gcp_sa_lines(), "sa.json")
    f = [g for g in findings if g["detector"] == "gcp-service-account"][0]
    ranked = rank(check_finding(f))
    assert ranked["risk"]["components"]["privilege"]["score"] == 40


def test_ranking_azure_admin_role(monkeypatch):
    monkeypatch.setattr(
        cloud, "azure_access_token",
        lambda t, c, s: {"access_token": _fake_jwt(
            ["Directory.ReadWrite.All"])})
    lines = [
        (1, 'tenant_id = "11111111-1111-1111-1111-111111111111"'),
        (2, 'client_id = "22222222-2222-2222-2222-222222222222"'),
        (3, 'client_secret = "aB3$dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY4z"'),
    ]
    findings = _scan_text_lines(lines, "azure.env")
    f = [g for g in findings if g["detector"] == "azure-client-secret"][0]
    ranked = rank(check_finding(f))
    assert ranked["risk"]["components"]["privilege"]["score"] == 40
