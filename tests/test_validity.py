"""Tests for SigV4 signing and the validity checks (mocked HTTP)."""
import json
from datetime import datetime, timezone

import pytest

from keyring_audit import aws_sign
from keyring_audit.validity import (check_aws, check_finding, check_github,
                                    check_gitlab, check_slack, check_stripe)

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"


# ---------------------------------------------------------------- SigV4
def test_sign_request_is_deterministic_and_well_formed():
    now = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
    h1 = aws_sign.sign_request("GET", "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                               AWS_KEY_ID, AWS_SECRET, "us-east-1", "sts", now=now)
    h2 = aws_sign.sign_request("GET", "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                               AWS_KEY_ID, AWS_SECRET, "us-east-1", "sts", now=now)
    assert h1 == h2  # deterministic
    auth = h1["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFOD" + "NN7EXAMPLE/20261115/us-east-1/sts/aws4_request, ")
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in auth
    assert "Signature=" in auth and len(auth.rsplit("Signature=", 1)[1]) == 64
    assert h1["x-amz-date"] == "20261115T100000Z"
    # No secret material in the headers.
    assert AWS_SECRET not in json.dumps(h1)


def test_sign_request_changes_with_the_secret():
    now = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
    a = aws_sign.sign_request("GET", "https://sts.amazonaws.com/", AWS_KEY_ID,
                              AWS_SECRET, "us-east-1", "sts", now=now)
    b = aws_sign.sign_request("GET", "https://sts.amazonaws.com/", AWS_KEY_ID,
                              "AAAAAAAAAAAAAAAAAAAA" + "AAAAAAAAAAAAAAAAAAAA",
                              "us-east-1", "sts", now=now)
    assert a["Authorization"] != b["Authorization"]


# ---------------------------------------------------------------- GitHub
def _fake_github(requests):
    """Build a fake request() from a {(method, url): (status, body, headers)} map."""
    def fake(method, url, headers=None, timeout=15):
        status, body, resp_headers = requests[(method, url)]
        return status, body if isinstance(body, bytes) else body.encode(), resp_headers
    return fake


def test_github_classic_pat_returns_scopes_from_header():
    fake = _fake_github({
        ("GET", "https://api.github.com/user"): (
            200, json.dumps({"login": "octocat"}),
            {"x-oauth-scopes": "repo, user, gist"}),
    })
    r = check_github(GITHUB_PAT, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["repo", "user", "gist"]
    assert r["method"] == "header"
    assert r["login"] == "octocat"


def test_github_401_is_dead():
    fake = _fake_github({
        ("GET", "https://api.github.com/user"): (401, b'{"message":"Bad credentials"}', {}),
    })
    r = check_github(GITHUB_PAT, request=fake)
    assert r["live"] == "dead"


def test_github_429_is_unknown_not_dead():
    fake = _fake_github({
        ("GET", "https://api.github.com/user"): (429, b"", {}),
    })
    assert check_github(GITHUB_PAT, request=fake)["live"] == "unknown"


def test_github_fine_grained_token_probes_endpoints():
    # No x-oauth-scopes header: the token is fine-grained, so endpoints
    # are probed and the method is reported as "probed".
    fake = _fake_github({
        ("GET", "https://api.github.com/user"): (
            200, json.dumps({"login": "octocat"}), {}),
        ("GET", "https://api.github.com/user/repos?per_page=1"): (200, b"[]", {}),
        ("GET", "https://api.github.com/user/orgs?per_page=1"): (404, b"", {}),
        ("GET", "https://api.github.com/user/starred?per_page=1"): (200, b"[]", {}),
    })
    r = check_github("github_pat_" + "x" * 82, request=fake)
    assert r["live"] == "live"
    assert r["method"] == "probed"
    assert "list own repositories" in r["permissions"]
    assert "list organisations" not in r["permissions"]


def test_github_network_error_is_unknown():
    def failing(method, url, headers=None, timeout=15):
        raise ConnectionError("no network")
    r = check_github(GITHUB_PAT, request=failing)
    assert r["live"] == "unknown"


# ---------------------------------------------------------------- AWS
def test_aws_without_secret_is_unknown():
    r = check_aws(AWS_KEY_ID, None)
    assert r["live"] == "unknown"
    assert "secret was not in the scan" in r["reason"]


def test_aws_invalid_key_is_dead(monkeypatch):
    def fake_sts(*a, **k):
        raise ValueError("invalid credentials")
    monkeypatch.setattr(aws_sign, "sts_get_caller_identity", fake_sts)
    r = check_aws(AWS_KEY_ID, AWS_SECRET)
    assert r["live"] == "dead"


def test_aws_live_key_lists_policies(monkeypatch):
    import xml.etree.ElementTree as ET

    def fake_sts(*a, **k):
        return {"account": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/deployer",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"}
    attached = ET.fromstring(
        '<ListAttachedUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        '<ListAttachedUserPoliciesResult><AttachedPolicies><member>'
        '<PolicyName>AdministratorAccess</PolicyName>'
        '<PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn>'
        '</member></AttachedPolicies></ListAttachedUserPoliciesResult>'
        '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
        '</ListAttachedUserPoliciesResponse>')
    inline = ET.fromstring(
        '<ListUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        '<ListUserPoliciesResult><PolicyNames/></ListUserPoliciesResult>'
        '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
        '</ListUserPoliciesResponse>')
    last_used = ET.fromstring(
        '<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        '<GetAccessKeyLastUsedResult><AccessKeyLastUsed>'
        '<LastUsedDate>2026-11-14T09:00:00Z</LastUsedDate>'
        '</AccessKeyLastUsed></GetAccessKeyLastUsedResult>'
        '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
        '</GetAccessKeyLastUsedResponse>')
    calls = {"n": 0}
    def fake_query(*a, **k):
        calls["n"] += 1
        return [attached, inline, last_used][calls["n"] - 1]
    monkeypatch.setattr(aws_sign, "sts_get_caller_identity", fake_sts)
    monkeypatch.setattr(aws_sign, "iam_query", fake_query)
    r = check_aws(AWS_KEY_ID, AWS_SECRET)
    assert r["live"] == "live"
    assert any("AdministratorAccess" in p for p in r["permissions"])
    assert r["last_used"] == "2026-11-14T09:00:00Z"


def test_aws_iam_denied_reports_unknown_permissions(monkeypatch):
    def fake_sts(*a, **k):
        return {"account": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/deployer",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"}
    def fake_query(*a, **k):
        raise ValueError("access denied (the key cannot read IAM)")
    monkeypatch.setattr(aws_sign, "sts_get_caller_identity", fake_sts)
    monkeypatch.setattr(aws_sign, "iam_query", fake_query)
    r = check_aws(AWS_KEY_ID, AWS_SECRET)
    assert r["live"] == "live"  # the key IS live; only its permissions are unknown
    assert r["permissions"] == []
    assert "IAM read denied" in r["reason"]


# ---------------------------------------------------------------- check_finding
def test_check_finding_strips_the_secret():
    finding = {"detector": "github-pat-classic", "provider": "github",
               "redacted": "ghp_…cdef", "fingerprint": "x", "source": "a.py",
               "line": 1, "commit": None, "author": None, "date": None,
               "_secret": GITHUB_PAT}
    out = check_finding(finding, verify=False)
    assert "_secret" not in out
    assert out["validity"]["live"] == "skipped"
    # The original finding still holds the secret in memory (the caller owns it).
    assert finding["_secret"] == GITHUB_PAT


def test_check_finding_unknown_provider_is_unknown():
    finding = {"detector": "jwt", "provider": "generic", "redacted": "eyJ…",
               "fingerprint": "x", "source": "a.py", "line": 1,
               "commit": None, "author": None, "date": None, "_secret": "y"}
    out = check_finding(finding, verify=True)
    assert out["validity"]["live"] == "unknown"


# ---------------------------------------------------------------- Slack (v0.2)
SLACK_TOKEN = "xoxb-" + "FAKE-TOKEN-FOR-TEST"
GITLAB_TOKEN = "glpat-" + "FAKE-TOKEN-FOR-TEST"
STRIPE_TEST_KEY = "sk_test_" + "FAKE"
STRIPE_LIVE_KEY = "sk_live_" + "FAKE"
STRIPE_RESTRICTED_KEY = "rk_live_" + "FAKE"


def test_slack_live_returns_scopes_from_header():
    fake = _fake_github({
        ("POST", "https://slack.com/api/auth.test"): (
            200, json.dumps({"ok": True, "user": "bot", "team": "acme"}),
            {"x-oauth-scopes": "channels:read,chat:write"}),
    })
    r = check_slack(SLACK_TOKEN, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["channels:read", "chat:write"]
    assert r["method"] == "auth.test"
    assert r["user"] == "bot"
    assert r["team"] == "acme"


def test_slack_invalid_auth_is_dead():
    # Slack returns HTTP 200 even for a bad token — ok: false decides.
    fake = _fake_github({
        ("POST", "https://slack.com/api/auth.test"): (
            200, json.dumps({"ok": False, "error": "invalid_auth"}), {}),
    })
    assert check_slack(SLACK_TOKEN, request=fake)["live"] == "dead"


def test_slack_other_error_is_unknown_not_dead():
    fake = _fake_github({
        ("POST", "https://slack.com/api/auth.test"): (
            200, json.dumps({"ok": False, "error": "account_inactive"}), {}),
    })
    assert check_slack(SLACK_TOKEN, request=fake)["live"] == "unknown"


def test_slack_429_is_unknown():
    fake = _fake_github({
        ("POST", "https://slack.com/api/auth.test"): (429, b"", {}),
    })
    assert check_slack(SLACK_TOKEN, request=fake)["live"] == "unknown"


def test_slack_network_error_is_unknown():
    def failing(method, url, headers=None, timeout=15):
        raise ConnectionError("no network")
    assert check_slack(SLACK_TOKEN, request=failing)["live"] == "unknown"


# ---------------------------------------------------------------- GitLab (v0.2)
def test_gitlab_self_returns_scopes_and_expiry():
    fake = _fake_github({
        ("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"): (
            200, json.dumps({"id": 1, "name": "ci", "scopes": ["api", "read_user"],
                             "active": True, "revoked": False,
                             "expires_at": "2027-01-01"}), {}),
    })
    r = check_gitlab(GITLAB_TOKEN, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["api", "read_user"]
    assert r["method"] == "self"
    assert r["expires_at"] == "2027-01-01"


def test_gitlab_401_is_dead():
    fake = _fake_github({
        ("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"): (401, b"{}", {}),
    })
    assert check_gitlab(GITLAB_TOKEN, request=fake)["live"] == "dead"


def test_gitlab_revoked_token_is_dead():
    fake = _fake_github({
        ("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"): (
            200, json.dumps({"id": 1, "name": "ci", "scopes": ["api"],
                             "active": False, "revoked": True}), {}),
    })
    assert check_gitlab(GITLAB_TOKEN, request=fake)["live"] == "dead"


def test_gitlab_self_404_falls_back_to_user():
    # Group/project tokens cannot be described by the self endpoint.
    fake = _fake_github({
        ("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"): (404, b"", {}),
        ("GET", "https://gitlab.com/api/v4/user"): (
            200, json.dumps({"username": "deploy"}), {}),
    })
    r = check_gitlab(GITLAB_TOKEN, request=fake)
    assert r["live"] == "live"
    assert r["method"] == "user"
    assert r["permissions"] == []  # scopes not listed for these token types


def test_gitlab_fallback_user_401_is_dead():
    fake = _fake_github({
        ("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"): (404, b"", {}),
        ("GET", "https://gitlab.com/api/v4/user"): (401, b"{}", {}),
    })
    assert check_gitlab(GITLAB_TOKEN, request=fake)["live"] == "dead"


# ---------------------------------------------------------------- Stripe (v0.2)
def test_stripe_live_full_key():
    fake = _fake_github({
        ("GET", "https://api.stripe.com/v1/account"): (
            200, json.dumps({"id": "acct_FAKE123", "livemode": True}), {}),
    })
    r = check_stripe(STRIPE_LIVE_KEY, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["full secret key"]
    assert r["account"] == "acct_FAKE123"


def test_stripe_401_is_dead():
    fake = _fake_github({
        ("GET", "https://api.stripe.com/v1/account"): (
            401, json.dumps({"error": {"type": "invalid_request_error",
                                       "message": "Invalid API Key provided"}}), {}),
    })
    assert check_stripe(STRIPE_TEST_KEY, request=fake)["live"] == "dead"


def test_stripe_403_means_live_but_restricted():
    # Stripe only returns 403 after authenticating: the key is live, it
    # just cannot read the account.
    fake = _fake_github({
        ("GET", "https://api.stripe.com/v1/account"): (
            403, json.dumps({"error": {"type": "invalid_request_error",
                                       "message": "does not have access"}}), {}),
    })
    r = check_stripe(STRIPE_RESTRICTED_KEY, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["restricted key"]


def test_stripe_restricted_key_prefix_reported_as_restricted():
    fake = _fake_github({
        ("GET", "https://api.stripe.com/v1/account"): (
            200, json.dumps({"id": "acct_FAKE123", "livemode": False}), {}),
    })
    r = check_stripe(STRIPE_RESTRICTED_KEY, request=fake)
    assert r["live"] == "live"
    assert r["permissions"] == ["restricted key"]


def test_stripe_429_is_unknown():
    fake = _fake_github({
        ("GET", "https://api.stripe.com/v1/account"): (429, b"", {}),
    })
    assert check_stripe(STRIPE_TEST_KEY, request=fake)["live"] == "unknown"


def test_check_finding_dispatches_slack_gitlab_stripe(monkeypatch):
    import keyring_audit.validity as v
    monkeypatch.setattr(v, "check_slack", lambda t: {
        "live": "live", "reason": "x", "permissions": ["chat:write"],
        "method": "auth.test"})
    monkeypatch.setattr(v, "check_gitlab", lambda t: {
        "live": "live", "reason": "x", "permissions": ["api"],
        "method": "self"})
    monkeypatch.setattr(v, "check_stripe", lambda k: {
        "live": "dead", "reason": "401", "permissions": [],
        "method": "account"})
    base = {"detector": "x", "redacted": "x…", "fingerprint": "x",
            "source": "a.py", "line": 1, "commit": None, "author": None,
            "date": None}
    for provider, token, live in (("slack", SLACK_TOKEN, "live"),
                                  ("gitlab", GITLAB_TOKEN, "live"),
                                  ("stripe", STRIPE_TEST_KEY, "dead")):
        out = check_finding({**base, "provider": provider, "_secret": token},
                            verify=True)
        assert out["validity"]["live"] == live
        assert "_secret" not in out
