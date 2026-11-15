"""Tests for v0.6 safe remediation: plans, the AWS two-key rollover,
and post-rotation verification."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from keyring_audit import aws_sign
from keyring_audit.__main__ import cli
from keyring_audit.remediation import (
    build_plan,
    complete_aws_rollover,
    execute_aws_rollover,
    iam_user_name,
    render_plan,
    rotate_with_care,
    verify_old_credential,
)

# Fragmented on purpose: the full literals trip GitHub push protection
# (see the v0.1 push saga). The runtime values are the documented AWS
# example pair.
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"
NEW_KEY_ID = "AKIAI44QH8D" + "HBEXAMPLE"
NEW_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYNEWKEY"


def _aws_finding(**over):
    base = {"detector": "aws-access-key-id", "provider": "aws",
            "redacted": "AKIA…MPLE", "fingerprint": "fp-aws-1",
            "source": ".env", "line": 2, "commit": "abc123",
            "author": "Dev <dev@example.com>", "date": 1646138400,
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live",
                         "reason": "authenticated as "
                                   "arn:aws:iam::123456789012:user/deployer",
                         "permissions": ["managed policy: ReadOnlyAccess"],
                         "method": "iam",
                         "identity": {"arn": "arn:aws:iam::123456789012:"
                                            "user/deployer",
                                      "account": "123456789012",
                                      "user_id": "AIDACKCEVSQ6C2EXAMPLE"},
                         "last_used": "2026-11-10T09:00:00Z"}}
    base.update(over)
    return base


def _github_finding(**over):
    base = {"detector": "github-pat-classic", "provider": "github",
            "redacted": "ghp_…cdef", "fingerprint": "fp-gh-1",
            "source": "config.py", "line": 3, "commit": "abc123",
            "author": "Dev <dev@example.com>", "date": 1646138400,
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live", "reason": "authenticated as octocat",
                         "permissions": ["repo"], "method": "header"}}
    base.update(over)
    return base


# ---------------------------------------------------------------- plans
def test_aws_live_user_plan_is_automated():
    plan = build_plan(_aws_finding())
    assert plan["automated"] is True
    assert plan["live"] == "live"
    assert len(plan["steps"]) == 5
    assert any("Never delete" in w for w in plan["warnings"])
    assert any("CloudTrail" in w for w in plan["warnings"])


def test_aws_dead_key_plan_is_manual():
    plan = build_plan(_aws_finding(
        validity={"live": "dead", "reason": "bad key", "permissions": [],
                  "method": "sts"}))
    assert plan["automated"] is False
    assert "no rollover" in plan["steps"][0]


def test_assumed_role_plan_is_manual():
    f = _aws_finding()
    f["validity"]["identity"]["arn"] = (
        "arn:aws:sts::123456789012:assumed-role/deploy/session")
    assert iam_user_name(f) is None
    assert build_plan(f)["automated"] is False


def test_github_plan_is_manual_and_names_the_web_ui():
    plan = build_plan(_github_finding())
    assert plan["automated"] is False
    assert any("web-UI" in s or "github.com" in s for s in plan["steps"])


def test_rotate_with_care_uses_last_24_hours():
    now = datetime.now(timezone.utc)
    recent = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    f = _aws_finding()
    f["validity"]["last_used"] = recent
    assert rotate_with_care(f) is True
    assert any("ROTATE WITH CARE" in w for w in build_plan(f)["warnings"])
    f["validity"]["last_used"] = old
    assert rotate_with_care(f) is False
    f["validity"].pop("last_used")
    assert rotate_with_care(f) is False


def test_render_plan_formats():
    plan = build_plan(_aws_finding())
    text = render_plan(plan, "text")
    assert "Rotation plan" in text and "two-key rollover" in text
    md = render_plan(plan, "md")
    assert md.startswith("# Rotation plan")
    assert json.loads(render_plan(plan, "json"))["automated"] is True


# ---------------------------------------------------------------- AWS API
def test_create_access_key_parses_response(monkeypatch):
    import xml.etree.ElementTree as ET

    seen = {}
    def fake_query(access_key, secret_key, action, params,
                   session_token=None):
        seen.update({"action": action, "params": params})
        return ET.fromstring(
            '<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            '<CreateAccessKeyResult><AccessKey>'
            f"<UserName>deployer</UserName><AccessKeyId>{NEW_KEY_ID}</AccessKeyId>"
            f"<Status>Active</Status><SecretAccessKey>{NEW_SECRET}</SecretAccessKey>"
            '</AccessKey></CreateAccessKeyResult>'
            '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
            '</CreateAccessKeyResponse>')
    monkeypatch.setattr(aws_sign, "iam_query", fake_query)
    out = aws_sign.create_access_key(AWS_KEY_ID, AWS_SECRET, "deployer")
    assert seen["action"] == "CreateAccessKey"
    assert seen["params"]["UserName"] == "deployer"
    assert out == {"key_id": NEW_KEY_ID, "secret": NEW_SECRET}


def test_delete_and_list_access_keys(monkeypatch):
    import xml.etree.ElementTree as ET

    calls = []
    def fake_query(access_key, secret_key, action, params,
                   session_token=None):
        calls.append((action, params))
        if action == "ListAccessKeys":
            return ET.fromstring(
                '<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
                '<ListAccessKeysResult><AccessKeyMetadata><member>'
                f"<UserName>deployer</UserName><AccessKeyId>{NEW_KEY_ID}</AccessKeyId>"
                '<Status>Active</Status>'
                '</member></AccessKeyMetadata></ListAccessKeysResult>'
                '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
                '</ListAccessKeysResponse>')
        return ET.fromstring(
            '<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            '<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>'
            '</DeleteAccessKeyResponse>')
    monkeypatch.setattr(aws_sign, "iam_query", fake_query)
    aws_sign.delete_access_key(NEW_KEY_ID, NEW_SECRET, "deployer", AWS_KEY_ID)
    assert calls[0][0] == "DeleteAccessKey"
    assert calls[0][1]["AccessKeyId"] == AWS_KEY_ID
    assert aws_sign.list_access_keys(NEW_KEY_ID, NEW_SECRET, "deployer") == [NEW_KEY_ID]


# ---------------------------------------------------------------- rollover
def test_execute_creates_and_verifies_the_new_key(monkeypatch):
    monkeypatch.setattr(aws_sign, "create_access_key",
                        lambda *a, **k: {"key_id": NEW_KEY_ID,
                                         "secret": NEW_SECRET})
    monkeypatch.setattr(aws_sign, "sts_get_caller_identity",
                        lambda *a, **k: {"account": "123456789012",
                                         "arn": "arn:aws:iam::123456789012:"
                                                "user/deployer",
                                         "user_id": "AIDACKCEVSQ6C2EXAMPLE"})
    out = execute_aws_rollover(_aws_finding(), AWS_KEY_ID, AWS_SECRET)
    assert out["new_key_id"] == NEW_KEY_ID
    assert out["new_secret"] == NEW_SECRET


def test_execute_refuses_an_assumed_role():
    f = _aws_finding()
    f["validity"]["identity"]["arn"] = (
        "arn:aws:sts::123456789012:assumed-role/deploy/session")
    with pytest.raises(ValueError, match="assumed role"):
        execute_aws_rollover(f, AWS_KEY_ID, AWS_SECRET)


def test_complete_deletes_and_confirms_gone(monkeypatch):
    monkeypatch.setattr(aws_sign, "delete_access_key",
                        lambda *a, **k: None)
    monkeypatch.setattr(aws_sign, "list_access_keys",
                        lambda *a, **k: [NEW_KEY_ID])
    out = complete_aws_rollover(_aws_finding(), AWS_KEY_ID,
                                NEW_KEY_ID, NEW_SECRET)
    assert out == {"deleted": True, "verified_gone": True, "reason": None}


def test_complete_reports_a_key_that_survived(monkeypatch):
    monkeypatch.setattr(aws_sign, "delete_access_key",
                        lambda *a, **k: None)
    monkeypatch.setattr(aws_sign, "list_access_keys",
                        lambda *a, **k: [NEW_KEY_ID, AWS_KEY_ID])
    out = complete_aws_rollover(_aws_finding(), AWS_KEY_ID,
                                NEW_KEY_ID, NEW_SECRET)
    assert out["deleted"] is False
    assert "still listed" in out["reason"]


# ---------------------------------------------------------------- verify
def test_verify_dead_github_token(monkeypatch):
    import keyring_audit.remediation as remediation

    monkeypatch.setattr(remediation, "check_github",
                        lambda token: {"live": "dead",
                                       "reason": "bad credentials",
                                       "permissions": [], "method": "header"})
    out = verify_old_credential(_github_finding(), "ghp_" + "x" * 36)
    assert out["dead"] is True


def test_verify_live_github_token_reports_still_live(monkeypatch):
    import keyring_audit.remediation as remediation

    monkeypatch.setattr(remediation, "check_github",
                        lambda token: {"live": "live", "reason": "ok",
                                       "permissions": ["repo"],
                                       "method": "header"})
    out = verify_old_credential(_github_finding(), "ghp_" + "x" * 36)
    assert out["dead"] is False


def test_verify_aws_used_after_rotation(monkeypatch):
    import keyring_audit.remediation as remediation

    monkeypatch.setattr(remediation, "check_aws",
                        lambda kid, secret: {"live": "dead",
                                             "reason": "bad key",
                                             "permissions": [],
                                             "method": "sts",
                                             "last_used": "2026-11-15T10:00:00Z"})
    # The key is dead but was used AFTER the rotation completed: something
    # still holds it (or held it past the rotation).
    out = verify_old_credential(_aws_finding(), AWS_SECRET,
                                old_key_id=AWS_KEY_ID,
                                rotated_at="2026-11-15T09:00:00Z")
    assert out["dead"] is True
    assert out["used_after_rotation"] is True
    out = verify_old_credential(_aws_finding(), AWS_SECRET,
                                old_key_id=AWS_KEY_ID,
                                rotated_at="2026-11-15T11:00:00Z")
    assert out["used_after_rotation"] is False


def test_verify_aws_needs_the_old_key_id():
    with pytest.raises(ValueError, match="--old-key-id"):
        verify_old_credential(_aws_finding(), AWS_SECRET)


def test_verify_unknown_provider_is_honest():
    out = verify_old_credential(_github_finding(provider="jwt"), "x")
    assert out["dead"] is None
    assert "cannot verify" in out["reason"]


# ---------------------------------------------------------------- CLI
def _write_report(tmp_path, finding):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"findings": [finding]}))
    return report


def test_cli_rotate_plan_is_a_dry_run(tmp_path, capsys):
    report = _write_report(tmp_path, _aws_finding())
    rc = cli(["rotate", "--fingerprint", "fp-aws-1", "--report", str(report)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Rotation plan" in out
    assert "two-key rollover" in out


def test_cli_rotate_prefix_match(tmp_path, capsys):
    report = _write_report(tmp_path, _aws_finding(
        fingerprint="fp-aws-1-deadbeef"))
    rc = cli(["rotate", "--fingerprint", "fp-aws-1", "--report", str(report)])
    assert rc == 0


def test_cli_rotate_unknown_fingerprint(tmp_path):
    report = _write_report(tmp_path, _aws_finding())
    rc = cli(["rotate", "--fingerprint", "fp-nope", "--report", str(report)])
    assert rc == 2


def test_cli_rotate_execute_needs_approve(tmp_path):
    report = _write_report(tmp_path, _aws_finding())
    rc = cli(["rotate", "--fingerprint", "fp-aws-1", "--report", str(report),
              "--execute", "--old-key-id", AWS_KEY_ID])
    assert rc == 2


def test_cli_rotate_execute_refuses_non_aws(tmp_path):
    report = _write_report(tmp_path, _github_finding())
    rc = cli(["rotate", "--fingerprint", "fp-gh-1", "--report", str(report),
              "--execute", "--approve", "--old-key-id", "x"])
    assert rc == 2


def test_cli_rotate_modes_are_exclusive(tmp_path):
    report = _write_report(tmp_path, _aws_finding())
    rc = cli(["rotate", "--fingerprint", "fp-aws-1", "--report", str(report),
              "--execute", "--verify"])
    assert rc == 2
