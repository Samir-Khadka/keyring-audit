"""Tests for ranking, remediation guides, report rendering, and the CLI.

Includes the safety-contract test: no rendered output (text, JSON, or
Markdown) may contain a full test secret.
"""
import json
import pytest

from keyring_audit.ranking import rank, rank_all
from keyring_audit.remediation import guide
from keyring_audit.report import public_finding, render
from keyring_audit.__main__ import scan_main

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"


def _finding(**over):
    base = {"detector": "github-pat-classic", "provider": "github",
            "redacted": "ghp_…cdef", "fingerprint": "fp1", "source": "config.py",
            "line": 3, "commit": "abc123", "author": "Dev <dev@example.com>",
            "date": 1646138400,  # 2022-03-01
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live", "reason": "authenticated as octocat",
                         "permissions": ["repo", "user"], "method": "header"}}
    base.update(over)
    return base


# ---------------------------------------------------------------- ranking
def test_admin_scope_scores_critical():
    r = rank(_finding())
    assert r["risk"]["score"] >= 80
    assert r["risk"]["band"] == "Critical"
    assert r["risk"]["components"]["privilege"]["score"] == 40


def test_dead_credential_scores_low():
    r = rank(_finding(validity={"live": "dead", "reason": "401",
                                "permissions": [], "method": "header"}))
    assert r["risk"]["components"]["privilege"]["score"] == 0
    assert r["risk"]["safe_to_kill"] is True


def test_unknown_validity_scores_in_the_middle():
    r = rank(_finding(validity={"live": "unknown", "reason": "?",
                                "permissions": [], "method": "none"}))
    assert r["risk"]["components"]["privilege"]["score"] == 20


def test_working_tree_only_is_lower_exposure_than_history():
    in_history = rank(_finding())
    in_tree = rank(_finding(commit=None))
    assert (in_history["risk"]["components"]["exposure"]["score"]
            > in_tree["risk"]["components"]["exposure"]["score"])


def test_rank_all_sorts_highest_first():
    low = rank(_finding(validity={"live": "dead", "reason": "401",
                                  "permissions": [], "method": "header"}))
    high = rank(_finding())
    ordered = rank_all([low, high])
    assert ordered[0]["risk"]["score"] == high["risk"]["score"]
    assert ordered[1]["risk"]["score"] == low["risk"]["score"]


# ---------------------------------------------------------------- v0.2 providers
def test_slack_write_scope_scores_high():
    r = rank(_finding(provider="slack",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["channels:read", "chat:write"],
                                "method": "auth.test"}))
    assert r["risk"]["components"]["privilege"]["score"] == 35


def test_slack_read_only_scope_scores_lower():
    r = rank(_finding(provider="slack",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["channels:read"],
                                "method": "auth.test"}))
    assert r["risk"]["components"]["privilege"]["score"] == 20


def test_gitlab_api_scope_scores_max():
    r = rank(_finding(provider="gitlab",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["api", "read_user"],
                                "method": "self"}))
    assert r["risk"]["components"]["privilege"]["score"] == 40


def test_gitlab_read_only_scope_scores_low():
    r = rank(_finding(provider="gitlab",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["read_user"],
                                "method": "self"}))
    assert r["risk"]["components"]["privilege"]["score"] == 15


def test_stripe_full_secret_key_scores_max():
    r = rank(_finding(provider="stripe",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["full secret key"],
                                "method": "account"}))
    assert r["risk"]["components"]["privilege"]["score"] == 40


def test_stripe_restricted_key_scores_mid():
    r = rank(_finding(provider="stripe",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["restricted key"],
                                "method": "account"}))
    assert r["risk"]["components"]["privilege"]["score"] == 25


# ---------------------------------------------------------------- v0.4 blast radius
def _aws_finding(blast_radius, permissions=None):
    return _finding(provider="aws", detector="aws-access-key-id",
                    validity={"live": "live", "reason": "x",
                              "permissions": permissions or [],
                              "method": "simulate",
                              "blast_radius": blast_radius})


def test_aws_simulation_privesc_scores_max():
    r = rank(_aws_finding({"method": "simulate",
                           "allowed": ["iam:CreateUser", "iam:PassRole"],
                           "denied": ["s3:DeleteBucket"]}))
    assert r["risk"]["components"]["privilege"]["score"] == 40
    assert "escalate privilege" in r["risk"]["components"]["privilege"]["why"]


def test_aws_simulation_destructive_scores_35():
    r = rank(_aws_finding({"method": "simulate",
                           "allowed": ["s3:DeleteBucket"],
                           "denied": ["iam:CreateUser"]}))
    assert r["risk"]["components"]["privilege"]["score"] == 35
    assert "destroy resources" in r["risk"]["components"]["privilege"]["why"]


def test_aws_simulation_nothing_allowed_scores_low():
    r = rank(_aws_finding({"method": "simulate", "allowed": [],
                           "denied": ["iam:CreateUser"]}))
    assert r["risk"]["components"]["privilege"]["score"] == 10


def test_aws_no_simulation_falls_back_to_policy_names():
    # Simulation not permitted: the policy names decide, as before.
    r = rank(_finding(provider="aws", detector="aws-access-key-id",
                      validity={"live": "live", "reason": "x",
                                "permissions": ["managed policy: AdministratorAccess"],
                                "method": "iam",
                                "blast_radius": {"method": "none",
                                                 "note": "not permitted"}}))
    assert r["risk"]["components"]["privilege"]["score"] == 40


def test_render_text_shows_blast_radius():
    ranked = rank_all([_aws_finding(
        {"method": "simulate", "allowed": ["iam:CreateUser"],
         "denied": ["s3:DeleteBucket"]},
        permissions=["simulated: can iam:CreateUser"])])
    out = render(ranked, [], "fixtures/repo", "text")
    assert "blast radius (simulation): can iam:CreateUser" in out
    assert "partial evidence" in out


# ---------------------------------------------------------------- remediation
def test_github_guide_names_the_revoke_page():
    steps = guide(_finding())
    assert any("github.com/settings/tokens" in s for s in steps)


def test_aws_guide_is_a_two_key_rollover():
    f = _finding(detector="aws-access-key-id", provider="aws",
                 key_id=AWS_KEY_ID)
    steps = guide(f)
    assert any("create-access-key" in s for s in steps)
    assert any("delete-access-key" in s and AWS_KEY_ID in s for s in steps)
    # Never delete first: create comes before delete.
    create_i = next(i for i, s in enumerate(steps) if "create-access-key" in s)
    delete_i = next(i for i, s in enumerate(steps) if "delete-access-key" in s)
    assert create_i < delete_i


def test_dead_credential_guide_says_remove_from_history():
    f = _finding(validity={"live": "dead", "reason": "401",
                           "permissions": [], "method": "header"})
    assert any("git filter-repo" in s for s in guide(f))


# ---------------------------------------------------------------- report + safety contract
def test_public_finding_strips_private_fields():
    f = _finding(_secret=GITHUB_PAT, key_id=AWS_KEY_ID)
    pub = public_finding(f)
    assert "_secret" not in pub
    assert GITHUB_PAT not in json.dumps(pub)
    # The AWS key ID is public (like a username) and stays.
    assert pub["key_id"] == AWS_KEY_ID


def test_no_rendered_output_contains_a_full_secret():
    # The safety contract, enforced: render every format from a finding
    # that carries a real (fake, but full-length) secret in memory, and
    # assert the secret never appears in the output.
    findings = [
        _finding(_secret=GITHUB_PAT),
        _finding(detector="aws-access-key-id", provider="aws",
                 redacted="AKIA…MPLE", fingerprint="fp2", key_id=AWS_KEY_ID,
                 _secret=AWS_SECRET,
                 validity={"live": "live", "reason": "authenticated as arn",
                           "permissions": ["managed policy: AdministratorAccess"],
                           "method": "iam"}),
    ]
    ranked = rank_all([dict(f) for f in findings])
    for fmt in ("text", "json", "md"):
        out = render(ranked, [], "fixtures/repo", fmt)
        assert GITHUB_PAT not in out, fmt
        assert AWS_SECRET not in out, fmt
        assert AWS_KEY_ID in out  # the public ID may appear


def test_render_text_shows_the_ranked_list():
    ranked = rank_all([_finding()])
    out = render(ranked, [], "fixtures/repo", "text")
    assert "CRITICAL" in out
    assert "ghp_…cdef" in out
    assert "can do: repo, user" in out


# ---------------------------------------------------------------- CLI
def test_cli_no_verify_exits_zero_below_threshold(capsys, fixture_repo):
    assert scan_main(["scan", str(fixture_repo), "--no-verify", "--fail-on", "100"]) == 0
    out = capsys.readouterr().out
    assert "6 credential(s) found" in out


def test_cli_exits_one_when_a_live_finding_scores_high(monkeypatch, capsys, fixture_repo):
    # Fake the GitHub check as live with admin scope, so the CLI exits 1.
    # The other providers are faked as unknown so the test stays offline.
    from keyring_audit import validity
    monkeypatch.setattr(validity, "check_github", lambda token, request=None: {
        "live": "live", "reason": "authenticated as octocat",
        "permissions": ["repo"], "method": "header"})
    monkeypatch.setattr(validity, "check_slack", lambda token, request=None: {
        "live": "unknown", "reason": "offline", "permissions": [],
        "method": "auth.test"})
    monkeypatch.setattr(validity, "check_gitlab", lambda token, request=None: {
        "live": "unknown", "reason": "offline", "permissions": [],
        "method": "self"})
    monkeypatch.setattr(validity, "check_stripe", lambda key, request=None: {
        "live": "unknown", "reason": "offline", "permissions": [],
        "method": "account"})
    assert scan_main(["scan", str(fixture_repo), "--fail-on", "60"]) == 1


def test_cli_json_output_is_valid_json(capsys, fixture_repo):
    assert scan_main(["scan", str(fixture_repo), "--no-verify", "--format", "json"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["tool"] == "keyring-audit"
    assert len(doc["findings"]) == 6
    assert all("_secret" not in f for f in doc["findings"])


def test_cli_missing_directory_is_infra(capsys):
    assert scan_main(["scan", "/nonexistent/path"]) == 2


def test_cli_allowlist_ignores_a_fingerprint(tmp_path, fixture_repo):
    from keyring_audit.detectors import fingerprint
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"fingerprints": [fingerprint(GITHUB_PAT)]}))
    # The GitHub PAT is the only history finding; allowlisting it drops
    # the count from 6 to 5.
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = scan_main(["scan", str(fixture_repo), "--no-verify",
                          "--allowlist", str(allow), "--format", "json"])
    doc = json.loads(buf.getvalue())
    assert len(doc["findings"]) == 5
    assert code == 0
