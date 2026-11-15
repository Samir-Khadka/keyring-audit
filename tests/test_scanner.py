"""Tests for the scanner: working tree, git history, AWS pairing, dedup."""
from keyring_audit.scanner import scan, scan_history, scan_working_tree

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"


def test_working_tree_finds_the_env_pair(fixture_repo):
    findings, warnings = scan_working_tree(fixture_repo)
    aws = [f for f in findings if f["detector"] == "aws-access-key-id"]
    assert len(aws) == 1
    assert aws[0]["key_id"] == AWS_KEY_ID
    assert aws[0]["_secret"] == AWS_SECRET  # paired, in memory only
    assert aws[0]["source"] == ".env"
    # The paired secret is NOT a second finding.
    assert not any(f["detector"] == "generic-high-entropy"
                   and f.get("_secret") == AWS_SECRET for f in findings)


def test_history_finds_the_removed_github_token(fixture_repo):
    findings, warnings = scan_history(fixture_repo)
    gh = [f for f in findings if f["detector"] == "github-pat-classic"]
    assert len(gh) == 1
    assert gh[0]["source"] == "config.py"
    assert gh[0]["commit"] is not None  # only in history, not the tree
    assert gh[0]["author"] == "Test Dev <dev@example.com>"
    assert gh[0]["date"] is not None


def test_full_scan_dedups_and_counts_six(fixture_repo):
    result = scan(fixture_repo)
    assert len(result["findings"]) == 6
    detectors = sorted(f["detector"] for f in result["findings"])
    assert detectors == ["aws-access-key-id", "github-pat-classic",
                         "gitlab-pat", "private-key", "slack-token",
                         "stripe-live"]
    # No full secret in any finding's public fields.
    for f in result["findings"]:
        for key in ("redacted", "source", "author"):
            assert GITHUB_PAT not in str(f.get(key, ""))
            assert AWS_SECRET not in str(f.get(key, ""))


def test_history_scan_of_non_repo_warns(tmp_path):
    findings, warnings = scan_history(tmp_path)
    assert findings == []
    assert warnings and "not a git repository" in warnings[0]


def test_working_tree_skips_binary_files(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02" + b"A" * 100)
    (tmp_path / "clean.txt").write_text("nothing here\n")
    findings, warnings = scan_working_tree(tmp_path)
    assert findings == []


def test_unpaired_aws_key_id_has_no_secret(tmp_path):
    (tmp_path / "a.txt").write_text(f"key = {AWS_KEY_ID}\n")
    findings, _ = scan_working_tree(tmp_path)
    assert len(findings) == 1
    assert findings[0]["_secret"] is None
