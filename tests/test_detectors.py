"""Tests for detectors: patterns, entropy, redaction, fingerprinting."""
from keyring_audit.detectors import (
    fingerprint,
    find_generic,
    redact,
    scan_line,
    shannon_entropy,
)

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"
GITHUB_FINE = "github_pat_" + "11ABCDEFGH1234567890ab" + "_" + "x" * 59
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"


def test_github_classic_pat():
    hits = scan_line(f'token = "{GITHUB_PAT}"')
    assert any(h["detector"] == "github-pat-classic" and h["value"] == GITHUB_PAT
               for h in hits)


def test_github_fine_grained_pat():
    hits = scan_line(f'token = "{GITHUB_FINE}"')
    assert any(h["detector"] == "github-pat-fine-grained" for h in hits)


def test_github_oauth_variants():
    for prefix in ("gho_", "ghu_", "ghs_", "ghr_"):
        token = prefix + "A" * 36
        hits = scan_line(f"x = '{token}'")
        assert len(hits) == 1, (prefix, hits)
        assert hits[0]["provider"] == "github"


def test_aws_key_id():
    hits = scan_line(f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}")
    assert any(h["detector"] == "aws-access-key-id" and h["value"] == AWS_KEY_ID
               for h in hits)


def test_slack_and_gitlab_and_stripe():
    assert scan_line("xoxb-" + "abcdefghij-abcdefghij" + "kl-AbCdEfGhIjKlMnOpQrStUvWx")[0]["provider"] == "slack"
    assert scan_line("glpat-abcdefg" + "hij1234567890")[0]["provider"] == "gitlab"
    assert scan_line("sk_live_4eC39HqL" + "yjWDarjtT1zdp7dc")[0]["provider"] == "stripe"


def test_private_key_header():
    hits = scan_line("-----BEGIN RSA " + "PRIVATE KEY-----")
    assert hits and hits[0]["detector"] == "private-key"


def test_jwt():
    token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX" + "VCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
             "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    hits = scan_line(f"Authorization: Bearer {token}")
    assert any(h["detector"] == "jwt" for h in hits)


def test_generic_high_entropy_only_in_assignment_context():
    # A random-looking value with no assignment context is not flagged.
    assert find_generic("wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY") == []
    # In an assignment context it is.
    assert find_generic(f"password = '{AWS_SECRET}'") == [AWS_SECRET]
    # Low-entropy values are not flagged even in context.
    assert find_generic("password = 'hunter2'") == []


def test_shannon_entropy():
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY") > 4.5


def test_redact_never_returns_the_full_value():
    assert redact(GITHUB_PAT) == "ghp_…cdef"
    assert GITHUB_PAT not in redact(GITHUB_PAT)
    assert redact(AWS_SECRET) == "wJal…EKEY"


def test_fingerprint_is_salted_and_deterministic():
    fp1 = fingerprint(GITHUB_PAT)
    fp2 = fingerprint(GITHUB_PAT)
    assert fp1 == fp2
    assert len(fp1) == 64
    assert GITHUB_PAT not in fp1
    # Different values give different fingerprints.
    assert fingerprint(GITHUB_PAT) != fingerprint(AWS_SECRET)
