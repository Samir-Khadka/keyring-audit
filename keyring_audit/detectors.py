"""Secret detectors (Keyring Audit v0.1).

A detector is a named, provider-specific pattern plus an optional
entropy test. Detection is deliberately conservative: a pattern must
match the provider's documented token shape, not just "looks random".
Generic high-entropy strings are only flagged inside an assignment
context (password=, secret=, token=, api_key=, …) so the scanner does
not drown the user in false positives.

Safety: a finding never carries the full secret. ``redact()`` keeps the
first/last 4 characters for identification; ``fingerprint()`` is a
salted SHA-256 used for dedup and allowlisting. The full value exists
only in memory while a detector or a validity check holds it.
"""
from __future__ import annotations

import hashlib
import math
import re

SALT = "keyring-audit-v1"

# Assignment contexts that make a high-entropy string worth flagging.
ASSIGNMENT_KEYS = (
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "api-key", "access_key", "accesskey", "private_key", "client_secret",
    "auth", "bearer", "credentials",
)


def redact(value: str) -> str:
    """First 4 + last 4 characters. Never return the full value."""
    if len(value) <= 8:
        return value[:2] + "…" + value[-2:] if len(value) > 4 else "****"
    return f"{value[:4]}…{value[-4:]}"


def fingerprint(value: str) -> str:
    """Salted SHA-256, for dedup and allowlisting. Not reversible."""
    return hashlib.sha256((SALT + value).encode("utf-8")).hexdigest()


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class Detector:
    """One provider pattern."""

    def __init__(self, name: str, provider: str, pattern: str,
                 group: int = 0, min_entropy: float = 0.0,
                 description: str = ""):
        self.name = name
        self.provider = provider
        self.regex = re.compile(pattern)
        self.group = group
        self.min_entropy = min_entropy
        self.description = description or name

    def find(self, line: str) -> list[str]:
        """All values this detector finds in one line."""
        out = []
        for m in self.regex.finditer(line):
            value = m.group(self.group)
            if self.min_entropy and shannon_entropy(value) < self.min_entropy:
                continue
            out.append(value)
        return out


# --- GitHub ---------------------------------------------------------------
# Classic PATs (ghp_), fine-grained PATs (github_pat_), OAuth (gho_),
# user-to-server (ghu_), server-to-server (ghs_), refresh (ghr_).
# The 36-character body is base62; the fine-grained form is
# github_pat_ + 22 chars + _ + 59 chars.
DETECTORS: list[Detector] = [
    Detector("github-pat-classic", "github", r"ghp_[A-Za-z0-9]{36}",
             description="GitHub classic personal access token"),
    Detector("github-pat-fine-grained", "github",
             r"github_pat_[A-Za-z0-9_]{22,255}",
             description="GitHub fine-grained personal access token"),
    Detector("github-oauth", "github", r"gho_[A-Za-z0-9]{36}",
             description="GitHub OAuth access token"),
    Detector("github-user-to-server", "github", r"ghu_[A-Za-z0-9]{36}",
             description="GitHub user-to-server token"),
    Detector("github-server-to-server", "github", r"ghs_[A-Za-z0-9]{36}",
             description="GitHub server-to-server token"),
    Detector("github-refresh", "github", r"ghr_[A-Za-z0-9]{36}",
             description="GitHub refresh token"),
    # --- AWS ------------------------------------------------------------
    # AKIA = long-lived IAM user key, ASIA = temporary STS credential.
    # The secret is a 40-char base64 string, paired by the scanner (see
    # scanner.py): an ID alone cannot be validated, and TruffleHog pairs
    # them for the same reason.
    Detector("aws-access-key-id", "aws", r"(?:AKIA|ASIA)[A-Z0-9]{16}",
             description="AWS access key ID"),
    # --- Slack ----------------------------------------------------------
    Detector("slack-token", "slack", r"xox[baprs]-[A-Za-z0-9-]{10,}",
             description="Slack token (bot, user, app, refresh, session)"),
    Detector("slack-webhook", "slack",
             r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
             description="Slack incoming webhook URL"),
    # --- GitLab ---------------------------------------------------------
    Detector("gitlab-pat", "gitlab", r"glpat-[A-Za-z0-9_\-]{20}",
             description="GitLab personal access token"),
    # --- Stripe ---------------------------------------------------------
    Detector("stripe-live", "stripe", r"(?:sk|rk)_live_[A-Za-z0-9]{16,}",
             description="Stripe live secret/restricted key"),
    # --- SaaS: AI providers -------------------------------------------
    # OpenAI: project keys (sk-proj-…), service-account and admin keys
    # (sk-svcacct-…, sk-admin-…), and the legacy account-wide key
    # (sk- + 48 alphanumerics, 51 total). The legacy regex cannot match
    # an Anthropic key: sk-ant-… has a dash after "ant", which breaks
    # the 48-char alphanumeric run — but the Anthropic detector is
    # listed first anyway, so a Claude key is never read as OpenAI.
    Detector("anthropic-api-key", "anthropic", r"sk-ant-[A-Za-z0-9_-]{20,}",
             description="Anthropic (Claude) API key"),
    Detector("openai-project-key", "openai",
             r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",
             description="OpenAI project / service-account / admin key"),
    Detector("openai-legacy-key", "openai", r"sk-[A-Za-z0-9]{48}",
             description="OpenAI legacy account-wide API key"),
    # --- SaaS: Notion + Hugging Face ----------------------------------
    # Notion: ntn_… (current, since Sep 2024) or secret_… (older, still
    # works). Notion says to treat tokens as opaque, so the length is
    # a minimum, not an exact count.
    Detector("notion-token", "notion", r"(?:secret_|ntn_)[A-Za-z0-9]{32,}",
             description="Notion integration token"),
    Detector("huggingface-token", "huggingface", r"hf_[A-Za-z0-9]{30,}",
             description="Hugging Face access token"),
    # --- GCP ------------------------------------------------------------
    # A GCP API key: AIza + 35 base64url chars. Detected, but its
    # validity is always "unknown" — whether a key works depends on
    # which APIs are enabled for its project, so a 403 cannot tell a
    # valid key from an invalid one (cloud.py). A service-account key
    # (a JSON file with "type": "service_account") is paired by the
    # scanner, like an AWS key/secret pair.
    Detector("gcp-api-key", "gcp", r"AIza[0-9A-Za-z_-]{35}",
             description="GCP API key"),
    # --- Azure ----------------------------------------------------------
    # An Azure service-principal client secret has no fixed shape — it
    # is paired by the scanner with a nearby client_id and tenant_id,
    # like an AWS key/secret pair.
    # --- Private keys ---------------------------------------------------
    Detector("private-key", "generic",
             r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
             description="Private key header (the key itself follows)"),
    # --- JWT ------------------------------------------------------------
    Detector("jwt", "generic",
             r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*",
             description="JSON Web Token (validity cannot be checked offline)"),
]

# A 40-char base64 string is an AWS secret candidate — but only in one
# of two shapes, so the regex cannot grab a window starting mid-token
# (e.g. "KEY=<secret>" is one 44-char run, not a 40-char secret):
#   1. assigned:  secret = <40 base64 chars>  (the value after '=')
#   2. bare: a 40-char base64 run bounded by non-base64 chars, near an
#      AWS key ID (within PAIR_WINDOW lines).
# The pairing is done in scanner.py; these regexes are exported for it.
AWS_SECRET_ASSIGNED_RE = re.compile(
    r"(?i)secret[A-Za-z0-9_]*\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")
AWS_SECRET_BARE_RE = re.compile(
    r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")

# Generic high-entropy secret: a long random-looking value on the right
# of an assignment. Entropy >= 4.5 bits/char and length >= 20 keeps the
# false-positive rate low; the assignment context is what makes it a
# secret rather than a hash or a UUID.
_GENERIC_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth|bearer)\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9/+=._\-]{20,})['\"]?")


def find_generic(line: str) -> list[str]:
    """High-entropy values in an assignment context."""
    out = []
    for m in _GENERIC_RE.finditer(line):
        value = m.group(1).rstrip(".,;")
        if len(value) >= 20 and shannon_entropy(value) >= 4.5:
            # Skip values that are clearly not secrets.
            if value.lower() in ("true", "false", "null", "none"):
                continue
            out.append(value)
    return out


def scan_line(line: str) -> list[dict]:
    """All detector hits in one line: [{detector, provider, value}]."""
    hits = []
    for d in DETECTORS:
        for value in d.find(line):
            hits.append({"detector": d.name, "provider": d.provider,
                         "value": value})
    for value in find_generic(line):
        # Don't double-report a value a specific detector already caught.
        if not any(h["value"] == value for h in hits):
            hits.append({"detector": "generic-high-entropy",
                         "provider": "generic", "value": value})
    return hits
