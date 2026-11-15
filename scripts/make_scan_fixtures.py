"""Generate the scan fixtures deterministically.

Run from the repo root:  python scripts/make_scan_fixtures.py [dest]
With no dest it writes fixtures/repo/ (local/CI use only — never commit
it: the generated files hold literal fake secrets). Tests pass a tmp dir.
Builds fixtures/repo/ — a small git repo with planted FAKE secrets:

- commit 1 (2022-03-01): config.py with a classic GitHub PAT (removed
  in commit 2, so it lives only in history).
- commit 2 (2024-06-15): the working tree — .env with an AWS key pair,
  deploy.sh with a Slack token, keys.txt with a private-key header,
  payments.py with a Stripe live key, README.md (clean).

All secrets are fake: the GitHub token is a fixed pattern, the AWS pair
is the documented AWS example pair from the AWS docs (not a real
credential), and the rest are fixed patterns. The tests assert that
no rendered output ever contains one of these full values.

The fixture repo is generated, never committed: it holds literal fake
secrets, so committing it trips GitHub secret scanning. Tests build it
into a tmp dir; CI regenerates it before the dogfood step.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "repo"

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"  # 36 chars
GITHUB_FINE = "github_pat_" + "11ABCDEFGH1234567890ab" + "_" + "x" * 59
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"
SLACK_TOKEN = "xoxb-" + "abcdefghij-abcdefghij" + "kl-AbCdEfGhIjKlMnOpQrStUvWx"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp"  # 20 chars after sk_live_:
# GitHub's secret-scanning pattern needs 24, so this clearly-fake test
# key does not trip push protection — but it still matches this scanner's
# detector (16+ chars), which is what the fixture is testing.
GITLAB_TOKEN = "glpat-" + "abcdefghij1234567890"


def _run(cmd: list[str], cwd: Path, env: dict | None = None):
    full = dict(os.environ)
    full.update(env or {})
    subprocess.run(cmd, cwd=cwd, env=full, check=True,
                   capture_output=True, text=True)


def _commit(cwd: Path, message: str, date: str):
    env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date,
           "GIT_AUTHOR_NAME": "Test Dev", "GIT_AUTHOR_EMAIL": "dev@example.com",
           "GIT_COMMITTER_NAME": "Test Dev",
           "GIT_COMMITTER_EMAIL": "dev@example.com"}
    _run(["git", "add", "-A"], cwd)
    _run(["git", "commit", "-m", message], cwd, env)


def main(dest: Path | None = None) -> None:
    ROOT = dest or DEFAULT_ROOT
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    _run(["git", "init", "-q"], ROOT)
    # --- commit 1: a GitHub PAT in config.py (removed in commit 2)
    (ROOT / "config.py").write_text(
        f'# config\nGITHUB_TOKEN = "{GITHUB_PAT}"\n')
    (ROOT / "README.md").write_text("# fixture repo\n")
    _commit(ROOT, "add config with token", "2022-03-01T10:00:00+00:00")
    # --- commit 2: remove the token, add the working tree
    (ROOT / "config.py").write_text("# config\nGITHUB_TOKEN = ''\n")
    (ROOT / ".env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n")
    (ROOT / "deploy.sh").write_text(
        f'#!/bin/sh\nSLACK_TOKEN="{SLACK_TOKEN}"\n')
    (ROOT / "keys.txt").write_text(
        "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n")
    (ROOT / "payments.py").write_text(
        f'STRIPE_KEY = "{STRIPE_KEY}"\n')
    (ROOT / "ci.yml").write_text(
        f"gitlab_token: {GITLAB_TOKEN}\n")
    _commit(ROOT, "rotate config, add deploy + payments",
            "2024-06-15T10:00:00+00:00")
    print(f"fixtures written to {ROOT}")
    print("FAKE secrets (never real credentials):")
    print(f"  github: {GITHUB_PAT[:8]}…")
    print(f"  aws: {AWS_KEY_ID}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
