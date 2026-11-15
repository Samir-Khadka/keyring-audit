"""Tests for v0.7 PR automation: transformers, the fix flow, and the
GitHub PR calls (mocked — no network)."""
import json
import subprocess
from pathlib import Path

import pytest

from keyring_audit import github as github_mod
from keyring_audit.__main__ import cli
from keyring_audit.fix import (
    build_pr_body,
    build_pr_title,
    env_var_name,
    find_occurrences,
    fix_credential,
    open_fix_pr,
    parse_github_remote,
    transform_file,
)

# Fragmented on purpose: the full literals trip GitHub push protection
# (see the v0.1 push saga). The runtime values are fake test secrets.
GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"
AWS_KEY_ID = "AKIAIOSFOD" + "NN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDEN" + "G/bPxRfiCYEXAMPLEKEY"


def _gh_finding(**over):
    base = {"detector": "github-pat-classic", "provider": "github",
            "redacted": "ghp_…cdef", "fingerprint": "fp-gh-1",
            "source": "config.py", "line": 2, "commit": None,
            "author": None, "date": None,
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live", "reason": "ok",
                         "permissions": ["repo"], "method": "header"}}
    base.update(over)
    return base


def _aws_finding(**over):
    base = {"detector": "aws-access-key-id", "provider": "aws",
            "redacted": "AKIA…MPLE", "fingerprint": "fp-aws-1",
            "source": ".env", "line": 2, "commit": None,
            "author": None, "date": None, "key_id": AWS_KEY_ID,
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live", "reason": "ok",
                         "permissions": [], "method": "iam",
                         "identity": {"arn": "arn:aws:iam::123456789012:"
                                            "user/deployer"}}}
    base.update(over)
    return base


# ---------------------------------------------------------------- transformers
def test_python_assignment_becomes_os_environ():
    new, changed, manual = transform_file(
        Path("config.py"), f'TOKEN = "{GITHUB_PAT}"\n',
        GITHUB_PAT, _gh_finding())
    assert changed == 1 and not manual
    assert new == 'import os\nTOKEN = os.environ["TOKEN"]\n'


def test_python_keeps_an_existing_import_os():
    new, changed, _ = transform_file(
        Path("config.py"),
        f'import os\n\nTOKEN = "{GITHUB_PAT}"\n',
        GITHUB_PAT, _gh_finding())
    assert new.count("import os") == 1
    assert 'TOKEN = os.environ["TOKEN"]' in new


def test_python_dict_value_is_a_manual_note():
    new, changed, manual = transform_file(
        Path("config.py"), f'cfg = {{"token": "{GITHUB_PAT}"}}\n',
        GITHUB_PAT, _gh_finding())
    assert changed == 0
    assert len(manual) == 1 and "not a simple assignment" in manual[0]
    assert GITHUB_PAT in new  # unchanged


def test_env_line_becomes_a_comment():
    new, changed, manual = transform_file(
        Path(".env"), f'AWS_SECRET_ACCESS_KEY="{AWS_SECRET}"\n',
        AWS_SECRET, _aws_finding())
    assert changed == 1 and not manual
    assert AWS_SECRET not in new
    assert new.startswith("# AWS_SECRET_ACCESS_KEY is set in the deployment")


def test_shell_assignment_keeps_export():
    new, changed, _ = transform_file(
        Path("deploy.sh"), f'export TOKEN="{GITHUB_PAT}"\n',
        GITHUB_PAT, _gh_finding())
    assert new == 'export TOKEN="${TOKEN}"\n'


def test_js_const_becomes_process_env():
    new, changed, _ = transform_file(
        Path("app.js"), f'const token = "{GITHUB_PAT}";\n',
        GITHUB_PAT, _gh_finding())
    assert new == 'const token = process.env.TOKEN;\n'


def test_yaml_key_becomes_env_reference():
    new, changed, _ = transform_file(
        Path("ci.yml"), f'token: "{GITHUB_PAT}"\n',
        GITHUB_PAT, _gh_finding())
    assert new == 'token: ${TOKEN}\n'


def test_workflow_yaml_uses_github_secrets():
    new, changed, _ = transform_file(
        Path(".github/workflows/ci.yml"), f'token: "{GITHUB_PAT}"\n',
        GITHUB_PAT, _gh_finding())
    assert new == 'token: ${{ secrets.TOKEN }}\n'


def test_json_is_refused():
    with pytest.raises(ValueError, match="unsupported file type"):
        transform_file(Path("config.json"),
                       f'{{"token": "{GITHUB_PAT}"}}\n',
                       GITHUB_PAT, _gh_finding())


def test_env_var_name_from_the_line():
    assert env_var_name(_gh_finding(), 'TOKEN = "x"') == "TOKEN"
    assert env_var_name(_aws_finding(),
                        'AWS_SECRET_ACCESS_KEY="x"') == \
        "AWS_SECRET_ACCESS_KEY"
    assert env_var_name(_gh_finding(), '  "token": "x"') == "TOKEN"


# ---------------------------------------------------------------- fix flow
def _init_repo(path: Path):
    subprocess.run(["git", "init", "-q", str(path)], check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test Dev"], cwd=path,
                   check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"],
                   cwd=path, check=True, capture_output=True, text=True)


def test_find_occurrences_and_fix(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    (repo / "deploy.sh").write_text(f'TOKEN="{GITHUB_PAT}"\n')
    hits = find_occurrences(repo, GITHUB_PAT)
    assert len(hits) == 2
    fix = fix_credential(repo, _gh_finding(), [GITHUB_PAT])
    assert fix["changed_files"] == 2
    assert fix["occurrences"] == 2
    assert fix["env_vars"] == ["TOKEN"]
    assert 'os.environ["TOKEN"]' in fix["files"]["config.py"]
    assert '"${TOKEN}"' in fix["files"]["deploy.sh"]
    # Nothing was written to disk by the fix itself.
    assert GITHUB_PAT in (repo / "config.py").read_text()


def test_fix_aws_replaces_both_values(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / ".env").write_text(
        f'AWS_ACCESS_KEY_ID="{AWS_KEY_ID}"\n'
        f'AWS_SECRET_ACCESS_KEY="{AWS_SECRET}"\n')
    fix = fix_credential(repo, _aws_finding(), [AWS_KEY_ID, AWS_SECRET])
    assert fix["changed_files"] == 1
    assert AWS_KEY_ID not in fix["files"][".env"]
    assert AWS_SECRET not in fix["files"][".env"]
    assert fix["env_vars"] == ["AWS_ACCESS_KEY_ID",
                               "AWS_SECRET_ACCESS_KEY"]


def test_fix_history_only_value_is_refused(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text("# no secrets here\n")
    with pytest.raises(ValueError, match="only in history"):
        fix_credential(repo, _gh_finding(), [GITHUB_PAT])


# ---------------------------------------------------------------- PR body + remote
def test_pr_body_is_redacted_and_names_the_env_var():
    fix = {"files": {"config.py": 'TOKEN = os.environ["TOKEN"]\n'},
           "manual": [], "env_vars": ["TOKEN"], "occurrences": 1,
           "changed_files": 1}
    body = build_pr_body(_gh_finding(), fix)
    assert GITHUB_PAT not in body
    assert "ghp_…cdef" in body
    assert "`TOKEN`" in body
    assert "rotate --fingerprint fp-gh-1" in body
    assert build_pr_title(_gh_finding()).startswith(
        "Replace hardcoded github credential")


def test_parse_github_remote():
    assert parse_github_remote(
        "https://github.com/Samir-Khadka/keyring-audit.git") == \
        ("Samir-Khadka", "keyring-audit")
    assert parse_github_remote(
        "git@github.com:Samir-Khadka/keyring-audit.git") == \
        ("Samir-Khadka", "keyring-audit")
    assert parse_github_remote("https://gitlab.com/a/b.git") is None
    assert parse_github_remote("not-a-url") is None


def test_open_fix_pr_calls_the_api_in_order(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    subprocess.run(["git", "remote", "add", "origin",
                    "https://github.com/Samir-Khadka/keyring-audit.git"],
                   cwd=repo, check=True, capture_output=True, text=True)
    calls: list[tuple[str, str]] = []

    def fake_request(token, method, path, payload=None):
        calls.append((method, path))
        if path == "/repos/Samir-Khadka/keyring-audit":
            return {"default_branch": "main"}
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "base-sha"}}
        if path.endswith("/git/ref/heads/keyring-audit/fix-fp-gh-1"):
            raise ValueError("not found")
        if path.endswith("/git/refs"):
            return {"ref": "refs/heads/keyring-audit/fix-fp-gh-1"}
        if path.endswith("/git/blobs"):
            return {"sha": "blob-sha"}
        if path.endswith("/git/trees"):
            return {"sha": "tree-sha"}
        if path.endswith("/git/commits"):
            return {"sha": "commit-sha"}
        if path.endswith("/git/refs/heads/keyring-audit/fix-fp-gh-1"):
            return {}
        if path.endswith("/pulls"):
            return {"html_url": "https://github.com/Samir-Khadka/"
                                "keyring-audit/pull/1", "number": 1}
        raise AssertionError(f"unexpected call {method} {path}")

    monkeypatch.setattr(github_mod, "request", fake_request)
    fix = {"files": {"config.py": 'TOKEN = os.environ["TOKEN"]\n'},
           "manual": [], "env_vars": ["TOKEN"], "occurrences": 1,
           "changed_files": 1}
    pr = open_fix_pr(repo, _gh_finding(), fix, "tok")
    assert pr["number"] == 1
    assert pr["html_url"].endswith("/pull/1")
    methods = [m for m, _ in calls]
    assert methods[0] == "GET"  # default branch first
    assert ("POST", "/repos/Samir-Khadka/keyring-audit/pulls") in calls


def test_open_fix_pr_refuses_an_existing_branch(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    subprocess.run(["git", "remote", "add", "origin",
                    "https://github.com/Samir-Khadka/keyring-audit.git"],
                   cwd=repo, check=True, capture_output=True, text=True)

    def fake_request(token, method, path, payload=None):
        if path == "/repos/Samir-Khadka/keyring-audit":
            return {"default_branch": "main"}
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "base-sha"}}
        if path.endswith("/git/ref/heads/keyring-audit/fix-fp-gh-1"):
            return {"object": {"sha": "existing-sha"}}
        raise AssertionError(f"unexpected call {method} {path}")

    monkeypatch.setattr(github_mod, "request", fake_request)
    fix = {"files": {"config.py": "x"}, "manual": [], "env_vars": [],
           "occurrences": 1, "changed_files": 1}
    with pytest.raises(ValueError, match="already exists"):
        open_fix_pr(repo, _gh_finding(), fix, "tok")


# ---------------------------------------------------------------- CLI
def test_cli_fix_dry_run_changes_nothing(tmp_path, capsys):
    from keyring_audit.detectors import fingerprint

    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "commit", "-q", "-m", "c"], cwd=repo,
                   check=True, capture_output=True, text=True)
    rc = cli(["fix", "--fingerprint", fingerprint(GITHUB_PAT),
              "--path", str(repo)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert 'os.environ["TOKEN"]' in out
    assert GITHUB_PAT not in out  # the secret never appears in output
    assert "PR title:" in out
    # The file on disk is untouched by a dry run.
    assert GITHUB_PAT in (repo / "config.py").read_text()


def test_cli_fix_approve_opens_the_pr(monkeypatch, tmp_path, capsys):
    from keyring_audit.detectors import fingerprint

    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "commit", "-q", "-m", "c"], cwd=repo,
                   check=True, capture_output=True, text=True)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    import keyring_audit.__main__ as main_mod

    monkeypatch.setattr(main_mod, "open_fix_pr",
                        lambda *a, **k: {"html_url": "https://github.com/x/y/pull/1",
                                         "number": 1})
    rc = cli(["fix", "--fingerprint", fingerprint(GITHUB_PAT),
              "--path", str(repo), "--approve"])
    assert rc == 0
    assert "PR opened: https://github.com/x/y/pull/1" in \
        capsys.readouterr().out
    # The working tree is still untouched — the change lives in the PR.
    assert GITHUB_PAT in (repo / "config.py").read_text()


def test_cli_fix_unknown_fingerprint(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text("# clean\n")
    rc = cli(["fix", "--fingerprint", "fp-nope", "--path", str(repo)])
    assert rc == 2
