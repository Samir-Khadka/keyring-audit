"""Tests for v0.3: --repo (remote clone), --staged (pre-commit scan),
and install-hook."""
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from keyring_audit.__main__ import scan_main
from keyring_audit.scanner import _sanitize_url, scan_staged

ROOT = Path(__file__).parent.parent
GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True,
                   capture_output=True, text=True)


def _stage(path: Path, name: str, content: str) -> None:
    (path / name).write_text(content)
    subprocess.run(["git", "add", name], cwd=path, check=True,
                   capture_output=True, text=True)


# ---------------------------------------------------------------- --staged
def test_scan_staged_finds_a_staged_secret(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    _stage(repo, "config.py", f'TOKEN = "{GITHUB_PAT}"\n')
    assert scan_main(["scan", str(repo), "--staged", "--no-verify"]) == 1
    assert "1 credential(s) found" in capsys.readouterr().out


def test_scan_staged_ignores_unstaged_changes(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    # The secret is in the working tree but NOT staged — not the hook's
    # business, and a full scan would catch it separately.
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    assert scan_main(["scan", str(repo), "--staged", "--no-verify"]) == 0
    assert "0 credential(s) found" in capsys.readouterr().out


def test_scan_staged_clean_staging_exits_zero(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    _stage(repo, "app.py", 'print("hello")\n')
    assert scan_main(["scan", str(repo), "--staged", "--no-verify"]) == 0
    assert "0 credential(s) found" in capsys.readouterr().out


def test_scan_staged_reports_real_line_numbers(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    _stage(repo, "config.py",
           "# header\n# comment\n" + f'TOKEN = "{GITHUB_PAT}"\n')
    result = scan_staged(repo)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["line"] == 3
    assert result["findings"][0]["source"] == "config.py"


def test_scan_staged_not_a_repo_is_a_warning(tmp_path):
    result = scan_staged(tmp_path)
    assert result["findings"] == []
    assert any("not a git repository" in w for w in result["warnings"])


# ---------------------------------------------------------------- --repo
def test_scan_repo_clones_a_local_path(fixture_repo, capsys):
    # A local path is a valid clone source — the same code path as a
    # remote URL, without touching the network.
    assert scan_main(["scan", "--repo", str(fixture_repo), "--no-verify"]) == 0
    assert "6 credential(s) found" in capsys.readouterr().out


def test_scan_repo_bad_url_is_infra(capsys):
    assert scan_main(["scan", "--repo", "/nonexistent/path/repo"]) == 2


def test_scan_repo_sanitizes_credentials_in_url():
    assert _sanitize_url("https://user:token123@github.com/o/r.git") == \
        "https://github.com/o/r.git"
    assert _sanitize_url("https://github.com/o/r.git") == \
        "https://github.com/o/r.git"


def test_scan_repo_and_staged_cannot_combine():
    assert scan_main(["scan", "--repo", "https://example.com/r.git",
                      "--staged"]) == 2


# ---------------------------------------------------------------- install-hook
def _hook_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    return repo


def test_install_hook_writes_an_executable_hook(tmp_path):
    repo = _hook_repo(tmp_path)
    assert scan_main(["install-hook", "--path", str(repo)]) == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert hook.stat().st_mode & stat.S_IXUSR
    text = hook.read_text()
    assert "scan --staged" in text
    assert "keyring-audit" in text


def test_install_hook_refuses_to_overwrite(tmp_path):
    repo = _hook_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho existing\n")
    assert scan_main(["install-hook", "--path", str(repo)]) == 2
    assert "existing" in hook.read_text()  # untouched
    assert scan_main(["install-hook", "--path", str(repo), "--force"]) == 0
    assert "scan --staged" in hook.read_text()


def test_install_hook_refuses_non_repo(tmp_path):
    assert scan_main(["install-hook", "--path", str(tmp_path)]) == 2


def test_installed_hook_blocks_a_commit_with_a_staged_secret(tmp_path):
    repo = _hook_repo(tmp_path)
    assert scan_main(["install-hook", "--path", str(repo)]) == 0
    _stage(repo, "config.py", f'TOKEN = "{GITHUB_PAT}"\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    proc = subprocess.run([str(repo / ".git" / "hooks" / "pre-commit")],
                          cwd=repo, env=env, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "1 credential(s) found" in proc.stdout


def test_installed_hook_allows_a_clean_commit(tmp_path):
    repo = _hook_repo(tmp_path)
    assert scan_main(["install-hook", "--path", str(repo)]) == 0
    _stage(repo, "app.py", 'print("hello")\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    proc = subprocess.run([str(repo / ".git" / "hooks" / "pre-commit")],
                          cwd=repo, env=env, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "0 credential(s) found" in proc.stdout
