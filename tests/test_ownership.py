"""Tests for v0.5 ownership: commit author, git blame, AWS tags, and
the 'no owner' risk factor."""
import os
import subprocess
from pathlib import Path

from keyring_audit.ownership import (
    apply_tag_owner,
    assign_owner,
    assign_owners,
    owner_from_blame,
)
from keyring_audit.ranking import rank
from keyring_audit.report import render

GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"


def _init_repo(path: Path, name="Test Dev", email="dev@example.com"):
    subprocess.run(["git", "init", "-q", str(path)], check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", name], cwd=path,
                   check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", email], cwd=path,
                   check=True, capture_output=True, text=True)


def _commit(path: Path, message="c"):
    env = dict(os.environ,
               GIT_AUTHOR_DATE="2022-03-01T10:00:00+00:00",
               GIT_COMMITTER_DATE="2022-03-01T10:00:00+00:00")
    subprocess.run(["git", "add", "-A"], cwd=path, check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=path, env=env,
                   check=True, capture_output=True, text=True)


def _finding(**over):
    base = {"detector": "github-pat-classic", "provider": "github",
            "redacted": "ghp_…cdef", "fingerprint": "fp1",
            "source": "config.py", "line": 2, "commit": None,
            "author": None, "date": None}
    base.update(over)
    return base


# ---------------------------------------------------------------- sources
def test_owner_from_commit_author(tmp_path):
    f = assign_owner(_finding(author="Test Dev <dev@example.com>",
                              commit="abc123"), tmp_path)
    assert f["owner"] == {"name": "Test Dev <dev@example.com>",
                          "source": "commit"}


def test_owner_from_blame(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(
        "# config\n" + f'TOKEN = "{GITHUB_PAT}"\n')
    _commit(repo)
    f = assign_owner(_finding(), repo)
    assert f["owner"] == {"name": "Test Dev <dev@example.com>",
                          "source": "blame"}


def test_blame_uncommitted_line_uses_local_user(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    subprocess.run(["git", "add", "config.py"], cwd=repo, check=True,
                   capture_output=True, text=True)
    f = assign_owner(_finding(line=1), repo)
    assert f["owner"] == {"name": "Test Dev <dev@example.com>",
                          "source": "blame"}


def test_blame_untracked_file_falls_back_to_local_user(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(f'TOKEN = "{GITHUB_PAT}"\n')
    # Never staged or committed: git cannot blame it, so the local user
    # (who holds the working tree) is the owner.
    f = assign_owner(_finding(line=1), repo)
    assert f["owner"] == {"name": "Test Dev <dev@example.com>",
                          "source": "blame"}


def test_no_owner_when_no_git_user(tmp_path):
    # Not a git repo at all, and no commit author: nobody to ask.
    plain = tmp_path / "plain"
    plain.mkdir()
    f = assign_owner(_finding(line=1), plain)
    assert f["owner"] == {"name": None, "source": "none"}


def test_owner_from_blame_returns_none_without_a_line(tmp_path):
    assert owner_from_blame(tmp_path, "config.py", None) is None
    assert owner_from_blame(tmp_path, "config.py", 0) is None


def test_tag_owner_wins_over_commit(tmp_path):
    f = _finding(author="Test Dev <dev@example.com>", commit="abc123",
                 validity={"live": "live", "reason": "x", "permissions": [],
                           "method": "iam",
                           "owner": {"name": "platform-team",
                                     "source": "aws-tag"}})
    out = apply_tag_owner(f)
    assert out["owner"] == {"name": "platform-team", "source": "aws-tag"}


def test_apply_tag_owner_leaves_other_findings_alone(tmp_path):
    f = _finding(author="Test Dev <dev@example.com>", commit="abc123",
                 validity={"live": "live", "reason": "x", "permissions": [],
                           "method": "header"})
    out = apply_tag_owner(f)
    assert "owner" not in out  # no tag owner, nothing to apply


def test_assign_owners_handles_a_list(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    (repo / "config.py").write_text(
        "# config\n" + f'TOKEN = "{GITHUB_PAT}"\n')
    _commit(repo)
    owned = assign_owners([_finding(), _finding(author="A <a@b.c>",
                                                commit="def456")], repo)
    assert owned[0]["owner"]["source"] == "blame"
    assert owned[1]["owner"] == {"name": "A <a@b.c>", "source": "commit"}


# ---------------------------------------------------------------- scoring
def _ranked(**over):
    base = {"detector": "github-pat-classic", "provider": "github",
            "redacted": "ghp_…cdef", "fingerprint": "fp1",
            "source": "config.py", "line": 3, "commit": "abc123",
            "author": "Dev <dev@example.com>", "date": 1646138400,
            "owner": {"name": "Dev <dev@example.com>", "source": "commit"},
            "validity": {"live": "live", "reason": "authenticated as octocat",
                         "permissions": ["repo", "user"], "method": "header"}}
    base.update(over)
    return rank(base)


def test_owned_credential_scores_zero_on_ownership():
    r = _ranked()
    assert r["risk"]["components"]["ownership"]["score"] == 0


def test_no_owner_adds_ten_points():
    r = _ranked(owner={"name": None, "source": "none"})
    assert r["risk"]["components"]["ownership"]["score"] == 10
    assert "no owner" in r["risk"]["components"]["ownership"]["why"]
    # The same finding with an owner scores 10 less.
    assert r["risk"]["score"] == _ranked()["risk"]["score"] + 10


def test_render_text_shows_owner_and_no_owner():
    owned = render([_ranked()], [], "repo", "text")
    assert "owner: Dev <dev@example.com> (commit)" in owned
    unowned = render([_ranked(owner={"name": None, "source": "none"})],
                     [], "repo", "text")
    assert "owner: none found — nobody to ask to rotate this" in unowned
