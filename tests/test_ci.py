"""Tests for v1.1 CI/CD variables (Phase 6 coverage): the Actions
secrets listing, the workflow cross-reference, and the `ci-secrets`
command. The GitHub API is mocked — no network."""
import base64
import json
from pathlib import Path

import pytest

from keyring_audit import ci as ci_mod
from keyring_audit.__main__ import cli
from keyring_audit.ranking import rank

WORKFLOW = """name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.DEPLOY_KEY }} | deploy
      - run: echo ${{secrets.API_TOKEN}}
"""


def test_workflow_secret_refs():
    refs = ci_mod.workflow_secret_refs(WORKFLOW)
    assert refs == {"DEPLOY_KEY", "API_TOKEN"}


def test_list_actions_secrets_paginates():
    calls = []

    def fake_request(token, method, path, payload=None):
        calls.append(path)
        # "&page=1" (not "page=1": "per_page=100" contains "page=1").
        if "&page=1" in path:
            return {"secrets": [{"name": f"S{i}", "created_at": "2025-01-01T00:00:00Z",
                                 "updated_at": "2025-01-01T00:00:00Z"}
                                for i in range(100)]}
        return {"secrets": [{"name": "S100", "created_at": "2025-01-01T00:00:00Z",
                             "updated_at": "2025-01-01T00:00:00Z"}]}

    secrets = ci_mod.list_actions_secrets("o", "r", "tok",
                                          request=fake_request)
    assert len(secrets) == 101
    assert len(calls) == 2
    assert "per_page=100" in calls[0]


def test_build_ci_findings_used_vs_unused():
    secrets = [
        {"name": "DEPLOY_KEY", "created_at": "2025-01-01T00:00:00Z",
         "updated_at": "2026-11-01T00:00:00Z"},
        {"name": "OLD_TOKEN", "created_at": "2024-01-01T00:00:00Z",
         "updated_at": "2024-01-01T00:00:00Z"},
    ]
    findings = ci_mod.build_ci_findings("o", "r", secrets,
                                        {"ci.yml": WORKFLOW})
    by_name = {f["redacted"]: f for f in findings}
    used = by_name["DEPLOY_KEY"]
    assert used["used_in"] == ["ci.yml"]
    assert used["usage_override"][0] == 8
    unused = by_name["OLD_TOKEN"]
    assert unused["used_in"] == []
    assert unused["usage_override"][0] == 15
    assert unused["validity"]["live"] == "unknown"
    # The name is metadata, not a secret — it is shown, and the
    # fingerprint is of the repo+name, not of a value.
    assert unused["fingerprint"]
    assert unused["exposure_source"] == "ci"


def test_build_ci_findings_ranked(tmp_path):
    secrets = [{"name": "OLD_TOKEN", "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"}]
    findings = ci_mod.build_ci_findings("o", "r", secrets, {})
    ranked = rank(findings[0])
    # Stale (over 2 years since the last rotation) + unused + no owner.
    assert ranked["risk"]["components"]["age"]["score"] == 15
    assert ranked["risk"]["components"]["usage"]["score"] == 15
    assert ranked["risk"]["components"]["exposure"]["score"] == 12
    assert ranked["risk"]["components"]["ownership"]["score"] == 10
    assert ranked["risk"]["score"] >= 60


def test_load_workflows_local(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    (repo / ".github" / "workflows" / "notes.txt").write_text("not a workflow")
    workflows = ci_mod.load_workflows_local(repo)
    assert list(workflows) == ["ci.yml"]
    assert "DEPLOY_KEY" in workflows["ci.yml"]


def test_load_workflows_api():
    def fake_request(token, method, path, payload=None):
        if path.endswith("/contents/.github/workflows"):
            return [{"name": "ci.yml", "type": "file"},
                    {"name": "notes.txt", "type": "file"}]
        if path.endswith("/ci.yml"):
            return {"content": base64.b64encode(WORKFLOW.encode()).decode()}
        raise AssertionError(f"unexpected {path}")

    workflows = ci_mod.load_workflows_api("o", "r", "tok",
                                          request=fake_request)
    assert list(workflows) == ["ci.yml"]
    assert "DEPLOY_KEY" in workflows["ci.yml"]


def test_load_workflows_api_no_workflows_dir():
    def fake_request(token, method, path, payload=None):
        raise ValueError("not found")

    assert ci_mod.load_workflows_api("o", "r", "tok",
                                     request=fake_request) == {}


def test_cli_ci_secrets(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(ci_mod, "list_actions_secrets",
                        lambda o, r, t: [
                            {"name": "DEPLOY_KEY",
                             "created_at": "2025-01-01T00:00:00Z",
                             "updated_at": "2026-11-01T00:00:00Z"},
                            {"name": "OLD_TOKEN",
                             "created_at": "2024-01-01T00:00:00Z",
                             "updated_at": "2024-01-01T00:00:00Z"}])
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    rc = cli(["ci-secrets", "--repo", "o/r", "--path", str(repo)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DEPLOY_KEY" in out and "OLD_TOKEN" in out
    assert "no workflow — safe to remove" in out
    assert "safe to remove: yes" in out


def test_cli_ci_secrets_bad_repo(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    rc = cli(["ci-secrets", "--repo", "not-a-repo"])
    assert rc == 2
