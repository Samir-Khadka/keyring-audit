"""Tests for v1.4 Slack/GitLab connectors (Phase 6 coverage): enumerate
the non-human identities inside a GitLab instance and a Slack
workspace. The provider APIs are mocked — no network, no real token.
"""
import pytest

from keyring_audit import connectors as conn
from keyring_audit.__main__ import cli
from keyring_audit.ranking import rank

ME = {"username": "samir", "name": "Samir Khadka"}
GROUPS = [{"id": 1, "full_path": "acme"}]
PROJECTS = [{"id": 10, "path_with_namespace": "acme/web"}]
GROUP_TOKENS = [
    {"id": 100, "name": "ci-token", "scopes": ["api"],
     "expires_at": "2027-01-01", "revoked": False,
     "created_at": "2025-06-01T10:00:00.000Z", "last_used_at": None},
    {"id": 101, "name": "old-token", "scopes": ["read_api"],
     "expires_at": "2025-01-01", "revoked": False,
     "created_at": "2024-01-01T10:00:00.000Z", "last_used_at": None},
    {"id": 102, "name": "revoked-token", "scopes": ["api"],
     "expires_at": None, "revoked": True,
     "created_at": "2025-01-01T10:00:00.000Z", "last_used_at": None},
    {"id": 103, "name": "never-expires", "scopes": ["read_repository"],
     "expires_at": None, "revoked": False,
     "created_at": "2025-06-01T10:00:00.000Z", "last_used_at": None},
]
GROUP_DEPLOY = [{"id": 200, "name": "registry", "scopes": ["read_registry"],
                 "expires_at": "2027-01-01", "revoked": False,
                 "created_at": "2025-06-01T10:00:00.000Z"}]
PROJECT_TOKENS = [{"id": 300, "name": "deploy-bot", "scopes": ["write_repository"],
                   "expires_at": "2026-06-01", "revoked": False,
                   "created_at": "2025-06-01T10:00:00.000Z", "last_used_at": None}]
PROJECT_DEPLOY: list = []


def _fake_request(method, url, headers, body=None):
    # _paged_get appends ?page=N&per_page=100; match on the path.
    path = url.split("?")[0]
    if path.endswith("/user"):
        return dict(ME)
    if path.endswith("/groups"):
        return list(GROUPS)
    if path.endswith("/projects"):
        return list(PROJECTS)
    if path.endswith("/groups/1/access_tokens"):
        return list(GROUP_TOKENS)
    if path.endswith("/groups/1/deploy_tokens"):
        return list(GROUP_DEPLOY)
    if path.endswith("/projects/10/access_tokens"):
        return list(PROJECT_TOKENS)
    if path.endswith("/projects/10/deploy_tokens"):
        return list(PROJECT_DEPLOY)
    raise AssertionError(f"unexpected {url}")


def test_gitlab_connectors_enumerates(monkeypatch):
    monkeypatch.setattr(conn, "_request", _fake_request)
    result = conn.gitlab_connectors("tok")
    assert result["identity"]["username"] == "samir"
    assert result["groups"] == 1 and result["projects"] == 1
    by_name = {f["redacted"]: f for f in result["findings"]}
    assert len(result["findings"]) == 6
    assert by_name["ci-token"]["detector"] == "gitlab-group-access-token"
    assert by_name["registry"]["detector"] == "gitlab-group-deploy-token"
    assert by_name["deploy-bot"]["detector"] == "gitlab-project-access-token"
    assert by_name["ci-token"]["validity"]["live"] == "live"
    assert by_name["old-token"]["validity"]["live"] == "dead"  # expired
    assert by_name["revoked-token"]["validity"]["live"] == "dead"
    assert "never expires" in by_name["never-expires"]["validity"]["reason"]
    assert by_name["ci-token"]["owner"]["name"] == "acme"


def test_gitlab_connectors_ranked(monkeypatch):
    monkeypatch.setattr(conn, "_request", _fake_request)
    result = conn.gitlab_connectors("tok")
    from keyring_audit.ranking import rank_all
    ranked = rank_all(result["findings"])
    by_name = {f["redacted"]: f for f in ranked}
    # api scope is admin-level.
    assert by_name["ci-token"]["risk"]["components"]["privilege"]["score"] == 40
    # A deploy token is read-only.
    assert by_name["registry"]["risk"]["components"]["privilege"]["score"] == 15
    # In GitLab, not in code.
    assert by_name["ci-token"]["risk"]["components"]["exposure"]["score"] == 12
    # A dead token scores 0 on privilege.
    assert by_name["old-token"]["risk"]["components"]["privilege"]["score"] == 0


def test_gitlab_connectors_bad_token(monkeypatch):
    def bad(method, url, headers, body=None):
        raise ValueError("HTTP 401")
    monkeypatch.setattr(conn, "_request", bad)
    with pytest.raises(ValueError, match="rejected"):
        conn.gitlab_connectors("bad")


def test_slack_connectors_lists_apps(monkeypatch):
    def fake(method, url, headers, body=None):
        if url.endswith("/auth.test"):
            return {"ok": True, "team": "Acme", "user": "samir",
                    "url": "https://acme.slack.com/", "bot_id": None}
        if url.endswith("/apps.list"):
            return {"ok": True, "apps": [
                {"id": "A1", "name": "Deploy Bot", "is_bot": True},
                {"id": "A2", "name": "GitHub", "is_bot": False}]}
        raise AssertionError(f"unexpected {url}")
    monkeypatch.setattr(conn, "_request", fake)
    result = conn.slack_connectors("xoxp-fake")
    assert result["identity"]["team"] == "Acme"
    assert len(result["apps"]) == 2
    assert result["apps"][0]["name"] == "Deploy Bot"
    assert result["apps"][0]["is_bot"] is True
    assert result["apps_error"] is None


def test_slack_connectors_missing_scope(monkeypatch):
    def fake(method, url, headers, body=None):
        if url.endswith("/auth.test"):
            return {"ok": True, "team": "Acme", "user": "samir",
                    "url": "https://acme.slack.com/"}
        if url.endswith("/apps.list"):
            return {"ok": False, "error": "missing_scope"}
        raise AssertionError(f"unexpected {url}")
    monkeypatch.setattr(conn, "_request", fake)
    result = conn.slack_connectors("xoxb-fake")
    assert result["apps"] == []
    assert "apps:read" in result["apps_error"]
    assert result["identity"]["team"] == "Acme"


def test_slack_connectors_bad_token(monkeypatch):
    def fake(method, url, headers, body=None):
        return {"ok": False, "error": "invalid_auth"}
    monkeypatch.setattr(conn, "_request", fake)
    with pytest.raises(ValueError, match="rejected"):
        conn.slack_connectors("bad")


def test_cli_connectors_gitlab(monkeypatch, capsys):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    monkeypatch.setattr(conn, "_request", _fake_request)
    rc = cli(["connectors", "--gitlab"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ci-token" in out and "never-expires" in out
    assert "never expires" in out


def test_cli_connectors_needs_one_flag(monkeypatch):
    rc = cli(["connectors"])
    assert rc == 2
    rc = cli(["connectors", "--gitlab", "--slack"])
    assert rc == 2
