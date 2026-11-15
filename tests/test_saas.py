"""Tests for v1.3 SaaS integrations (Phase 6 coverage): OpenAI,
Anthropic, Notion and Hugging Face API keys — detection, validity
(mocked provider endpoints) and privilege scoring.

Test credential values are assembled from fragments, so no literal
key sits in the source (the repo's push-protection rule). The values
are fake (repeating characters), never real credentials.
"""
import pytest

from keyring_audit import saas
from keyring_audit.ranking import rank
from keyring_audit.scanner import _scan_text_lines
from keyring_audit.validity import check_finding

# Fake keys, fragmented. The bodies are repeating characters — no real
# credential has this shape, and no literal key appears in the source.
OPENAI_PROJ = "sk-proj-" + "Ab3dEf7hJk2mN5pQr8tUv0wXy" + "_Z1c4e6g8i0k2m4o6"
OPENAI_LEGACY = "sk-" + "A" * 48
ANTHROPIC = "sk-ant-" + "api03-" + "B" * 80
NOTION = "ntn_" + "C" * 43
NOTION_OLD = "secret_" + "D" * 43
HF = "hf_" + "E" * 34


def _one(line: str, source: str = "config.env"):
    return _scan_text_lines([(1, line)], source)


def test_openai_project_key_detected():
    f = _one(f'OPENAI_API_KEY="{OPENAI_PROJ}"')
    assert [g for g in f if g["detector"] == "openai-project-key"]
    assert not [g for g in f if g["detector"] == "generic-high-entropy"]


def test_openai_legacy_key_detected():
    f = _one(f'OPENAI_API_KEY="{OPENAI_LEGACY}"')
    assert [g for g in f if g["detector"] == "openai-legacy-key"]


def test_anthropic_not_mistaken_for_openai():
    f = _one(f'ANTHROPIC_API_KEY="{ANTHROPIC}"')
    assert [g for g in f if g["detector"] == "anthropic-api-key"]
    assert not [g for g in f if g["provider"] == "openai"]


def test_notion_tokens_detected():
    assert [g for g in _one(f'NOTION_TOKEN="{NOTION}"')
            if g["detector"] == "notion-token"]
    assert [g for g in _one(f'NOTION_TOKEN="{NOTION_OLD}"')
            if g["detector"] == "notion-token"]


def test_huggingface_token_detected():
    f = _one(f'HF_TOKEN="{HF}"')
    assert [g for g in f if g["detector"] == "huggingface-token"]


def _mock_get(body=None, status=None):
    def fake(url, headers):
        if status is not None:
            raise ValueError(status)
        return body or {}
    return fake


def test_check_openai_live(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(
        {"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]}))
    v = saas.check_openai(OPENAI_PROJ)
    assert v["live"] == "live"
    assert "2 visible" in v["permissions"][0]


def test_check_openai_dead(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(status="HTTP 401"))
    assert saas.check_openai(OPENAI_PROJ)["live"] == "dead"


def test_check_openai_network_unknown(monkeypatch):
    monkeypatch.setattr(saas, "_get",
                        _mock_get(status="network error: boom"))
    assert saas.check_openai(OPENAI_PROJ)["live"] == "unknown"


def test_check_anthropic_live(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get({"data": [{"id": "claude-sonnet-4"}]}))
    v = saas.check_anthropic(ANTHROPIC)
    assert v["live"] == "live"


def test_check_anthropic_dead(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(status="HTTP 401"))
    assert saas.check_anthropic(ANTHROPIC)["live"] == "dead"


def test_check_notion_bot_vs_user(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(
        {"type": "bot", "name": "My Bot",
         "bot": {"workspace_name": "Acme"}}))
    v = saas.check_notion(NOTION)
    assert v["live"] == "live"
    assert "type: bot" in v["permissions"]
    assert "workspace: Acme" in v["permissions"]
    monkeypatch.setattr(saas, "_get", _mock_get(
        {"type": "user", "name": "Samir"}))
    v = saas.check_notion(NOTION)
    assert "type: user" in v["permissions"]


def test_check_notion_dead(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(status="HTTP 401"))
    assert saas.check_notion(NOTION)["live"] == "dead"


def test_check_huggingface_write_vs_read(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(
        {"name": "samir", "role": "write"}))
    v = saas.check_huggingface(HF)
    assert v["live"] == "live"
    assert "role: write" in v["permissions"]
    monkeypatch.setattr(saas, "_get", _mock_get(
        {"name": "samir", "role": "read"}))
    assert "role: read" in saas.check_huggingface(HF)["permissions"]


def test_check_huggingface_dead(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get(status="HTTP 401"))
    assert saas.check_huggingface(HF)["live"] == "dead"


def test_ranking_live_ai_key_is_high(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get({"data": [{"id": "gpt-4o"}]}))
    f = _one(f'OPENAI_API_KEY="{OPENAI_PROJ}"')[0]
    ranked = rank(check_finding(f))
    assert ranked["risk"]["components"]["privilege"]["score"] == 35
    # A live AI key in a working tree with no owner and no age or usage
    # data is High (65). It becomes Critical when it is old (age 15)
    # or in git history (exposure 17) — a leaked key that has sat in
    # history is the one to rotate within minutes.
    assert ranked["risk"]["band"] == "High"
    assert ranked["risk"]["score"] == 65


def test_ranking_notion_user_vs_bot(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get({"type": "user"}))
    f = _one(f'NOTION_TOKEN="{NOTION}"')[0]
    assert rank(check_finding(f))["risk"]["components"]["privilege"]["score"] == 35
    monkeypatch.setattr(saas, "_get", _mock_get({"type": "bot"}))
    f = _one(f'NOTION_TOKEN="{NOTION}"')[0]
    assert rank(check_finding(f))["risk"]["components"]["privilege"]["score"] == 25


def test_ranking_huggingface_write_vs_read(monkeypatch):
    monkeypatch.setattr(saas, "_get", _mock_get({"role": "write"}))
    f = _one(f'HF_TOKEN="{HF}"')[0]
    assert rank(check_finding(f))["risk"]["components"]["privilege"]["score"] == 35
    monkeypatch.setattr(saas, "_get", _mock_get({"role": "read"}))
    f = _one(f'HF_TOKEN="{HF}"')[0]
    assert rank(check_finding(f))["risk"]["components"]["privilege"]["score"] == 15
