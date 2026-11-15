"""Tests for v0.8 agent identities (Phase 5): the gateway policy
extractor, the audit-log chain check, the identity graph, and the
`agents` command. No network, no real gateway — the fixture is a
small gateway-shaped directory built in a temp dir."""
import hashlib
import json
from pathlib import Path

import pytest

from keyring_audit import agents as agents_mod
from keyring_audit.__main__ import cli

SUPPORT_POLICY = """# A support bot: it may send email and refund, so it is the
# dangerous one in the fixture.
agent: support-bot
risk_tier: high
allow:
  - tool: crm.read_customer
    limits: { max_rows: 50 }
  - tool: email.send
  - tool: crm.refund
deny_when_tainted:
  - tool: email.send
egress_allowlist: ["company.com"]
budgets:
  max_calls: 200
"""

ANALYST_POLICY = """agent: analyst-bot
risk_tier: low
allow:
  - tool: crm.read_customer
    limits: { max_rows: 50 }
  - tool: web.fetch
budgets:
  max_calls: 200
"""

SUPPORT_KEY = "demo-key-support-bot"
ANALYST_KEY = "demo-key-analyst-bot"


def _hash_entry(entry: dict) -> str:
    """The gateway's audit-log hash, computed independently here so
    the test checks the implementation against the documented
    algorithm (SHA-256 of the entry dict minus `hash`, sorted keys,
    compact separators)."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()


def _audit_entry(seq: int, agent: str, tool: str, decision: str,
                 ts: str, prev: str) -> dict:
    entry = {"seq": seq, "ts": ts, "agent": agent, "tool": tool,
             "args": {}, "decision": decision, "reason": "",
             "result": "", "tainted": False, "prev_hash": prev}
    entry["hash"] = _hash_entry(entry)
    return entry


def _gateway(tmp_path: Path, with_keys: bool = True) -> Path:
    root = tmp_path / "gateway"
    (root / "policies").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "policies" / "support-bot.yaml").write_text(SUPPORT_POLICY)
    (root / "policies" / "analyst-bot.yaml").write_text(ANALYST_POLICY)
    entries = []
    prev = "0" * 64
    for i, (agent, tool, decision, ts) in enumerate([
            ("support-bot", "crm.read_customer", "allow",
             "2026-11-14T10:00:00+00:00"),
            ("support-bot", "email.send", "allow",
             "2026-11-14T10:05:00+00:00"),
            ("support-bot", "crm.refund", "deny",
             "2026-11-14T10:06:00+00:00"),
            ("support-bot", "crm.refund", "deny",
             "2026-11-14T10:07:00+00:00"),
            ("support-bot", "email.send", "allow",
             "2026-11-15T09:00:00+00:00")], start=1):
        entry = _audit_entry(i, agent, tool, decision, ts, prev)
        entries.append(entry)
        prev = entry["hash"]
    (root / "data" / "audit.jsonl").write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n")
    if with_keys:
        (root / "keys.json").write_text(json.dumps(
            {SUPPORT_KEY: "support-bot", ANALYST_KEY: "analyst-bot"}))
    return root


# ---------------------------------------------------------------- extractors
def test_extract_policy_reads_agent_tier_and_tools():
    policy = agents_mod.extract_policy(SUPPORT_POLICY)
    assert policy["agent"] == "support-bot"
    assert policy["risk_tier"] == "high"
    assert policy["allowed_tools"] == ["crm.read_customer", "email.send",
                                       "crm.refund"]


def test_extract_policy_read_only_agent():
    policy = agents_mod.extract_policy(ANALYST_POLICY)
    assert policy["allowed_tools"] == ["crm.read_customer", "web.fetch"]
    assert policy["risk_tier"] == "low"


def test_load_keys_from_file_and_env(tmp_path, monkeypatch):
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps({SUPPORT_KEY: "support-bot"}))
    assert agents_mod.load_keys(keys_file) == {SUPPORT_KEY: "support-bot"}
    monkeypatch.setenv("AGENT_KEYS",
                       json.dumps({ANALYST_KEY: "analyst-bot"}))
    assert agents_mod.load_keys() == {ANALYST_KEY: "analyst-bot"}
    monkeypatch.delenv("AGENT_KEYS")
    assert agents_mod.load_keys() == {}


# ---------------------------------------------------------------- audit log
def test_audit_log_chain_verifies_and_aggregates(tmp_path):
    root = _gateway(tmp_path)
    audit = agents_mod.load_audit_log([root / "data" / "audit.jsonl"])
    assert audit["events"] == 5
    assert audit["chain_ok"] is True
    assert audit["chain_error"] == ""
    use = audit["usage"]["support-bot"]
    assert use["calls"] == 5
    assert use["allowed"] == 3
    assert use["denied"] == 2
    assert use["denied_tools"] == ["crm.refund"]
    assert use["last_used"] == "2026-11-15T09:00:00+00:00"
    assert "analyst-bot" not in audit["usage"]


def test_audit_log_tamper_breaks_the_chain(tmp_path):
    root = _gateway(tmp_path)
    path = root / "data" / "audit.jsonl"
    lines = path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "crm.refund"  # the stored hash no longer matches
    lines[1] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")
    audit = agents_mod.load_audit_log([path])
    assert audit["chain_ok"] is False
    assert "hash does not match" in audit["chain_error"]


# ---------------------------------------------------------------- identities
def _identities(tmp_path):
    root = _gateway(tmp_path)
    keys = agents_mod.load_keys(root / "keys.json")
    policies = agents_mod.load_policies(root / "policies")
    audit = agents_mod.load_audit_log([root / "data" / "audit.jsonl"])
    return agents_mod.build_agent_identities(keys, policies, audit), audit


def test_support_bot_scores_high_and_analyst_is_safe_to_kill(tmp_path):
    identities, _ = _identities(tmp_path)
    by_agent = {i["agent"]: i for i in identities}
    support = by_agent["support-bot"]
    assert support["risk"]["score"] >= 60  # dangerous tools + high tier
    assert support["risk"]["band"] in ("High", "Critical")
    assert support["risk"]["safe_to_kill"] is False
    assert any("denied attempt" in n for n in support["notes"])
    analyst = by_agent["analyst-bot"]
    assert analyst["risk"]["score"] < 60
    assert analyst["risk"]["safe_to_kill"] is True  # never used
    assert any("never used" in n for n in analyst["notes"])
    # The key fingerprint is present, the key itself never is.
    assert support["key_fingerprint"]
    assert support["key_redacted"].startswith("demo")
    for ident in identities:
        assert SUPPORT_KEY not in json.dumps(ident)
        assert ANALYST_KEY not in json.dumps(ident)


def test_agent_without_a_key_is_still_reported(tmp_path):
    root = _gateway(tmp_path, with_keys=False)
    policies = agents_mod.load_policies(root / "policies")
    audit = agents_mod.load_audit_log([root / "data" / "audit.jsonl"])
    identities = agents_mod.build_agent_identities({}, policies, audit)
    assert {i["agent"] for i in identities} == {"support-bot",
                                                "analyst-bot"}
    assert all(i["key_provided"] is False for i in identities)
    assert all(i["key_redacted"] == "key not provided" for i in identities)


def test_render_json_is_the_identity_graph(tmp_path):
    identities, audit = _identities(tmp_path)
    out = agents_mod.render_agents(identities, audit, "json",
                                   gateway="/tmp/gateway")
    doc = json.loads(out)
    assert doc["gateway"] == "/tmp/gateway"
    assert doc["audit_log"]["events"] == 5
    assert doc["audit_log"]["chain_ok"] is True
    assert len(doc["agents"]) == 2
    assert SUPPORT_KEY not in out
    assert ANALYST_KEY not in out


def test_render_text_never_shows_a_key(tmp_path):
    identities, audit = _identities(tmp_path)
    out = agents_mod.render_agents(identities, audit, "text")
    assert "support-bot" in out and "analyst-bot" in out
    assert "chain intact" in out
    assert SUPPORT_KEY not in out
    assert ANALYST_KEY not in out


# ---------------------------------------------------------------- CLI
def test_cli_agents_on_a_gateway_fixture(tmp_path, capsys):
    root = _gateway(tmp_path)
    rc = cli(["agents", "--gateway", str(root),
              "--keys-file", str(root / "keys.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "support-bot" in out and "analyst-bot" in out
    assert "chain intact" in out
    assert SUPPORT_KEY not in out
    assert ANALYST_KEY not in out


def test_cli_agents_needs_a_gateway_or_policy_dir(capsys):
    rc = cli(["agents"])
    assert rc == 2
