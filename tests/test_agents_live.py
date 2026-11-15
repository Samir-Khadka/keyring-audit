"""Tests for v0.9: the live key check against a running gateway.
A mock gateway (a real HTTP server on 127.0.0.1, ephemeral port)
implements the gateway's auth: `x-agent-key` is checked before
dispatch, a method the gateway does not support is rejected without
calling any tool, and an unknown key gets 401."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from keyring_audit import agents as agents_mod
from keyring_audit.__main__ import cli
from test_agents import _gateway

LIVE_KEY = "live-key-support-bot"
DEAD_KEY = "dead-key-ghost-bot"
NO_POLICY_KEY = "no-policy-key-bot"

SEEN: list[dict] = []


class MockGateway(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            doc = json.loads(body) if body else {}
        except json.JSONDecodeError:
            doc = {}
        SEEN.append({"path": self.path,
                     "key": self.headers.get("x-agent-key"),
                     "method": doc.get("method")})
        key = self.headers.get("x-agent-key")
        if self.path != "/mcp":
            self._send(404, {})
            return
        if key == LIVE_KEY:
            # The key is accepted, then the method is rejected — no
            # tool is called, no upstream is touched, no audit entry.
            self._send(200, {"jsonrpc": "2.0", "id": 1,
                             "error": {"code": -32601,
                                       "message": "method not supported: ping"}})
        elif key == NO_POLICY_KEY:
            self._send(403, {"detail": "no policy for agent ghost-bot"})
        else:
            self._send(401, {"detail": "missing or unknown agent key"})

    def _send(self, status, doc):
        payload = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def gateway_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockGateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    SEEN.clear()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_check_key_live_accepted_key(gateway_url):
    result = agents_mod.check_key_live(gateway_url, LIVE_KEY)
    assert result["live"] == "live"
    assert result["method"] == "gateway-live-check"


def test_check_key_live_unknown_key_is_dead(gateway_url):
    result = agents_mod.check_key_live(gateway_url, DEAD_KEY)
    assert result["live"] == "dead"
    assert "401" in result["reason"]


def test_check_key_live_no_policy_is_still_live(gateway_url):
    result = agents_mod.check_key_live(gateway_url, NO_POLICY_KEY)
    assert result["live"] == "live"
    assert "no policy" in result["reason"]


def test_check_key_live_unreachable_is_unknown_not_dead():
    result = agents_mod.check_key_live("http://127.0.0.1:1", LIVE_KEY,
                                       timeout=2)
    assert result["live"] == "unknown"
    assert "unreachable" in result["reason"]


def test_live_check_never_calls_a_tool(gateway_url):
    agents_mod.check_key_live(gateway_url, LIVE_KEY)
    assert len(SEEN) == 1
    assert SEEN[0]["method"] == "ping"  # not a tool call
    assert SEEN[0]["path"] == "/mcp"


def test_identities_with_live_check(tmp_path, gateway_url):
    root = _gateway(tmp_path)
    keys = {LIVE_KEY: "support-bot", DEAD_KEY: "ghost-bot"}
    policies = agents_mod.load_policies(root / "policies")
    audit = agents_mod.load_audit_log([root / "data" / "audit.jsonl"])
    identities = agents_mod.build_agent_identities(
        keys, policies, audit, live_check_url=gateway_url)
    by_agent = {i["agent"]: i for i in identities}
    live = by_agent["support-bot"]
    assert live["validity"]["live"] == "live"
    assert live["risk"]["score"] >= 60  # dangerous tools, live key
    dead = by_agent["ghost-bot"]
    assert dead["validity"]["live"] == "dead"
    assert dead["risk"]["score"] < 30  # a dead key scores low
    assert dead["risk"]["safe_to_kill"] is True
    assert any("dead" in n for n in dead["notes"])
    assert any("no policy file" in n for n in dead["notes"])


def test_cli_agents_live_check(tmp_path, gateway_url, capsys):
    root = _gateway(tmp_path)
    (root / "keys.json").write_text(json.dumps(
        {LIVE_KEY: "support-bot", DEAD_KEY: "ghost-bot"}))
    rc = cli(["agents", "--gateway", str(root),
              "--keys-file", str(root / "keys.json"),
              "--live-check", gateway_url])
    assert rc == 0
    out = capsys.readouterr().out
    assert "support-bot" in out and "(live)" in out
    assert "ghost-bot" in out and "(dead)" in out
    assert LIVE_KEY not in out
    assert DEAD_KEY not in out
