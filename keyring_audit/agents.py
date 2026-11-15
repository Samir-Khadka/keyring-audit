"""Agent identities (Keyring Audit v0.8, Phase 5).

The Agent Gateway tie-in — the strongest differentiator in the plan:
no other open-source scanner has a policy-enforcement sibling. Every
agent key the gateway governs is a Keyring Audit credential, and every
Gateway policy decision is logged against it. The two products share
the identity graph (the `--format json` output of `agents`).

Sources, all read-only:
- Agent keys: the gateway's `--keys-file` (JSON: key -> agent id) or
  the `AGENT_KEYS` env var. The key values are used only in memory to
  fingerprint them (salted hash + first/last 4), then discarded — the
  same safety contract as the scanner. When no keys are provided, the
  agents are still reported from their policies and audit trail, with
  the key marked "not provided".
- Policies: `<gateway>/policies/*.yaml` — agent name, risk_tier, the
  allowed tools, budgets. Keyring Audit is stdlib-only, so there is no
  YAML parser: the policy files are read with a focused extractor for
  the fields this command needs (agent, risk_tier, the `tool:` lines
  under `allow:`). The gateway's policy files are machine-generated in
  a stable shape; if the format grows, this is the place to add a real
  parser.
- Audit log: `<gateway>/data/*.jsonl` — one event per tool call, with
  agent, tool, decision and timestamp, hash-chained. The chain is
  verified (the gateway's own algorithm: SHA-256 of the entry dict
  minus `hash`, sorted keys, compact separators; each entry's
  prev_hash must equal the previous entry's hash) and the result is
  reported — a broken chain is itself a finding.

Scoring reuses the same 0–100 components: privilege from the policy's
allowed tools (a tool that can send, refund or delete scores highest)
and the risk_tier; usage from the audit log's last-used time; exposure
is the gateway key config (server-side, not committed); ownership is
the agent itself. An agent key with no audit entries at all is a
"safe to kill" candidate — dead weight, not a mystery.

With `--live-check <url>` (v0.9) the key is also checked against a
running gateway: a POST to `<url>/mcp` with the key in `x-agent-key`
and a method the gateway does not support. The gateway checks the key
before dispatching, so a 401 means the key is unknown (dead) and any
other answer means the key was accepted (live) — without calling any
tool, touching the upstream, or writing an audit entry. A gateway
that cannot be reached leaves the validity "unknown", never "dead".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .detectors import fingerprint, redact
from .ranking import rank

DANGEROUS_TOOLS = ("refund", "delete", "send", "execute", "transfer",
                   "revoke", "disable")
WRITE_TOOLS = ("write", "update", "create", "set", "put", "post")
TIER_SCORE = {"high": 35, "medium": 25, "low": 15}


def load_keys(keys_file: Path | None = None) -> dict[str, str]:
    """key -> agent id, from --keys-file or the AGENT_KEYS env var.
    Returns {} when neither is provided."""
    if keys_file is not None:
        return json.loads(keys_file.read_text())
    raw = os.environ.get("AGENT_KEYS")
    if raw:
        return json.loads(raw)
    return {}


def extract_policy(text: str) -> dict:
    """The fields `agents` needs from one gateway policy file."""
    agent = None
    tier = None
    tools: list[str] = []
    in_allow = False
    for line in text.splitlines():
        m = re.match(r"^agent:\s*(\S+)", line)
        if m:
            agent = m.group(1)
            continue
        m = re.match(r"^risk_tier:\s*(\S+)", line)
        if m:
            tier = m.group(1)
            continue
        if re.match(r"^allow:\s*$", line):
            in_allow = True
            continue
        if in_allow:
            if re.match(r"^[a-z_]+:\s*", line) and not line.startswith(" "):
                in_allow = False
            else:
                m = re.match(r"^\s*-\s*tool:\s*(\S+)", line)
                if m:
                    tools.append(m.group(1))
    return {"agent": agent, "risk_tier": tier, "allowed_tools": tools}


def load_policies(policy_dir: Path) -> dict[str, dict]:
    """agent -> policy, from every .yaml file in the directory."""
    out: dict[str, dict] = {}
    if not policy_dir.is_dir():
        return out
    for path in sorted(policy_dir.glob("*.yaml")) + sorted(
            policy_dir.glob("*.yml")):
        try:
            policy = extract_policy(path.read_text())
        except OSError:
            continue
        if policy["agent"]:
            out[policy["agent"]] = policy
    return out


def _hash_entry(entry: dict) -> str:
    """The gateway's audit-log hash: SHA-256 of the entry dict minus
    `hash`, sorted keys, compact separators."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()


def load_audit_log(paths: list[Path]) -> dict:
    """Parse audit-log JSONL files, verify the hash chain, and
    aggregate per agent. Returns events + chain status + per-agent
    usage."""
    events: list[dict] = []
    for path in paths:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    chain_ok = True
    chain_error = ""
    prev = "0" * 64
    for i, entry in enumerate(events):
        if entry.get("prev_hash") != prev:
            chain_ok = False
            chain_error = (f"entry {i}: prev_hash does not match the "
                           "previous entry's hash")
            break
        if entry.get("hash") and _hash_entry(entry) != entry.get("hash"):
            chain_ok = False
            chain_error = f"entry {i}: hash does not match its content"
            break
        prev = entry.get("hash", prev)
    usage: dict[str, dict] = {}
    for entry in events:
        agent = entry.get("agent")
        if not agent:
            continue
        u = usage.setdefault(agent, {"calls": 0, "allowed": 0, "denied": 0,
                                     "last_used": None, "denied_tools": set(),
                                     "tools": set()})
        u["calls"] += 1
        if entry.get("decision") == "allow":
            u["allowed"] += 1
        elif entry.get("decision") == "deny":
            u["denied"] += 1
            if entry.get("tool"):
                u["denied_tools"].add(entry["tool"])
        if entry.get("tool"):
            u["tools"].add(entry["tool"])
        ts = entry.get("ts")
        if ts and (u["last_used"] is None or ts > u["last_used"]):
            u["last_used"] = ts
    for u in usage.values():
        u["denied_tools"] = sorted(u["denied_tools"])
        u["tools"] = sorted(u["tools"])
    return {"events": len(events), "chain_ok": chain_ok,
            "chain_error": chain_error, "usage": usage}


def agent_privilege(policy: dict | None) -> tuple[int, str]:
    """0–40. What the agent's policy lets it do. A tool that can send,
    refund or delete scores highest; the risk_tier is a floor."""
    if not policy:
        return 20, "no policy found — privilege unknown, scored in the middle"
    tools = policy.get("allowed_tools") or []
    if any(any(d in t for d in DANGEROUS_TOOLS) for t in tools):
        tool_score, tool_why = 40, "policy allows a dangerous tool"
    elif any(any(w in t for w in WRITE_TOOLS) for t in tools):
        tool_score, tool_why = 30, "policy allows a write tool"
    elif tools:
        tool_score, tool_why = 15, "policy allows read-only tools"
    else:
        tool_score, tool_why = 20, "policy allows no tools"
    tier = (policy.get("risk_tier") or "").lower()
    tier_score = TIER_SCORE.get(tier, 20)
    if tier_score > tool_score:
        return tier_score, f"risk_tier {tier} (policy: {tool_why})"
    return tool_score, tool_why


def check_key_live(url: str, key: str, timeout: float = 10) -> dict:
    """Is this agent key live on a running gateway? POST <url>/mcp
    with the key in `x-agent-key` and a method the gateway does not
    support. The gateway checks the key before dispatching, so a 401
    means the key is unknown (dead) and any other answer means the
    key was accepted (live) — without calling any tool, touching the
    upstream, or writing an audit entry. A gateway that cannot be
    reached leaves the validity "unknown", never "dead"."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping",
                       "params": {}}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/mcp", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "x-agent-key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"live": "unknown",
                "reason": f"gateway unreachable: {e}",
                "method": "gateway-live-check"}
    if status == 401:
        return {"live": "dead",
                "reason": "the gateway does not know this key (401)",
                "method": "gateway-live-check"}
    if status == 403:
        return {"live": "live",
                "reason": "key accepted, but no policy for this agent (403)",
                "method": "gateway-live-check"}
    return {"live": "live",
            "reason": f"key accepted by the gateway (HTTP {status})",
            "method": "gateway-live-check"}


def build_agent_identities(keys: dict[str, str],
                           policies: dict[str, dict],
                           audit: dict,
                           live_check_url: str | None = None) -> list[dict]:
    """The identity graph: one record per agent key, plus one per agent
    that has a policy or audit trail but no key on file. Ranked with
    the same 0–100 score as any other credential. With a live-check
    URL, each key is also checked against the running gateway."""
    usage = audit.get("usage", {})
    identities: list[dict] = []
    seen_agents: set[str] = set()
    for key, agent in sorted(keys.items(), key=lambda kv: kv[1]):
        seen_agents.add(agent)
        live = check_key_live(live_check_url, key) if live_check_url else None
        identities.append(_identity(agent, key, policies.get(agent),
                                    usage.get(agent), live))
    # Agents with a policy or an audit trail but no key on file: the
    # key is held by the gateway and was not provided.
    for agent in sorted(set(policies) | set(usage)):
        if agent in seen_agents:
            continue
        identities.append(_identity(agent, None, policies.get(agent),
                                    usage.get(agent)))
    identities.sort(key=lambda i: i["risk"]["score"], reverse=True)
    return identities


def _identity(agent: str, key: str | None, policy: dict | None,
              use: dict | None, live: dict | None = None) -> dict:
    last_used = (use or {}).get("last_used")
    validity = {"live": "unknown",
                "reason": "no provider endpoint checks a gateway "
                          "key — liveness comes from the audit log",
                "permissions": (policy or {}).get("allowed_tools", []),
                "method": "audit-log",
                "last_used": last_used}
    if live is not None:
        validity = dict(live)
        validity["permissions"] = (policy or {}).get("allowed_tools", [])
        validity["last_used"] = last_used
    # A finding-shaped dict, so the shared ranking scores it. The
    # privilege is precomputed from the gateway policy and passed in —
    # the ranking reads it, it does not import this module.
    finding = {
        "detector": "agent-api-key", "provider": "agent-gateway",
        "redacted": redact(key) if key else "key not provided",
        "fingerprint": fingerprint(key) if key else None,
        "source": "agent-gateway", "line": None, "commit": None,
        "author": None, "date": None,
        "owner": {"name": agent, "source": "agent-gateway"},
        "exposure_source": "gateway",
        "agent_privilege": agent_privilege(policy),
        "validity": validity,
    }
    ranked = rank(finding)
    calls = (use or {}).get("calls", 0)
    denied = (use or {}).get("denied", 0)
    notes: list[str] = []
    if validity.get("live") == "dead":
        notes.append("dead — the gateway does not know this key")
    if not use:
        notes.append("never used — no audit entries at all")
    elif denied:
        notes.append(f"{denied} denied attempt(s) in the audit log — "
                     "the agent keeps trying tools its policy denies")
    if not policy:
        notes.append("no policy file — the agent runs without a policy")
    # Safe to kill: a dead key (the live check proved it), or an agent
    # key with no audit entries, or none in 90+ days — dead weight.
    # (The ranking's safe_to_kill needs a live verdict, which a
    # gateway key cannot give without the live check, so this is
    # computed here.)
    safe_to_kill = validity.get("live") == "dead"
    if not use:
        safe_to_kill = True
    elif last_used:
        try:
            last = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
            safe_to_kill = safe_to_kill or \
                ((datetime.now(timezone.utc) - last).days >= 90)
        except ValueError:
            pass
    ranked["risk"]["safe_to_kill"] = safe_to_kill
    return {"agent": agent, "key_provided": key is not None,
            "key_fingerprint": finding["fingerprint"],
            "key_redacted": finding["redacted"],
            "policy": policy,
            "usage": {"calls": calls,
                      "allowed": (use or {}).get("allowed", 0),
                      "denied": denied,
                      "last_used": last_used,
                      "denied_tools": (use or {}).get("denied_tools", []),
                      "tools_used": (use or {}).get("tools", [])},
            "risk": ranked["risk"], "notes": notes,
            "validity": {"live": validity.get("live"),
                         "reason": validity.get("reason"),
                         "method": validity.get("method")}}


def render_agents(identities: list[dict], audit: dict, fmt: str = "text",
                  gateway: str = "") -> str:
    """Text for the terminal, md for a report, json for the shared
    identity graph both products can read."""
    if fmt == "json":
        return json.dumps({"gateway": gateway,
                           "audit_log": {"events": audit.get("events", 0),
                                         "chain_ok": audit.get("chain_ok"),
                                         "chain_error": audit.get("chain_error", "")},
                           "agents": identities}, indent=2)
    if fmt == "md":
        lines = ["# Agent identities",
                 "",
                 f"- Audit log: {audit.get('events', 0)} events, chain "
                 + ("intact" if audit.get("chain_ok") else
                    f"BROKEN — {audit.get('chain_error', '')}"),
                 ""]
        for ident in identities:
            lines.append(f"## {ident['agent']} "
                         f"[{ident['risk']['band']} "
                         f"{ident['risk']['score']}]")
            lines.append(f"- Key: {ident['key_redacted']}")
            policy = ident["policy"]
            lines.append("- Policy: "
                         + (", ".join(policy.get("allowed_tools", []))
                            if policy else "none found")
                         + (f" (risk_tier {policy.get('risk_tier')})"
                            if policy and policy.get("risk_tier") else ""))
            u = ident["usage"]
            lines.append(f"- Usage: {u['calls']} calls "
                         f"({u['allowed']} allowed, {u['denied']} denied)"
                         + (f", last used {u['last_used']}"
                            if u["last_used"] else ", never used"))
            for note in ident["notes"]:
                lines.append(f"- ⚠️ {note}")
            lines.append(f"- Safe to kill: "
                         f"{'yes' if ident['risk']['safe_to_kill'] else 'no'}")
            lines.append("")
        return "\n".join(lines)
    lines = [f"Agent identities — {len(identities)} agent(s)",
             f"Audit log: {audit.get('events', 0)} events, chain "
             + ("intact" if audit.get("chain_ok") else
                f"BROKEN — {audit.get('chain_error', '')}"),
             ""]
    for ident in identities:
        lines.append(f"{ident['agent']} [{ident['risk']['band']} "
                     f"{ident['risk']['score']}] — key "
                     f"{ident['key_redacted']} "
                     f"({ident['validity']['live']})")
        policy = ident["policy"]
        lines.append("  policy: "
                     + (", ".join(policy.get("allowed_tools", []))
                        if policy else "none found")
                     + (f" (risk_tier {policy.get('risk_tier')})"
                        if policy and policy.get("risk_tier") else ""))
        u = ident["usage"]
        lines.append(f"  usage: {u['calls']} calls ({u['allowed']} allowed, "
                     f"{u['denied']} denied)"
                     + (f", last used {u['last_used']}"
                        if u["last_used"] else ", never used"))
        for note in ident["notes"]:
            lines.append(f"  ⚠️ {note}")
        lines.append("  safe to kill: "
                     f"{'yes' if ident['risk']['safe_to_kill'] else 'no'}")
        lines.append("")
    return "\n".join(lines)
