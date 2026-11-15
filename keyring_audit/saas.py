"""SaaS integrations (Keyring Audit v1.3, Phase 6 coverage).

The API keys for the SaaS services developers actually paste into
repos — the AI providers (OpenAI, Anthropic), Notion, and Hugging
Face. Each is validated with one safe, read-only call that returns
live or dead without a side effect:

- OpenAI: GET https://api.openai.com/v1/models, Bearer auth. 200
  means the key is live (it can list models); 401 means it is dead.
  The response lists the models the key can reach — a permission
  signal, though it does not say whether the key is project-scoped
  or organisation-wide.
- Anthropic: GET https://api.anthropic.com/v1/models, x-api-key auth
  plus the anthropic-version header. 200 live, 401 dead.
- Notion: GET https://api.notion.com/v1/users/me, Bearer auth plus
  the Notion-Version header. 200 live, 401 dead. The response names
  the bot (or user) and the workspace, and says whether the token is
  a bot (an internal connection, scoped to shared pages) or a user
  (a personal access token, acting as that user).
- Hugging Face: GET https://huggingface.co/api/whoami, Bearer auth.
  200 live, 401 dead. The response names the user and the role
  (read or write).

AI keys are uniquely costly to leak: a live key can run usage up into
thousands of dollars within hours, so a verified-live OpenAI or
Anthropic key scores high on privilege (35) and lands in the Critical
band with any other risk factor. The report says so.

The HTTP layer reuses cloud.py's opener (explicit ProxyHandler +
SSL context) — the sandbox proxy is not reliably honoured by the
default urlopen.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .cloud import _opener

NOTION_VERSION = "2022-06-28"
ANTHROPIC_VERSION = "2023-06-01"


def _get(url: str, headers: dict) -> dict:
    """GET a JSON endpoint. Returns the parsed body. Raises ValueError
    with the HTTP status on a non-2xx response."""
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with _opener().open(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise ValueError(f"network error: {e}") from e


def _check(name: str, url: str, headers: dict,
           permissions_from: object) -> dict:
    """The shared shape: a GET that is live on 200, dead on 401, and
    unknown on anything else (network failure, or a status that does
    not decide). `permissions_from` is a function taking the parsed
    body and returning the permission list."""
    try:
        body = _get(url, headers)
    except ValueError as e:
        msg = str(e)
        if msg == "HTTP 401":
            return {"live": "dead",
                    "reason": f"the {name} endpoint rejected the key — "
                              "it is revoked or expired",
                    "permissions": [], "method": f"{name}-api",
                    "last_used": None}
        if msg.startswith("network error"):
            return {"live": "unknown",
                    "reason": f"the {name} endpoint could not be reached "
                              f"({msg})",
                    "permissions": [], "method": f"{name}-api",
                    "last_used": None}
        return {"live": "unknown",
                "reason": f"the {name} endpoint answered {msg} — the key "
                          "could not be checked",
                "permissions": [], "method": f"{name}-api",
                "last_used": None}
    return {"live": "live",
            "reason": f"the {name} endpoint answered 200 for this key",
            "permissions": permissions_from(body),
            "method": f"{name}-api", "last_used": None}


def check_openai(key: str) -> dict:
    """Validate an OpenAI API key against GET /v1/models."""
    def perms(body: dict) -> list:
        models = body.get("data", []) or []
        return [f"can list models ({len(models)} visible)"] if models \
            else ["can list models"]
    return _check("OpenAI", "https://api.openai.com/v1/models",
                  {"Authorization": f"Bearer {key}"}, perms)


def check_anthropic(key: str) -> dict:
    """Validate an Anthropic API key against GET /v1/models."""
    def perms(body: dict) -> list:
        models = body.get("data", []) or []
        return [f"can list models ({len(models)} visible)"] if models \
            else ["can list models"]
    return _check("Anthropic", "https://api.anthropic.com/v1/models",
                  {"x-api-key": key,
                   "anthropic-version": ANTHROPIC_VERSION}, perms)


def check_notion(token: str) -> dict:
    """Validate a Notion integration token against GET /v1/users/me."""
    def perms(body: dict) -> list:
        out = [f"type: {body.get('type', 'unknown')}"]
        if body.get("name"):
            out.append(f"name: {body['name']}")
        if body.get("bot", {}).get("workspace_name"):
            out.append(f"workspace: {body['bot']['workspace_name']}")
        return out
    return _check("Notion", "https://api.notion.com/v1/users/me",
                  {"Authorization": f"Bearer {token}",
                   "Notion-Version": NOTION_VERSION}, perms)


def check_huggingface(token: str) -> dict:
    """Validate a Hugging Face token against GET /api/whoami."""
    def perms(body: dict) -> list:
        out = []
        if body.get("name"):
            out.append(f"user: {body['name']}")
        if body.get("role"):
            out.append(f"role: {body['role']}")
        return out
    return _check("Hugging Face", "https://huggingface.co/api/whoami",
                  {"Authorization": f"Bearer {token}"}, perms)
