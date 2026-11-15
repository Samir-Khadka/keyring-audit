"""Minimal GitHub API client (Keyring Audit v0.7, Phase 4).

Stdlib only (urllib), with the same proxy/CA handling as gh_push.py:
the sandbox egress proxy is honoured from the HTTPS_PROXY env var, and
SSL_CERT_FILE is used for TLS verification when set. Deliberately
small — only the calls the `fix` command needs: repo info, branch
creation, a blob/tree/commit push, and PR creation.

`request` is the single choke point, so tests can monkeypatch it and
the whole PR flow runs without touching the network.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

API = "https://api.github.com"


def _opener() -> urllib.request.OpenerDirector:
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
             or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    handlers: list = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    ca = os.environ.get("SSL_CERT_FILE")
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def request(token: str, method: str, path: str,
            payload: dict | None = None) -> dict:
    """One GitHub API call. Returns the parsed JSON. Raises ValueError
    with GitHub's message on any non-2xx response."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    try:
        with _opener().open(req, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}").get("message", "")
        except Exception:  # noqa: BLE001 - fall back to the status
            detail = ""
        raise ValueError(f"GitHub {method} {path} failed "
                         f"({e.code}): {detail or e.reason}") from None


def get_default_branch(token: str, owner: str, repo: str) -> str:
    return request(token, "GET", f"/repos/{owner}/{repo}")["default_branch"]


def get_ref_sha(token: str, owner: str, repo: str, branch: str) -> str:
    return request(token, "GET",
                   f"/repos/{owner}/{repo}/git/ref/heads/{branch}")["object"]["sha"]


def create_branch(token: str, owner: str, repo: str, branch: str,
                  sha: str) -> None:
    request(token, "POST", f"/repos/{owner}/{repo}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": sha})


def push_commit(token: str, owner: str, repo: str, branch: str,
                base_sha: str, files: dict[str, str],
                message: str) -> str:
    """Push one commit to `branch`: blobs, a tree on base_sha, a commit,
    then move the branch ref. Returns the commit SHA."""
    tree_items = []
    for path, content in files.items():
        blob = request(token, "POST", f"/repos/{owner}/{repo}/git/blobs",
                       {"content": content, "encoding": "utf-8"})
        tree_items.append({"path": path, "mode": "100644",
                           "type": "blob", "sha": blob["sha"]})
    tree = request(token, "POST", f"/repos/{owner}/{repo}/git/trees",
                   {"base_tree": base_sha, "tree": tree_items})
    commit = request(token, "POST", f"/repos/{owner}/{repo}/git/commits",
                     {"message": message, "tree": tree["sha"],
                      "parents": [base_sha]})
    request(token, "PATCH", f"/repos/{owner}/{repo}/git/refs/heads/{branch}",
            {"sha": commit["sha"]})
    return commit["sha"]


def create_pr(token: str, owner: str, repo: str, title: str, head: str,
              base: str, body: str) -> dict:
    return request(token, "POST", f"/repos/{owner}/{repo}/pulls",
                   {"title": title, "head": head, "base": base,
                    "body": body})
