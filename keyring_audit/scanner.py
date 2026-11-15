"""Repo scanning (Keyring Audit v0.5).

Four sources:
- the working tree (every file except .git/, including gitignored files
  like .env — that is where secrets live);
- the full git history (every commit's added lines, via `git log -p`);
- the staged diff (`git diff --cached` — what a commit would actually
  add, for the pre-commit hook);
- a remote repo (`git clone` into a temp dir, scanned, then deleted).

A finding records where the secret was seen (file, line, commit, author,
date) and the redacted value + salted fingerprint — never the secret
itself. AWS key IDs are paired with a nearby 40-char secret (same file,
within 10 lines) because an ID alone cannot be validated; a lone ID is
reported with validity "unknown (secret not found)".

Limits, stated plainly: the history scan reads added lines only (a
secret introduced in a commit is caught where it was introduced);
binary files and files over 10 MB are skipped with a warning; a shallow
clone only covers the fetched history and the report says so. The staged
scan reads added lines only — a secret already in history is not the
staged diff's business (clean it separately); it is caught by a full
scan instead.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .detectors import (
    AWS_SECRET_ASSIGNED_RE,
    AWS_SECRET_BARE_RE,
    fingerprint,
    redact,
    scan_line,
)
from .ownership import assign_owners

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
PAIR_WINDOW = 10  # lines around a key ID to look for its secret

# A GCP service-account key is a JSON object: "type": "service_account",
# "project_id", "client_email", and "private_key" (a PEM RSA key whose
# value is one long line, with \n escapes). An Azure service principal
# is a client_secret paired with a client_id and a tenant_id. Both are
# paired within PAIR_WINDOW lines, like an AWS key/secret pair.
_GCP_CLIENT_EMAIL_RE = re.compile(
    r'"client_email"\s*:\s*"([^"]+)"|client_email\s*[:=]\s*[\'"]([^\'"]+)[\'"]')
_GCP_PRIVATE_KEY_RE = re.compile(
    # A plain [^"]*? — NOT (?:\\n|[^"])*?. The alternation made the
    # two branches overlap (a backslash is both \\n's first char and
    # a [^"] char), so a lazy group over a long PEM backtracked
    # catastrophically: a 2048-bit key hung the scanner for minutes.
    # [^"] already matches the \n escapes in a JSON value, so the
    # \\n branch was redundant as well as ambiguous. The trailing
    # \n is (?:\\n)? — a bare \\n? would mean "a backslash, then an
    # optional n", which is not optional at all.
    r'"private_key"\s*:\s*"([^"]*?-----END PRIVATE KEY-----(?:\\n)?)"')
_GCP_PROJECT_ID_RE = re.compile(
    r'"project_id"\s*:\s*"([^"]+)"|project_id\s*[:=]\s*[\'"]([^\'"]+)[\'"]')
_AZURE_CLIENT_SECRET_RE = re.compile(
    r'client_secret\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]')
_AZURE_CLIENT_ID_RE = re.compile(
    r'client_id\s*[:=]\s*[\'"]([^\'"]+)[\'"]')
_AZURE_TENANT_ID_RE = re.compile(
    r'tenant_id\s*[:=]\s*[\'"]([^\'"]+)[\'"]')
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
             ".pytest_cache", ".mypy_cache", ".tox", "dist", "build"}


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def _finding(detector: str, provider: str, value: str, source: str,
             line_no: int | None, commit: str | None = None,
             author: str | None = None, date: int | None = None,
             paired_secret: str | None = None,
             fingerprint_value: str | None = None,
             extra: dict | None = None) -> dict:
    # _secret is the credential material the validity check needs, kept
    # only in memory and stripped before any report is written (report.py).
    # For an AWS key ID it is the paired secret (None when unpaired);
    # for a GCP service-account key it is the paired private key; for
    # every other detector it is the found value itself.
    # The AWS key ID and the GCP client_email are NOT secrets (they are
    # the public identifiers, like usernames) — they are stored in full
    # so the validity check can use them. A service account can hold
    # several keys under one client_email, so a GCP finding's fingerprint
    # is of the private key, not the email.
    if detector in ("aws-access-key-id", "gcp-service-account"):
        secret = paired_secret
    else:
        secret = value
    record = {"detector": detector, "provider": provider,
              # The private-key header is structure, not secret material —
              # showing it is safe and more useful than "----…----".
              "redacted": value if detector == "private-key" else redact(value),
              "fingerprint": fingerprint(fingerprint_value or value),
              "source": source, "line": line_no, "commit": commit,
              "author": author, "date": date, "_secret": secret}
    if detector == "aws-access-key-id":
        record["key_id"] = value
    if detector == "gcp-service-account":
        record["client_email"] = value
    if extra:
        record.update(extra)
    return record


def _scan_text_lines(lines: list[tuple[int, str]], source: str,
                     commit: str | None = None,
                     author: str | None = None,
                     date: int | None = None) -> list[dict]:
    """Scan numbered lines. Pairs AWS key IDs with nearby secrets,
    GCP service-account keys with their client_email, and Azure
    client secrets with their client_id and tenant_id."""
    findings: list[dict] = []
    aws_ids: list[tuple[int, str]] = []  # (line_no, key_id)
    aws_secrets: list[tuple[int, str]] = []  # (line_no, secret)
    gcp_emails: list[tuple[int, str]] = []  # (line_no, client_email)
    gcp_keys: list[tuple[int, str]] = []  # (line_no, private key PEM)
    gcp_projects: list[tuple[int, str]] = []  # (line_no, project_id)
    azure_secrets: list[tuple[int, str]] = []  # (line_no, client_secret)
    azure_clients: list[tuple[int, str]] = []  # (line_no, client_id)
    azure_tenants: list[tuple[int, str]] = []  # (line_no, tenant_id)
    for line_no, text in lines:
        for hit in scan_line(text):
            if hit["detector"] == "aws-access-key-id":
                aws_ids.append((line_no, hit["value"]))
                continue
            findings.append(_finding(hit["detector"], hit["provider"],
                                     hit["value"], source, line_no,
                                     commit, author, date))
        # AWS secret candidates, assigned form (secret = <40 chars).
        for m in AWS_SECRET_ASSIGNED_RE.finditer(text):
            aws_secrets.append((line_no, m.group(1)))
        # GCP service-account fields, and Azure service-principal fields.
        for m in _GCP_CLIENT_EMAIL_RE.finditer(text):
            gcp_emails.append((line_no, m.group(1) or m.group(2)))
        for m in _GCP_PRIVATE_KEY_RE.finditer(text):
            # The JSON value holds literal \n escapes; the PEM parser
            # needs real newlines.
            gcp_keys.append((line_no, m.group(1).replace("\\n", "\n")))
        for m in _GCP_PROJECT_ID_RE.finditer(text):
            gcp_projects.append((line_no, m.group(1) or m.group(2)))
        for m in _AZURE_CLIENT_SECRET_RE.finditer(text):
            azure_secrets.append((line_no, m.group(1)))
        for m in _AZURE_CLIENT_ID_RE.finditer(text):
            azure_clients.append((line_no, m.group(1)))
        for m in _AZURE_TENANT_ID_RE.finditer(text):
            azure_tenants.append((line_no, m.group(1)))
    # Bare form: a 40-char base64 run near an AWS key ID. Second pass,
    # so the order of ID and secret in the file does not matter.
    id_lines = {i for i, _ in aws_ids}
    for line_no, text in lines:
        if any(abs(line_no - i) <= PAIR_WINDOW for i in id_lines):
            for m in AWS_SECRET_BARE_RE.finditer(text):
                if (line_no, m.group(0)) not in aws_secrets:
                    aws_secrets.append((line_no, m.group(0)))
    # Pair each key ID with the nearest secret in the window.
    used_secrets: set[int] = set()
    paired_values: set[str] = set()
    for line_no, key_id in aws_ids:
        best: tuple[int, str] | None = None
        best_idx = -1
        for i, (s_line, secret) in enumerate(aws_secrets):
            if i in used_secrets:
                continue
            if abs(s_line - line_no) <= PAIR_WINDOW:
                if best is None or abs(s_line - line_no) < abs(best[0] - line_no):
                    best = (s_line, secret)
                    best_idx = i
        if best is not None:
            used_secrets.add(best_idx)
            paired_values.add(best[1])
            findings.append(_finding("aws-access-key-id", "aws", key_id,
                                     source, line_no, commit, author, date,
                                     paired_secret=best[1]))
        else:
            findings.append(_finding("aws-access-key-id", "aws", key_id,
                                     source, line_no, commit, author, date))
    # Pair each GCP client_email with the nearest private key in the
    # window. A service-account key without its private key nearby is
    # not a usable credential — it is not reported.
    paired_gcp_keys: list[str] = []
    paired_gcp_key_lines: set[int] = set()
    for line_no, email in gcp_emails:
        best: tuple[int, str] | None = None
        for k_line, key in gcp_keys:
            if abs(k_line - line_no) <= PAIR_WINDOW:
                if best is None or abs(k_line - line_no) < abs(best[0] - line_no):
                    best = (k_line, key)
        if best is None:
            continue
        paired_gcp_keys.append(best[1])
        paired_gcp_key_lines.add(best[0])
        best: tuple[int, str] | None = None
        for k_line, key in gcp_keys:
            if abs(k_line - line_no) <= PAIR_WINDOW:
                if best is None or abs(k_line - line_no) < abs(best[0] - line_no):
                    best = (k_line, key)
        if best is None:
            continue
        project = next((p for p_line, p in gcp_projects
                        if abs(p_line - line_no) <= PAIR_WINDOW), None)
        findings.append(_finding(
            "gcp-service-account", "gcp", email, source, line_no,
            commit, author, date, paired_secret=best[1],
            fingerprint_value=best[1],
            extra={"project_id": project} if project else None))
    # Pair each Azure client_secret with the nearest client_id and
    # tenant_id in the window. A secret without both is not a usable
    # service principal — it is not reported as Azure (the generic
    # high-entropy detector may still have flagged the value itself).
    used_azure: set[str] = set()
    for line_no, secret in azure_secrets:
        client = next((c for c_line, c in azure_clients
                       if abs(c_line - line_no) <= PAIR_WINDOW), None)
        tenant = next((t for t_line, t in azure_tenants
                       if abs(t_line - line_no) <= PAIR_WINDOW), None)
        if client is None or tenant is None:
            continue
        used_azure.add(secret)
        findings.append(_finding(
            "azure-client-secret", "azure", secret, source, line_no,
            commit, author, date,
            extra={"client_id": client, "tenant_id": tenant}))
    # A paired AWS secret is not a second finding: drop any generic hit
    # whose value is a secret already paired with a key ID. The same
    # for an Azure client secret already paired with its client id, and
    # for a GCP private-key body the generic detector caught inside the
    # JSON line (the body is a substring of the paired key). A private
    # key that is part of a paired service-account key is not a second
    # finding either — the GCP finding already covers it.
    return [f for f in findings
            if not (f["detector"] == "generic-high-entropy"
                    and f.get("_secret") in paired_values)
            and not (f["detector"] == "generic-high-entropy"
                     and f.get("_secret") in used_azure)
            and not (f["detector"] == "generic-high-entropy"
                     and any(f.get("_secret", "") in k
                             for k in paired_gcp_keys))
            and not (f["detector"] == "private-key"
                     and f.get("line") in paired_gcp_key_lines)]


def scan_working_tree(root: Path) -> tuple[list[dict], list[str]]:
    """Scan every file under root. Returns (findings, warnings)."""
    findings: list[dict] = []
    warnings: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    warnings.append(f"skipped {rel}: over 10 MB")
                    continue
                if _is_binary(path):
                    continue
                text = path.read_text(errors="replace")
            except OSError as e:
                warnings.append(f"skipped {rel}: {e}")
                continue
            lines = [(i + 1, line) for i, line in enumerate(text.splitlines())]
            findings.extend(_scan_text_lines(lines, rel))
    return findings, warnings


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True, timeout=300)


def scan_history(root: Path) -> tuple[list[dict], list[str]]:
    """Scan the full git history. Returns (findings, warnings)."""
    findings: list[dict] = []
    warnings: list[str] = []
    check = _git(["rev-parse", "--is-inside-work-tree"], root)
    if check.returncode != 0:
        return [], [f"{root} is not a git repository — history scan skipped"]
    shallow = _git(["rev-parse", "--is-shallow-repository"], root)
    if shallow.stdout.strip() == "true":
        warnings.append("shallow clone — history scan covers only the fetched commits")
    log = _git(["log", "--all", "--no-color", "--no-ext-diff",
                "--pretty=format:COMMIT %H %ct %an <%ae>", "-p"], root)
    if log.returncode != 0:
        return [], [f"git log failed: {log.stderr.strip()[:200]}"]
    commit = author = None
    date = None
    current_file: str | None = None
    lines: list[tuple[int, str]] = []

    def flush():
        nonlocal lines
        if current_file and lines:
            findings.extend(_scan_text_lines(lines, current_file,
                                             commit, author, date))
        lines = []

    for raw in log.stdout.splitlines():
        if raw.startswith("COMMIT "):
            flush()
            parts = raw.split(" ", 3)
            commit = parts[1] if len(parts) > 1 else None
            date = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
            author = parts[3] if len(parts) > 3 else None
            current_file = None
        elif raw.startswith("diff --git "):
            flush()
            m = re.search(r" b/(.+)$", raw)
            current_file = m.group(1) if m else None
        elif raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        elif raw.startswith("+") and current_file:
            lines.append((0, raw[1:]))  # line numbers in a diff are not stable; use 0
        elif raw.startswith("Binary files "):
            current_file = None
    flush()
    return findings, warnings


def scan(root: Path) -> dict:
    """Scan a path: working tree + git history. Returns the raw scan."""
    tree_findings, tree_warnings = scan_working_tree(root)
    hist_findings, hist_warnings = scan_history(root)
    # Dedup: the same secret in the same file at HEAD and in history is
    # one credential, first seen at its earliest commit.
    seen: dict[str, dict] = {}
    for f in hist_findings + tree_findings:
        key = f["fingerprint"]
        if key not in seen:
            seen[key] = f
        elif f["commit"] and (not seen[key]["commit"]
                              or (f["date"] or 0) < (seen[key]["date"] or 0)):
            seen[key] = f
    findings = assign_owners(list(seen.values()), root)
    return {"path": str(root), "findings": findings,
            "warnings": tree_warnings + hist_warnings}


def scan_staged(root: Path) -> dict:
    """Scan only what is staged (`git diff --cached`). Returns the raw
    scan. Added lines only, with real new-file line numbers from the
    hunk headers. Unstaged working-tree changes are not scanned — the
    hook cares about what the commit would actually add."""
    findings, warnings = _scan_diff_cached(root)
    findings = assign_owners(findings, root)
    return {"path": str(root), "findings": findings, "warnings": warnings}


def _scan_diff_cached(root: Path) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    warnings: list[str] = []
    check = _git(["rev-parse", "--is-inside-work-tree"], root)
    if check.returncode != 0:
        return [], [f"{root} is not a git repository — staged scan skipped"]
    diff = _git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff"],
                root)
    if diff.returncode != 0:
        return [], [f"git diff --cached failed: {diff.stderr.strip()[:200]}"]
    current_file: str | None = None
    new_line = 0
    lines: list[tuple[int, str]] = []

    def flush():
        nonlocal lines
        if current_file and lines:
            findings.extend(_scan_text_lines(lines, current_file))
        lines = []

    for raw in diff.stdout.splitlines():
        if raw.startswith("diff --git "):
            flush()
            m = re.search(r" b/(.+)$", raw)
            current_file = m.group(1) if m else None
        elif raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        elif raw.startswith("@@ "):
            # @@ -old,start +new,start @@ — track the new-file line number.
            m = re.search(r"\+(\d+)(?:,\d+)? @@", raw)
            new_line = int(m.group(1)) if m else 0
        elif raw.startswith("+") and current_file:
            lines.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("Binary files "):
            current_file = None
    flush()
    return findings, warnings


def _sanitize_url(url: str) -> str:
    """Strip credentials from a clone URL before it is stored or shown.
    Never print a URL a user pasted with a token in it."""
    return re.sub(r"://[^@/]*@", "://", url)


def scan_remote(url: str, branch: str | None = None) -> dict:
    """Clone a remote repo into a temp dir, scan it, delete the clone.
    The clone is read-only — nothing is ever pushed. A private repo
    works when git can clone it (SSH key / credential helper); the tool
    never handles credentials itself. The URL is stored sanitized, so a
    token pasted into it never reaches a report or a log."""
    tmp = Path(tempfile.mkdtemp(prefix="keyring-audit-"))
    try:
        cmd = ["git", "clone", "--quiet"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, str(tmp)]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=600)
        if proc.returncode != 0:
            raise ValueError(
                f"git clone failed: {proc.stderr.strip()[:300]}")
        result = scan(tmp)
        result["path"] = _sanitize_url(url)
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
