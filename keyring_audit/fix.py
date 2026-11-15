"""PR automation (Keyring Audit v0.7, Phase 4).

`fix` opens a pull request that replaces a hardcoded credential with
an environment-variable reference — the vault reference: the value
lives in the deployment environment (GitHub Secrets, Render env vars)
and the code reads it by name. A dry run first, always: without
`--approve` it prints the diff (secret redacted) and the PR title and
body, and changes nothing.

What it can fix, and how (the value is replaced, never copied):
- `.env` — the line becomes a comment naming where the value lives.
  A committed .env must not hold a secret at all.
- `.py` — `NAME = "secret"` becomes `NAME = os.environ["NAME"]`
  (adding `import os` when the file lacks it).
- `.js` / `.ts` — `const NAME = "secret"` becomes
  `const NAME = process.env.NAME`.
- `.sh` — `NAME="secret"` becomes `NAME="${NAME}"` (export kept).
- `.yml` / `.yaml` — `key: "secret"` becomes `key: ${KEY}`; inside
  `.github/workflows/` it becomes `key: ${{ secrets.KEY }}`.

Anything else — a value embedded in a longer string, a dict value, a
JSON file, an unknown extension — is refused with a manual step, not
guessed at. After transforming, the tool verifies the fixed file
contains no occurrence of the old value before it commits anything.

The PR itself is opened with the GitHub API (see github.py). The PR
body uses the redacted form of the credential only — the PR's file
diff will show the removed line, but that line is already in the repo,
so the PR exposes it to no one new.
"""
from __future__ import annotations

import difflib
import re
import subprocess
from pathlib import Path

from . import github

PROVIDER_ENV_DEFAULTS = {
    "github": "GITHUB_TOKEN",
    "aws": "AWS_SECRET_ACCESS_KEY",
    "slack": "SLACK_TOKEN",
    "gitlab": "GITLAB_TOKEN",
    "stripe": "STRIPE_SECRET_KEY",
}

SUPPORTED_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh",
                      ".yml", ".yaml", ".env"}

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules",
             ".pytest_cache", ".tox", ".mypy_cache"}


def is_env_file(path: Path) -> bool:
    name = path.name
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def env_var_name(finding: dict, line_text: str) -> str:
    """The environment variable the fixed code will read. From the
    assignment's variable name where there is one, else the provider's
    conventional name."""
    if is_env_file(Path(finding["source"])):
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=",
                     line_text)
        if m:
            return m.group(1)
    m = re.match(r"^\s*(?:const|let|var|export\s+)?"
                 r"([A-Za-z_][A-Za-z0-9_]*)\s*=", line_text)
    if m:
        return m.group(1).upper()
    m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:", line_text)
    if m:
        return m.group(1).upper().replace("-", "_")
    m = re.match(r"^\s*[\"']([A-Za-z_][A-Za-z0-9_-]*)[\"']\s*:", line_text)
    if m:
        return m.group(1).upper().replace("-", "_")
    return PROVIDER_ENV_DEFAULTS.get(finding.get("provider"), "SECRET")


def _replace_quoted(line: str, value: str, replacement: str) -> str | None:
    """Replace a quoted occurrence of `value` in `line` with
    `replacement`. Returns None when the line does not hold the value
    as a standalone quoted string."""
    pattern = re.compile(r"([\"'])" + re.escape(value) + r"\1")
    if not pattern.search(line):
        return None
    return pattern.sub(replacement, line, count=1)


def _ensure_import_os(lines: list[str]) -> list[str]:
    """Add `import os` to a Python file that lacks it, after a shebang
    and module docstring when there is one."""
    if any(re.match(r"^\s*(import os|from os import)\b", ln) for ln in lines):
        return lines
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    if insert_at < len(lines):
        m = re.match(r'^(\s*)([\"\'])', lines[insert_at])
        if m:
            quote = m.group(2)
            for i in range(insert_at, len(lines)):
                if lines[i].rstrip().endswith(quote * 3):
                    insert_at = i + 1
                    break
    return lines[:insert_at] + ["import os"] + lines[insert_at:]


def transform_file(path: Path, content: str, value: str,
                   finding: dict) -> tuple[str, int, list[str]]:
    """Replace `value` in `content` with an env-var reference.
    Returns (new content, lines changed, manual notes). Raises
    ValueError for an unsupported file type."""
    suffix = path.suffix.lower()
    if is_env_file(path):
        kind = "env"
    elif suffix in SUPPORTED_SUFFIXES:
        kind = suffix
    else:
        raise ValueError(f"{path}: unsupported file type for an automatic "
                         "fix — edit it by hand and replace the value "
                         "with an environment-variable reference")
    lines = content.splitlines()
    changed = 0
    manual: list[str] = []
    for i, line in enumerate(lines):
        if value not in line:
            continue
        env_name = env_var_name(finding, line)
        if kind == "env":
            if re.match(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=",
                        line):
                lines[i] = (f"# {env_name} is set in the deployment "
                            "environment — value removed by keyring-audit")
                changed += 1
            else:
                manual.append(f"{path}:{i + 1}: the value is not a plain "
                              "KEY=value line — remove it by hand")
            continue
        if kind == ".py":
            m = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
                         r"[\"']" + re.escape(value) + r"[\"']\s*$", line)
            if m:
                lines[i] = (f'{m.group(1)}{m.group(2)} = '
                            f'os.environ["{m.group(2).upper()}"]')
                changed += 1
            else:
                manual.append(f"{path}:{i + 1}: not a simple assignment — "
                              "replace the value with "
                              f'os.environ["{env_name}"] by hand')
            continue
        if kind in (".js", ".ts", ".jsx", ".tsx"):
            m = re.match(r"^(\s*)(const|let|var)\s+"
                         r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[\"']"
                         + re.escape(value) + r"[\"'](\s*;?)\s*$", line)
            if m:
                semi = ";" if ";" in m.group(4) else ""
                lines[i] = (f"{m.group(1)}{m.group(2)} {m.group(3)} = "
                            f"process.env.{m.group(3).upper()}{semi}")
                changed += 1
            else:
                manual.append(f"{path}:{i + 1}: not a simple declaration — "
                              "replace the value with "
                              f"process.env.{env_name} by hand")
            continue
        if kind == ".sh":
            m = re.match(r"^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
                         r"[\"']?" + re.escape(value) + r"[\"']?\s*$", line)
            if m:
                lines[i] = (f"{m.group(1)}{m.group(2) or ''}{m.group(3)}="
                            f'"${{{m.group(3)}}}"')
                changed += 1
            else:
                manual.append(f"{path}:{i + 1}: not a simple assignment — "
                              "replace the value with "
                              f'"${{{env_name}}}" by hand')
            continue
        if kind in (".yml", ".yaml"):
            m = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*[\"']?"
                         + re.escape(value) + r"[\"']?\s*$", line)
            if m:
                if ".github/workflows/" in str(path):
                    ref = "${{ secrets." + m.group(2).upper().replace("-", "_") + " }}"
                else:
                    ref = "${" + m.group(2).upper().replace("-", "_") + "}"
                lines[i] = f"{m.group(1)}{m.group(2)}: {ref}"
                changed += 1
            else:
                manual.append(f"{path}:{i + 1}: not a simple key: value "
                              "line — replace the value with an "
                              "environment-variable reference by hand")
            continue
    new_lines = _ensure_import_os(lines) if kind == ".py" and changed else lines
    new_content = "\n".join(new_lines)
    if content.endswith("\n"):
        new_content += "\n"
    return new_content, changed, manual


def find_occurrences(root: Path, value: str) -> list[tuple[Path, int]]:
    """Every (file, line) in the working tree that holds `value`.
    Skips .git, virtualenvs, node_modules and binary files."""
    hits: list[tuple[Path, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if value in line:
                hits.append((path, i))
    return hits


def fix_credential(root: Path, finding: dict,
                   values: list[str]) -> dict:
    """Compute the fix for one credential. `values` is every value to
    replace — for AWS, the key id AND the secret; for other providers,
    the single token. Returns the fixed files, the manual notes, and
    the env vars the owner must set. Changes nothing on disk — the
    caller writes the files and opens the PR."""
    all_files: dict[str, str] = {}
    manual: list[str] = []
    env_vars: list[str] = []
    occurrences = 0
    for value in values:
        if not value:
            continue
        occ = find_occurrences(root, value)
        occurrences += len(occ)
        by_file: dict[Path, list[int]] = {}
        for path, line in occ:
            by_file.setdefault(path, []).append(line)
        for path in by_file:
            rel = str(path.relative_to(root))
            content = all_files.get(rel, path.read_text())
            try:
                new_content, changed, notes = transform_file(
                    path, content, value, finding)
            except ValueError as e:
                manual.append(str(e))
                continue
            manual.extend(notes)
            if changed:
                if value in new_content:
                    raise ValueError(f"{rel}: the fix left the value in "
                                     "the file — refusing to commit it")
                all_files[rel] = new_content
                for line in content.splitlines():
                    if value in line:
                        env_vars.append(env_var_name(finding, line))
    if not occurrences:
        raise ValueError("the value is no longer in the working tree — "
                         "it lives only in history, and a PR cannot fix "
                         "history (rewrite it with git filter-repo or BFG)")
    return {"files": all_files, "manual": manual,
            "env_vars": sorted(set(env_vars)),
            "occurrences": occurrences,
            "changed_files": len(all_files)}


def redacted_diff(path: str, old: str, new: str,
                  replacements: list[tuple[str, str]]) -> str:
    """A unified diff with each secret replaced by its redacted form,
    for the dry run and the PR body. The new content never holds the
    values, so only the removed lines need redacting."""
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(old_lines, new_lines,
                                        fromfile=f"a/{path}",
                                        tofile=f"b/{path}"))
    for value, redacted in replacements:
        diff = diff.replace(value, redacted)
    return diff


def build_pr_title(finding: dict) -> str:
    return (f"Replace hardcoded {finding.get('provider')} credential with "
            f"an env-var reference ({finding.get('redacted')})")


def build_pr_body(finding: dict, fix: dict) -> str:
    redacted = finding.get("redacted", "")
    owner = (finding.get("owner") or {}).get("name")
    lines = [
        "## Keyring Audit fix",
        "",
        f"This PR replaces a hardcoded {finding.get('provider')} "
        f"credential ({redacted}) with an environment-variable reference. "
        f"It was found in `{finding.get('source')}` "
        f"(line {finding.get('line')}) by `keyring-audit scan`.",
        "",
        "### What changed",
    ]
    for path in fix["files"]:
        lines.append(f"- `{path}`: the hardcoded value is now an "
                     "environment-variable reference.")
    lines.append("")
    lines.append("### What you need to do")
    if fix["env_vars"]:
        lines.append("1. Set these environment variables to the "
                     "credential's replacement value (GitHub Secrets, "
                     "Render env vars, or your deployment environment):")
        for var in fix["env_vars"]:
            lines.append(f"   - `{var}`")
    lines.append("2. Rotate the old credential — it is still live until "
                 "you do. `keyring-audit rotate --fingerprint "
                 f"{finding.get('fingerprint')}` gives the plan.")
    lines.append("3. Merge this PR, then re-run `keyring-audit scan` to "
                 "confirm the value is gone.")
    if fix["manual"]:
        lines.append("")
        lines.append("### Still needs a manual edit")
        for note in fix["manual"]:
            lines.append(f"- {note}")
    lines.append("")
    lines.append("### Verification")
    lines.append("- The fixed files contain no occurrence of the old value "
                 "(checked by keyring-audit before committing).")
    lines.append(f"- Owner at scan time: {owner or 'none found'}.")
    lines.append(f"- Credential status at scan time: "
                 f"{finding.get('validity', {}).get('live', 'unknown')}.")
    lines.append("")
    lines.append("Generated by keyring-audit (dry-run first, approval "
                 "required).")
    return "\n".join(lines) + "\n"


def parse_github_remote(url: str) -> tuple[str, str] | None:
    """(owner, repo) from a git remote URL, or None when it is not
    GitHub."""
    m = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$", url)
    if m:
        return m.group(1), m.group(2)
    return None


def open_fix_pr(root: Path, finding: dict, fix: dict,
                token: str) -> dict:
    """Create the branch, push the fix commit, and open the PR.
    Returns the PR (html_url, number)."""
    remote = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        capture_output=True, text=True, timeout=60)
    if remote.returncode != 0:
        raise ValueError("no git remote 'origin' — cannot open a PR "
                         "without a remote")
    parsed = parse_github_remote(remote.stdout.strip())
    if not parsed:
        raise ValueError("the origin remote is not GitHub — PR automation "
                         "only supports github.com")
    owner, repo = parsed
    base = github.get_default_branch(token, owner, repo)
    base_sha = github.get_ref_sha(token, owner, repo, base)
    fp = (finding.get("fingerprint") or "")[:8]
    branch = f"keyring-audit/fix-{fp}"
    try:
        github.get_ref_sha(token, owner, repo, branch)
    except ValueError:
        pass
    else:
        raise ValueError(f"branch {branch} already exists — delete it or "
                         "pick a different finding")
    github.create_branch(token, owner, repo, branch, base_sha)
    message = (build_pr_title(finding)
               + "\n\nReplaces a hardcoded credential with an "
                 "environment-variable reference (keyring-audit).")
    github.push_commit(token, owner, repo, branch, base_sha,
                       fix["files"], message)
    pr = github.create_pr(token, owner, repo, build_pr_title(finding),
                          branch, base, build_pr_body(finding, fix))
    return pr
