"""Keyring Audit CLI (v0.4).

    keyring-audit scan <path> [--verify|--no-verify]
                             [--format text|json|md] [--output FILE]
                             [--fail-on N] [--allowlist FILE] [-v]
    keyring-audit scan --repo <url> [--branch B] [same options]
    keyring-audit scan --staged [--no-verify]   (what a commit would add)
    keyring-audit install-hook [--path <repo>] [--force]

Exit codes: 0 = no live secrets (or all findings below --fail-on),
1 = a live secret at or above the fail-on threshold, 2 = infra error
(not a git repo, unreadable path, …). Staged mode is the exception:
any staged credential exits 1, whatever its validity — the hook's job
is to stop a secret being committed at all.

The allowlist is a JSON file: {"fingerprints": ["<sha256>", …]} — the
salted fingerprints of findings to ignore (e.g. a test secret that is
meant to be in the repo). Never put a real secret in the allowlist.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import stat
import sys
from pathlib import Path

from . import __version__
from .ranking import rank_all
from .report import render
from .scanner import scan, scan_remote, scan_staged
from .validity import check_finding

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_INFRA = 2

log = logging.getLogger("keyring-audit")

HOOK_TEMPLATE = """#!/bin/sh
# keyring-audit pre-commit hook — blocks commits that stage a secret.
# Installed by `keyring-audit install-hook`. Remove this file to uninstall.
# The check is offline (--no-verify) so commits stay fast; a full scan
# with verification is what `keyring-audit scan` is for.
KEYRING_AUDIT_PY="{python}"
if ! "$KEYRING_AUDIT_PY" -c "import keyring_audit" 2>/dev/null; then
    echo "keyring-audit: not importable under $KEYRING_AUDIT_PY — commit NOT scanned (reinstall keyring-audit to enable the check)" >&2
    exit 0
fi
exec "$KEYRING_AUDIT_PY" -m keyring_audit scan --staged --no-verify
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="keyring-audit",
        description="What credentials exist, who owns them, what can each "
                    "one reach, and which ones can I safely kill or rotate today?")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)
    scan_p = sub.add_parser("scan", help="scan a repo and its history for secrets")
    scan_p.add_argument("path", type=Path, nargs="?", default=Path("."),
                        help="directory to scan (default: current directory)")
    scan_p.add_argument("--repo",
                        help="clone this remote repo to a temp dir, scan it, delete the clone")
    scan_p.add_argument("--branch",
                        help="branch to clone with --repo (default: the remote's default branch)")
    scan_p.add_argument("--staged", action="store_true",
                        help="scan only what is staged for commit (git diff --cached); "
                             "any staged credential exits 1")
    scan_p.add_argument("--verify", dest="verify", action="store_true", default=True,
                        help="check whether each credential is live (default)")
    scan_p.add_argument("--no-verify", dest="verify", action="store_false",
                        help="skip validity checks")
    scan_p.add_argument("--format", choices=["text", "json", "md"], default="text")
    scan_p.add_argument("--output", type=Path, help="write the report here as well as stdout")
    scan_p.add_argument("--fail-on", type=int, default=60,
                        help="exit 1 when a live finding scores >= N (default 60)")
    scan_p.add_argument("--allowlist", type=Path,
                        help="JSON file of salted fingerprints to ignore")
    scan_p.add_argument("-v", "--verbose", action="store_true")
    hook_p = sub.add_parser("install-hook",
                            help="install a pre-commit hook that blocks commits staging a secret")
    hook_p.add_argument("--path", type=Path, default=Path("."),
                        help="repo to install the hook in (default: current directory)")
    hook_p.add_argument("--force", action="store_true",
                        help="overwrite an existing pre-commit hook")
    return ap


def load_allowlist(path: Path | None) -> set[str]:
    if not path:
        return set()
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"allowlist {path} unreadable: {e}") from None
    fps = doc.get("fingerprints", [])
    if not isinstance(fps, list):
        raise ValueError("allowlist: 'fingerprints' must be a list")
    return set(fps)


def scan_main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False)
                        else logging.INFO, format="%(levelname)s %(message)s")
    if args.command == "install-hook":
        return install_hook_main(args)
    if args.command != "scan":
        ap.print_help()
        return EXIT_INFRA
    if args.repo and args.staged:
        log.error("cannot combine --repo and --staged")
        return EXIT_INFRA
    if args.branch and not args.repo:
        log.error("--branch needs --repo")
        return EXIT_INFRA
    try:
        allowed = load_allowlist(args.allowlist)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    if args.repo:
        try:
            result = scan_remote(args.repo, args.branch)
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
        scanned_path = result["path"]
    elif args.staged:
        if not args.path.is_dir():
            log.error("%s is not a directory", args.path)
            return EXIT_INFRA
        result = scan_staged(args.path)
        scanned_path = str(args.path)
    else:
        if not args.path.is_dir():
            log.error("%s is not a directory", args.path)
            return EXIT_INFRA
        result = scan(args.path)
        scanned_path = str(args.path)
    findings = [f for f in result["findings"]
                if f["fingerprint"] not in allowed]
    checked = [check_finding(f, verify=args.verify) for f in findings]
    ranked = rank_all(checked)
    out = render(ranked, result["warnings"], scanned_path, args.format)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    if args.staged:
        # Any staged credential blocks the commit, whatever its validity:
        # the hook's job is to stop a secret being committed at all.
        return EXIT_FOUND if ranked else EXIT_OK
    # Exit 1 when a live finding scores at or above the threshold.
    for f in ranked:
        if (f.get("validity", {}).get("live") == "live"
                and f["risk"]["score"] >= args.fail_on):
            return EXIT_FOUND
    return EXIT_OK


def install_hook_main(args) -> int:
    """Write .git/hooks/pre-commit in the given repo."""
    root = args.path
    hooks_dir = root / ".git" / "hooks"
    if not (root / ".git").is_dir():
        log.error("%s is not a git repository (no .git directory)", root)
        return EXIT_INFRA
    hook_path = hooks_dir / "pre-commit"
    if hook_path.exists() and not args.force:
        log.error("%s already exists — add the keyring-audit line to it "
                  "manually, or re-run with --force to overwrite it",
                  hook_path)
        return EXIT_INFRA
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(HOOK_TEMPLATE.format(python=sys.executable))
    os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log.info("installed pre-commit hook at %s", hook_path)
    return EXIT_OK


def cli(argv=None) -> int:
    try:
        return scan_main(argv)
    except KeyboardInterrupt:
        return EXIT_INFRA


if __name__ == "__main__":
    sys.exit(cli())
