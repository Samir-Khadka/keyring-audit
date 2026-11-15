"""Keyring Audit CLI (v0.2).

    keyring-audit scan <path> [--verify|--no-verify]
                             [--format text|json|md] [--output FILE]
                             [--fail-on N] [--allowlist FILE] [-v]

Exit codes: 0 = no live secrets (or all findings below --fail-on),
1 = a live secret at or above the fail-on threshold, 2 = infra error
(not a git repo, unreadable path, …).

The allowlist is a JSON file: {"fingerprints": ["<sha256>", …]} — the
salted fingerprints of findings to ignore (e.g. a test secret that is
meant to be in the repo). Never put a real secret in the allowlist.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .ranking import rank_all
from .report import render
from .scanner import scan
from .validity import check_finding

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_INFRA = 2

log = logging.getLogger("keyring-audit")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="keyring-audit",
        description="What credentials exist, who owns them, what can each "
                    "one reach, and which ones can I safely kill or rotate today?")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)
    scan_p = sub.add_parser("scan", help="scan a repo and its history for secrets")
    scan_p.add_argument("path", type=Path, help="directory to scan")
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
    if args.command != "scan":
        ap.print_help()
        return EXIT_INFRA
    if not args.path.is_dir():
        log.error("%s is not a directory", args.path)
        return EXIT_INFRA
    try:
        allowed = load_allowlist(args.allowlist)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    result = scan(args.path)
    findings = [f for f in result["findings"]
                if f["fingerprint"] not in allowed]
    checked = [check_finding(f, verify=args.verify) for f in findings]
    ranked = rank_all(checked)
    out = render(ranked, result["warnings"], str(args.path), args.format)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    # Exit 1 when a live finding scores at or above the threshold.
    for f in ranked:
        if (f.get("validity", {}).get("live") == "live"
                and f["risk"]["score"] >= args.fail_on):
            return EXIT_FOUND
    return EXIT_OK


def cli(argv=None) -> int:
    try:
        return scan_main(argv)
    except KeyboardInterrupt:
        return EXIT_INFRA


if __name__ == "__main__":
    sys.exit(cli())
