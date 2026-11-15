"""Keyring Audit CLI (v1.4).

    keyring-audit scan <path> [--verify|--no-verify]
                             [--format text|json|md] [--output FILE]
                             [--fail-on N] [--allowlist FILE] [-v]
    keyring-audit scan --repo <url> [--branch B] [same options]
    keyring-audit scan --staged [--no-verify]   (what a commit would add)
    keyring-audit scan-image <image.tar> [--verify|--no-verify]
                             [--format text|json|md] [--output FILE]
                             [--fail-on N]
    keyring-audit ci-secrets --repo <owner/repo> [--path <dir>]
                             [--format text|json|md]
    keyring-audit rotate --fingerprint <fp> [--report FILE | --path DIR]
                         [--format text|md|json]
                         [--execute --approve --old-key-id ID]   (AWS only)
                         [--complete --new-key-id ID --old-key-id ID]
                         [--verify --old-key-id ID [--rotated-at ISO]]
    keyring-audit fix --fingerprint <fp> [--path DIR] [--approve]
    keyring-audit agents [--gateway DIR] [--keys-file FILE]
                         [--policy-dir DIR] [--audit-log FILE ...]
                         [--format text|json|md]

Rotate is a dry run first: without --execute/--complete/--verify it
prints the plan and changes nothing. --execute creates and verifies a
new AWS key (the old key is untouched); --complete deletes the old key
only after the new one is deployed. The old secret is read from the
terminal and used once, in memory — never stored, never written to a
file. The new secret is shown once; save it when it appears.

Exit codes: 0 = no live secrets (or all findings below --fail-on),
1 = a live secret at or above the fail-on threshold, 2 = infra error
(not a git repo, unreadable path, …). Staged mode is the exception:
any staged credential exits 1, whatever its validity — the hook's job
is to stop a secret being committed at all.

`agents` is a discovery report, not a gate: it always exits 0. It
reads an Agent Gateway install — the keys file (or AGENT_KEYS), the
policy directory, and the audit log — and scores every agent key with
the same 0–100 components as any other credential. The `--format json`
output is the shared identity graph both products can read.

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
from .fix import (
    build_pr_body,
    build_pr_title,
    fix_credential,
    open_fix_pr,
    redacted_diff,
)
from .ownership import apply_tag_owner
from .ranking import rank_all
from .remediation import (
    build_plan,
    complete_aws_rollover,
    execute_aws_rollover,
    render_plan,
    verify_old_credential,
)
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
    rot_p = sub.add_parser("rotate",
                           help="plan and perform a safe rotation for one finding (dry run first)")
    rot_p.add_argument("--fingerprint", required=True,
                       help="salted fingerprint of the finding (full, or a unique prefix of 8+ chars)")
    rot_p.add_argument("--report", type=Path,
                       help="JSON report from a previous scan (default: scan --path now)")
    rot_p.add_argument("--path", type=Path, default=Path("."),
                       help="repo to scan when --report is not given (default: current directory)")
    rot_p.add_argument("--format", choices=["text", "json", "md"], default="text")
    rot_p.add_argument("--execute", action="store_true",
                       help="perform the first half of the rollover: create and verify a new AWS key (needs --approve and --old-key-id)")
    rot_p.add_argument("--approve", action="store_true",
                       help="explicit approval for --execute (required)")
    rot_p.add_argument("--complete", action="store_true",
                       help="delete the old key after the new one is deployed (needs --new-key-id and --old-key-id)")
    rot_p.add_argument("--new-key-id",
                       help="the new key id printed by --execute (for --complete)")
    rot_p.add_argument("--old-key-id",
                       help="the old key id (for AWS --execute/--complete/--verify)")
    rot_p.add_argument("--verify", action="store_true",
                       help="re-check whether the old credential is dead")
    rot_p.add_argument("--rotated-at",
                       help="ISO time the rotation completed, for the post-rotation usage check (with --verify)")
    fix_p = sub.add_parser("fix",
                           help="open a PR replacing a hardcoded credential with an env-var reference (dry run first)")
    fix_p.add_argument("--fingerprint", required=True,
                       help="salted fingerprint of the finding (full, or a unique prefix of 8+ chars)")
    fix_p.add_argument("--path", type=Path, default=Path("."),
                       help="repo to scan and fix (default: current directory)")
    fix_p.add_argument("--approve", action="store_true",
                       help="explicit approval to create the branch, commit and PR (required)")
    fix_p.add_argument("--format", choices=["text", "md"], default="text")
    agents_p = sub.add_parser("agents",
                              help="discover and score AI agent identities from an Agent Gateway install (Phase 5)")
    agents_p.add_argument("--gateway", type=Path,
                          help="Agent Gateway install root (policies at <gateway>/policies, audit logs at <gateway>/data)")
    agents_p.add_argument("--keys-file", type=Path,
                          help="gateway --keys-file (JSON: key -> agent id); or set the AGENT_KEYS env var")
    agents_p.add_argument("--policy-dir", type=Path,
                          help="policy directory (default: <gateway>/policies)")
    agents_p.add_argument("--audit-log", type=Path, action="append", dest="audit_logs",
                          help="audit-log JSONL file (repeatable; default: <gateway>/data/*.jsonl)")
    agents_p.add_argument("--live-check",
                          help="running gateway base URL (e.g. http://127.0.0.1:8000) — check each key against it (POST /mcp with a method the gateway does not support; no tool is called, no audit entry is written)")
    agents_p.add_argument("--format", choices=["text", "json", "md"], default="text")
    image_p = sub.add_parser("scan-image",
                             help="scan a container image archive (docker save tar) for credentials baked into its layers")
    image_p.add_argument("path", type=Path,
                         help="the image archive (.tar from docker save)")
    image_p.add_argument("--verify", dest="verify", action="store_true", default=True,
                         help="check each credential against its provider (default)")
    image_p.add_argument("--no-verify", dest="verify", action="store_false",
                         help="skip the provider checks (offline)")
    image_p.add_argument("--format", choices=["text", "json", "md"], default="text")
    image_p.add_argument("--output", type=Path, help="write the report here as well as stdout")
    image_p.add_argument("--fail-on", type=int, default=60,
                         help="exit 1 when a live credential scores at or above this (default 60)")
    ci_p = sub.add_parser("ci-secrets",
                          help="list a repo's GitHub Actions secrets and cross-reference them with its workflow files (Phase 6)")
    ci_p.add_argument("--repo", required=True,
                      help="owner/repo (e.g. Samir-Khadka/keyring-audit)")
    ci_p.add_argument("--path", type=Path,
                      help="local repo to read the workflow files from (default: fetch them via the API)")
    ci_p.add_argument("--format", choices=["text", "json", "md"], default="text")
    conn_p = sub.add_parser("connectors",
                            help="enumerate the non-human identities inside a Slack workspace or a GitLab instance (Phase 6)")
    conn_p.add_argument("--gitlab", action="store_true",
                        help="list the group/project access tokens and deploy tokens visible to a GitLab personal access token (GITLAB_TOKEN or a prompt)")
    conn_p.add_argument("--slack", action="store_true",
                        help="identify a Slack token and list the workspace's installed apps (SLACK_TOKEN or a prompt)")
    conn_p.add_argument("--host", default="https://gitlab.com",
                        help="GitLab host (default https://gitlab.com)")
    conn_p.add_argument("--format", choices=["text", "json", "md"], default="text")
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
    if args.command == "rotate":
        return rotate_main(args)
    if args.command == "fix":
        return fix_main(args)
    if args.command == "agents":
        return agents_main(args)
    if args.command == "scan-image":
        return scan_image_main(args)
    if args.command == "ci-secrets":
        return ci_secrets_main(args)
    if args.command == "connectors":
        return connectors_main(args)
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
    # A cloud-tag owner found during validation wins over the commit
    # author / blame owner attached by the scanner.
    checked = [apply_tag_owner(f) for f in checked]
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


def _load_rotate_findings(args) -> list[dict]:
    """Findings for rotate: from a previous JSON report, or a fresh
    scan (with verification, so the plan knows live/dead and last-used)."""
    if args.report:
        try:
            doc = json.loads(args.report.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"report {args.report} unreadable: {e}") from None
        return doc.get("findings", [])
    if not args.path.is_dir():
        raise ValueError(f"{args.path} is not a directory")
    result = scan(args.path)
    checked = [check_finding(f, verify=True) for f in result["findings"]]
    return [apply_tag_owner(f) for f in checked]


def _find_by_fingerprint(findings: list[dict], fp: str) -> dict:
    if len(fp) >= 8:
        matches = [f for f in findings
                   if f.get("fingerprint", "").startswith(fp)]
    else:
        matches = [f for f in findings if f.get("fingerprint") == fp]
    if not matches:
        raise ValueError(f"no finding with fingerprint {fp!r}")
    if len(matches) > 1:
        raise ValueError(f"fingerprint prefix {fp!r} matches "
                         f"{len(matches)} findings — use more characters")
    return matches[0]


def _prompt_secret(prompt: str) -> str:
    """Read a credential from the terminal, hidden. Used once, in
    memory — never stored, never written anywhere."""
    import getpass

    value = getpass.getpass(prompt)
    if not value:
        raise ValueError("no value entered")
    return value


def rotate_main(args) -> int:
    modes = sum([args.execute, args.complete, args.verify])
    if modes > 1:
        log.error("choose one of --execute, --complete, --verify")
        return EXIT_INFRA
    try:
        findings = _load_rotate_findings(args)
        finding = _find_by_fingerprint(findings, args.fingerprint)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    plan = build_plan(finding)
    if not modes:
        # Dry run: the plan, and nothing else changes.
        sys.stdout.write(render_plan(plan, args.format))
        return EXIT_OK
    if args.verify:
        try:
            value = _prompt_secret(
                f"Old {finding['provider']} credential (hidden, never "
                "stored): ")
            result = verify_old_credential(finding, value,
                                           old_key_id=args.old_key_id,
                                           rotated_at=args.rotated_at)
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
        if result.get("dead") is None:
            log.error("%s", result["reason"])
            return EXIT_INFRA
        if result["dead"]:
            sys.stdout.write("The old credential is DEAD — the rotation "
                             "worked.\n")
            if result.get("used_after_rotation"):
                sys.stdout.write(
                    "WARNING: it was last used at "
                    f"{result['last_used']}, AFTER the rotation — "
                    "something still holds the old key. Find and update "
                    "that caller before calling this done.\n")
                return EXIT_FOUND
            return EXIT_OK
        sys.stdout.write("The old credential is still LIVE — the rotation "
                         "did not take effect yet. Do not delete anything "
                         "until it is dead.\n")
        return EXIT_FOUND
    if finding["provider"] != "aws":
        log.error("automated rotation is AWS-only — %s tokens are "
                  "rotated in the provider's web UI. The plan above is "
                  "the manual path; use --verify afterwards to confirm "
                  "the old token is dead.",
                  finding["provider"])
        sys.stdout.write(render_plan(plan, args.format))
        return EXIT_INFRA
    if args.execute:
        if not args.approve:
            log.error("--execute needs --approve: rotation is a real "
                      "change. Read the plan first (run rotate without "
                      "--execute), then re-run with --approve.")
            return EXIT_INFRA
        if not plan["automated"]:
            log.error("cannot roll over this key: %s",
                      "it is dead — nothing to rotate"
                      if finding.get("validity", {}).get("live") == "dead"
                      else "it is an assumed-role credential, which has "
                           "no access keys")
            return EXIT_INFRA
        if not args.old_key_id:
            log.error("--execute needs --old-key-id (the key id is an "
                      "identifier, not a secret — it is in the AWS console "
                      "and in the file the finding came from)")
            return EXIT_INFRA
        for w in plan["warnings"]:
            log.warning("%s", w)
        try:
            old_secret = _prompt_secret("Old AWS secret (hidden, never "
                                        "stored): ")
            out = execute_aws_rollover(finding, args.old_key_id, old_secret)
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
        sys.stdout.write(
            "New key created and verified live:\n"
            f"  key id: {out['new_key_id']}\n"
            f"  secret: {out['new_secret']}\n"
            "SAVE THE SECRET NOW — AWS shows it once, and this tool "
            "never stores it.\n"
            "Update every application and config to the new key, confirm "
            "it works, then finish with:\n"
            f"  keyring-audit rotate --fingerprint {finding['fingerprint']} "
            f"--complete --new-key-id {out['new_key_id']} "
            f"--old-key-id {args.old_key_id}\n")
        return EXIT_OK
    # --complete
    if not args.new_key_id or not args.old_key_id:
        log.error("--complete needs --new-key-id and --old-key-id")
        return EXIT_INFRA
    try:
        new_secret = _prompt_secret("New AWS secret (hidden, never "
                                    "stored): ")
        out = complete_aws_rollover(finding, args.old_key_id,
                                    args.new_key_id, new_secret)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    if not out["deleted"]:
        log.error("%s", out["reason"])
        return EXIT_INFRA
    sys.stdout.write("Old key deleted and confirmed gone from the user's "
                     "key list. Re-run the scan to confirm it no longer "
                     "appears.\n")
    return EXIT_OK


def fix_main(args) -> int:
    """Open a PR replacing a hardcoded credential with an env-var
    reference. A dry run first: without --approve it prints the diff
    (secret redacted) and the PR title and body, and changes nothing."""
    if not args.path.is_dir():
        log.error("%s is not a directory", args.path)
        return EXIT_INFRA
    try:
        result = scan(args.path)
        finding = _find_by_fingerprint(result["findings"], args.fingerprint)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    # The values to replace: for AWS, the key id AND the secret; for
    # every other provider, the single token.
    values = [finding.get("_secret")]
    if finding.get("provider") == "aws" and finding.get("key_id"):
        values = [finding["key_id"], finding.get("_secret")]
    values = [v for v in values if v]
    if not values:
        log.error("the finding has no credential value to replace — the "
                  "AWS key id was found without its secret, so there is "
                  "nothing to rotate or fix in the code")
        return EXIT_INFRA
    try:
        fix = fix_credential(args.path, finding, values)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    if not fix["files"]:
        log.error("nothing could be fixed automatically")
        for note in fix["manual"]:
            log.error("  %s", note)
        return EXIT_INFRA
    title = build_pr_title(finding)
    body = build_pr_body(finding, fix)
    if not args.approve:
        sys.stdout.write("DRY RUN — nothing changed, no branch or PR "
                         "created. Re-run with --approve to open the PR.\n\n")
        from .detectors import redact as _redact

        replacements = [(v, _redact(v)) for v in values]
        for rel, new_content in fix["files"].items():
            old_content = (args.path / rel).read_text()
            sys.stdout.write(redacted_diff(rel, old_content, new_content,
                                           replacements))
        sys.stdout.write(f"\nPR title: {title}\n\n{body}\n")
        sys.stdout.write("Would create branch "
                         f"keyring-audit/fix-{finding['fingerprint'][:8]} "
                         "and open a PR against the repo's default branch.\n")
        if fix["manual"]:
            sys.stdout.write("Still needs a manual edit:\n")
            for note in fix["manual"]:
                sys.stdout.write(f"  - {note}\n")
        return EXIT_OK
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            token = _prompt_secret("GitHub token (hidden, used once to "
                                   "open the PR): ")
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
    try:
        pr = open_fix_pr(args.path, finding, fix, token)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    sys.stdout.write(f"PR opened: {pr.get('html_url')}\n")
    if fix["manual"]:
        sys.stdout.write("Still needs a manual edit:\n")
        for note in fix["manual"]:
            sys.stdout.write(f"  - {note}\n")
    return EXIT_OK


def agents_main(args) -> int:
    """Discover and score AI agent identities from an Agent Gateway
    install. A discovery report, not a gate: always exits 0. The keys
    are read only to fingerprint them (salted hash + first/last 4) and
    are never printed or stored."""
    from .agents import (build_agent_identities, load_audit_log, load_keys,
                         load_policies, render_agents)

    policy_dir = args.policy_dir
    if policy_dir is None and args.gateway is not None:
        policy_dir = args.gateway / "policies"
    if policy_dir is None:
        log.error("agents needs --gateway or --policy-dir")
        return EXIT_INFRA
    try:
        keys = load_keys(args.keys_file)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("cannot read the agent keys: %s", e)
        return EXIT_INFRA
    policies = load_policies(policy_dir)
    audit_logs = list(args.audit_logs or [])
    if not audit_logs and args.gateway is not None:
        data_dir = args.gateway / "data"
        if data_dir.is_dir():
            audit_logs = sorted(data_dir.glob("*.jsonl"))
    audit = load_audit_log(audit_logs)
    identities = build_agent_identities(keys, policies, audit,
                                        live_check_url=args.live_check)
    if not identities:
        print("No agent identities found — no policies, no audit trail, "
              "no keys.")
        return EXIT_OK
    sys.stdout.write(render_agents(identities, audit, args.format,
                                   str(args.gateway or "")))
    sys.stdout.write("\n")
    return EXIT_OK


def scan_image_main(args) -> int:
    """Scan a container image archive for credentials baked into its
    layers. The same pipeline as `scan`: verify each credential
    against its provider, rank it, render the report. Exit 1 when a
    live credential scores at or above --fail-on."""
    from .images import scan_image
    from .validity import check_finding

    try:
        result = scan_image(args.path)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    checked = [check_finding(f, verify=args.verify)
               for f in result["findings"]]
    checked = [apply_tag_owner(f) for f in checked]
    ranked = rank_all(checked)
    out = render(ranked, result["warnings"], str(args.path), args.format)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    for f in ranked:
        if (f.get("validity", {}).get("live") == "live"
                and f["risk"]["score"] >= args.fail_on):
            return EXIT_FOUND
    return EXIT_OK


def ci_secrets_main(args) -> int:
    """List a repo's GitHub Actions secrets and cross-reference them
    with its workflow files. A report, not a gate: always exits 0.
    The token needs the `repo` scope (or Secrets: read) and comes
    from GITHUB_TOKEN or a prompt, used once. No secret value is ever
    read — GitHub never returns one."""
    from .ci import (build_ci_findings, list_actions_secrets,
                     load_workflows_api, load_workflows_local, render_ci)

    if "/" not in args.repo:
        log.error("--repo must be owner/repo")
        return EXIT_INFRA
    owner, repo = args.repo.split("/", 1)
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            token = _prompt_secret("GitHub token (hidden, used once to "
                                   "list the Actions secrets): ")
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
    try:
        secrets = list_actions_secrets(owner, repo, token)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    if args.path is not None:
        if not args.path.is_dir():
            log.error("%s is not a directory", args.path)
            return EXIT_INFRA
        workflows = load_workflows_local(args.path)
    else:
        workflows = load_workflows_api(owner, repo, token)
    findings = build_ci_findings(owner, repo, secrets, workflows)
    ranked = rank_all(findings)
    # An unused secret is safe to remove, whatever its liveness (which
    # cannot be checked) — the ranking's safe_to_kill needs a live
    # verdict, so this is set here.
    for f in ranked:
        if not f["used_in"]:
            f["risk"]["safe_to_kill"] = True
    sys.stdout.write(render_ci(ranked, owner, repo, args.format))
    sys.stdout.write("\n")
    return EXIT_OK


def connectors_main(args) -> int:
    """Enumerate the non-human identities inside a Slack workspace or
    a GitLab instance. A discovery report, not a gate: always exits 0.
    The token comes from GITLAB_TOKEN / SLACK_TOKEN or a prompt, used
    once. No secret value is ever listed — GitLab never returns a
    token's value after creation, and Slack never returns an app's
    token."""
    from .connectors import (gitlab_connectors, render_connectors,
                             slack_connectors)
    from .ranking import rank_all

    if args.gitlab == args.slack:
        log.error("pass exactly one of --gitlab or --slack")
        return EXIT_INFRA
    if args.gitlab:
        token = os.environ.get("GITLAB_TOKEN")
        if not token:
            try:
                token = _prompt_secret("GitLab personal access token "
                                       "(hidden, used once to list the "
                                       "tokens it can see): ")
            except ValueError as e:
                log.error("%s", e)
                return EXIT_INFRA
        try:
            result = gitlab_connectors(token, args.host)
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
        result["findings"] = rank_all(result["findings"])
        sys.stdout.write(render_connectors(result, "gitlab", args.format))
        sys.stdout.write("\n")
        return EXIT_OK
    token = os.environ.get("SLACK_TOKEN")
    if not token:
        try:
            token = _prompt_secret("Slack token (hidden, used once to "
                                   "identify it and list the apps): ")
        except ValueError as e:
            log.error("%s", e)
            return EXIT_INFRA
    try:
        result = slack_connectors(token)
    except ValueError as e:
        log.error("%s", e)
        return EXIT_INFRA
    sys.stdout.write(render_connectors(result, "slack", args.format))
    sys.stdout.write("\n")
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
