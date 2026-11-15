# Keyring Audit

**What credentials exist, who owns them, what can each one reach, and
which ones can I safely kill or rotate today?**

Keyring Audit is the open, developer-friendly layer between secret
detection and remediation — the part nobody open-source owns. It scans a
repo and its full git history for credentials, proves which ones are
still live, lists what each live one can actually do, ranks them by
risk, and tells the owner exactly how to revoke or rotate them.

- **Discover.** Git history + working tree (including gitignored files
  like `.env`). Detectors for GitHub (classic + fine-grained PATs,
  OAuth, App tokens), AWS (key ID + secret, paired), Slack, GitLab,
  Stripe, private keys, JWTs, and generic high-entropy secrets.
- **Identify.** One read-only identity call per credential proves it is
  live: `GET /user` for GitHub, `sts:GetCallerIdentity` for AWS. Dead,
  live, or unknown — never guessed.
- **Map blast radius.** GitHub scopes come from the `X-OAuth-Scopes`
  header; fine-grained tokens (which return no scope header) are
  probed endpoint by endpoint, and the report says which method was
  used. AWS permissions come from IAM policy reads and
  `GetAccessKeyLastUsed`.
- **Rank risk.** 0–100 from four measured inputs — privilege, exposure,
  age, usage — with every component shown, so the score is auditable.
- **Remediate.** A revoke/rotate guide per credential. AWS rotation is
  a two-key rollover (create new → verify → delete old), never
  delete-first.

## The wedge

Validity checking is solved — TruffleHog does it well, and Gitleaks
covers detection. What no open tool does is the next step: a live
credential mapped to its permissions, its usage, and a safe rotation,
in one tool, for small teams. That is this product.

The 2026 consolidation (Astrix → Cisco, Oasis → Cyera, Entro →
SailPoint, CyberArk → Palo Alto Networks as Idira) left NHI governance
as a platform feature with enterprise pricing. This is the open
alternative. Full verified research: [`PLAN.md`](PLAN.md).

## Install

```bash
pip install .
keyring-audit scan ~/my-repo
```

No third-party dependencies — the AWS checks use a stdlib-only SigV4
signer (`keyring_audit/aws_sign.py`).

## Usage

```bash
keyring-audit scan <path> [--verify|--no-verify]
                         [--format text|json|md] [--output FILE]
                         [--fail-on N] [--allowlist FILE] [-v]
keyring-audit scan --repo <url> [--branch B]   # clone, scan, delete
keyring-audit scan --staged [--no-verify]       # what a commit would add
keyring-audit install-hook [--path <repo>] [--force]
```

- `--verify` (default): check whether each credential is live.
  `--no-verify` skips the network checks.
- `--fail-on N` (default 60): exit 1 when a live finding scores >= N.
  Exit 0 = no live secrets at or above the threshold. Exit 2 = infra
  error (not a directory, unreadable allowlist, …).
- `--allowlist FILE`: a JSON file of salted fingerprints to ignore,
  `{"fingerprints": ["<sha256>", …]}`. Never put a real secret in it.
- `--repo <url>`: clones the repo into a temp dir, scans it (working
  tree + full history), then deletes the clone. Nothing is ever pushed.
  A private repo works when git can clone it (SSH key / credential
  helper) — the tool never handles credentials itself, and any
  credentials pasted into the URL are stripped before the URL is stored
  or shown.
- `--staged`: scans only what is staged for commit (`git diff --cached`,
  added lines only, with real line numbers). Any staged credential
  exits 1, whatever its validity — the point is to stop a secret being
  committed at all. Unstaged changes are not scanned.
- `install-hook`: writes a pre-commit hook (`.git/hooks/pre-commit`)
  that runs `scan --staged --no-verify` on every commit and blocks the
  commit when a secret is staged. The hook calls the same Python the
  tool was installed with; if the tool is not importable it warns and
  lets the commit through rather than breaking your workflow. It
  refuses to overwrite an existing hook unless `--force` is given.

Example output:

```
1. [CRITICAL 85] github-pat-classic (github) — ghp_…cdef
   where: config.py @ c8911414e3dc by Test Dev <dev@example.com>
   validity: live — authenticated as octocat
   can do: repo, user, gist
   risk: privilege 40 (admin scope: ['repo']); exposure 25; age 15; usage 8
   fix:
     1. Revoke the token: https://github.com/settings/tokens …
```

## The safety contract (non-negotiable)

1. **Never store a secret.** The scanner keeps a salted hash and the
   first/last 4 characters. The full value exists only in memory for
   the duration of one validity check. No secret ever touches disk, a
   log, a report, or a network call except the provider's own validity
   endpoint. The test suite enforces this by grepping every rendered
   output for a known test secret.
2. **Read-only checks, minimal scope.** Validity = one identity call.
   Permissions = metadata reads and policy simulation only. No data
   reads, ever.
3. **Only scan what you authorised.** Testing a credential you do not
   own is unauthorised access in most jurisdictions — this tool refuses
   to validate a credential it was not given by its owner.

## Honest limits (v0.3)

- The staged scan reads added lines only — a secret already in history
  is not the staged diff's business (clean it separately; a full scan
  catches it).
- `--repo` does a full clone, so a very large repo takes a while; there
  is no shallow option because the history scan needs the history.

- Validity checks are implemented for GitHub, AWS, Slack, GitLab and
  Stripe. Private keys and JWTs are detected but have no live check —
  a private key is validated by what it unlocks, not by an API call.
- Fine-grained GitHub tokens are probed, not listed — the report says
  so, and a probed "no permissions found" is not the same as "no
  permissions".
- AWS permissions need IAM read; when the key cannot read IAM, the
  report says "permissions unknown (IAM read denied)" instead of
  guessing. The policy simulator does not read resource-based policies.
- Stripe exposes no permissions list for a key via the API: the report
  names the key type (full secret key vs restricted key) instead of
  inventing one. A restricted key that cannot read the account is
  reported live-but-restricted, not dead.
- GitLab group/project tokens cannot be described by the self endpoint;
  the report falls back to `GET /user` and says the scopes are unlisted.
- The history scan reads added lines only, skips binary files and
  files over 10 MB, and a shallow clone only covers the fetched history.

## Roadmap

- **Phase 2:** full blast-radius mapping (AWS policy simulation for
  named high-risk actions).
- **Phase 3:** ownership (commit history, cloud tags) + the 0–100 score.
- **Phase 4:** safe remediation — guided rotation with dry runs and
  approvals, PRs replacing hardcoded keys.
- **Phase 5:** agent identities, shared with Agent Gateway.
- **Phase 6:** CI/CD variables, SaaS integrations, cloud accounts,
  container images.

## Development

```bash
python -m venv .venv && .venv/bin/python -m pip install pytest
.venv/bin/python -m pytest tests/ -q
python scripts/make_scan_fixtures.py   # rebuild fixtures/repo/
```

## Licence

MIT. See [LICENSE](LICENSE).
