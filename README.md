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
  `GetAccessKeyLastUsed` — and from `iam:SimulatePrincipalPolicy`
  against 8 named high-risk actions, which measures what the key can
  actually do even when it cannot read IAM. A simulated "allowed" is
  partial evidence (the simulator does not read resource-based
  policies) and the report says so.
- **Rank risk.** 0–100 from five measured inputs — privilege, exposure,
  age, usage, ownership — with every component shown, so the score is
  auditable. A credential with no owner scores 10 on ownership:
  nobody to ask to rotate it is itself a risk factor.
- **Rotate safely.** `keyring-audit rotate --fingerprint <fp>` prints
  the remediation plan and changes nothing (dry run first). With
  `--execute --approve` it performs the AWS two-key rollover — create
  and verify a new key, old key untouched — and prints the new secret
  once. `--complete` deletes the old key only after the new one is
  deployed, and confirms it is gone. `--verify` re-checks the old
  credential afterwards, and flags any use after the rotation time.
  GitHub, Slack, GitLab and Stripe are manual steps (no provider API
  can create or revoke those tokens from the CLI) with the same
  `--verify` afterwards. The old secret is read from the terminal and
  used once, in memory — never stored, never written to a file.
- **Fix with a PR.** `keyring-audit fix --fingerprint <fp>` opens a
  pull request that replaces a hardcoded credential with an
  environment-variable reference (the vault reference): Python reads
  `os.environ`, JS reads `process.env`, shell reads `"${VAR}"`, YAML
  reads `${VAR}` (or `${{ secrets.VAR }}` in workflows), and a `.env`
  line becomes a comment naming where the value lives. A dry run
  first, always — the diff (secret redacted) and the PR title and body
  are printed, nothing changes. With `--approve` it creates the
  branch, commits, and opens the PR. Anything it cannot fix safely
  (a value inside a longer string, a JSON file) is a manual step in
  the PR body, not a guess.
- **Agent identities.** `keyring-audit agents --gateway <dir>`
  discovers and scores the AI agent keys an Agent Gateway install
  governs: the keys file (or `AGENT_KEYS`), the policy directory, and
  the audit log. Every agent key is a credential — fingerprinted
  (salted hash + first/last 4, never printed), owned by its agent,
  scored on what its policy allows and when the audit log last saw
  it. The audit log's hash chain is verified and the result reported.
  An agent with no audit entries is a "safe to kill" candidate; an
  agent with many denied attempts is flagged. `--format json` is the
  shared identity graph both products can read. With
  `--live-check <url>` each key is also checked against a running
  gateway (POST `/mcp` with a method the gateway does not support —
  the key is checked before dispatch, so a 401 means dead and any
  other answer means live, with no tool called and no audit entry
  written; a gateway that cannot be reached leaves the key
  "unknown", never "dead").
- **Assign owners.** Every finding names who is responsible: AWS
  Owner/Team tags first, then the commit author, then `git blame` for
  working-tree and staged lines (an uncommitted line names the local
  git user). The report shows the owner and how it was found.
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

## Honest limits (v0.8)

- The staged scan reads added lines only — a secret already in history
  is not the staged diff's business (clean it separately; a full scan
  catches it).
- `--repo` does a full clone, so a very large repo takes a while; there
  is no shallow option because the history scan needs the history.
- The AWS simulation does not read resource-based policies, so a
  simulated "allowed" is partial evidence — the report says so on
  every finding it applies to. When simulation is not permitted, the
  report falls back to the policy names.
- Ownership is best-effort: `git blame` runs once per working-tree
  finding (fine for a handful, slow for hundreds), and AWS tags need
  IAM read. A finding whose owner cannot be determined is reported as
  "no owner" and scores 10 on ownership — that is the honest answer,
  not a gap to hide.
- Rotation is AWS-only for automation, and only for IAM users (an
  assumed-role credential has no access keys to create).
- The PR fix only covers `.py`, `.js`/`.ts`, `.sh`, `.env` and
  `.yml`/`.yaml`, and only simple assignments. A value that lives only
  in history cannot be fixed by a PR — rewrite the history with
  git filter-repo or BFG. The fix needs a GitHub remote and a token
  (`GITHUB_TOKEN`, or one pasted at the prompt); the PR's file diff
  will show the removed line, but that line is already in the repo,
  so the PR exposes it to no one new.
- Agent identities: the gateway's policy files are read with a focused
  extractor (agent, risk_tier, the `tool:` lines under `allow:`), not
  a YAML parser — Keyring Audit stays stdlib-only. If the policy
  format grows, the extractor is the place to add a real parser. A
  gateway key's liveness comes from the audit log unless
  `--live-check` is given, in which case the running gateway is asked
  directly; the probe calls no tool and writes no audit entry.

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

- **Phase 5 (remaining):** deeper Agent Gateway integration — a single
  combined install (Keyring Audit as the discovery half of Agent
  Gateway). The plan flags this as a bigger decision for later; it is
  Samir's call, not a build step.
- **Phase 6:** coverage — CI/CD variables, SaaS accounts, cloud
  accounts, container images.
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
