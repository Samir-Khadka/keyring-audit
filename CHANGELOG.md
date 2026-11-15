# Changelog

## v0.4.0 — 2026-11-15

Phase 2: AWS blast-radius mapping. The GitHub half (scopes / probed
permissions) was already built; this release adds the AWS simulation.

- `iam:SimulatePrincipalPolicy` against the 8 named high-risk actions
  (iam:CreateUser, AttachUserPolicy, PutUserPolicy, CreateAccessKey,
  PassRole, s3:DeleteBucket, ec2:TerminateInstances,
  rds:DeleteDBInstance) — one call, right after the identity check, for
  every principal type. A key that cannot read IAM still gets its blast
  radius measured when simulation is allowed. 90 tests.
- The report shows a `blast radius (simulation)` line with the allowed
  actions, and the caveat on every finding: the simulator does not read
  resource-based policies, so "allowed" is partial evidence. When
  simulation is not permitted, the report falls back to the policy
  names and says so.
- Ranking now scores the simulation: a simulated privilege-escalation
  action is 40 (a key that can escalate is effectively admin, whatever
  its policy names say), a destructive action 35, nothing allowed 10.

## v0.3.0 — 2026-11-15

Remote scanning and the pre-commit hook — stop secrets before they are
committed, and scan repos you have not cloned.

- `scan --repo <url> [--branch B]`: clones into a temp dir, scans
  working tree + full history, deletes the clone. Nothing is ever
  pushed. A private repo works when git can clone it; the tool never
  handles credentials, and any credentials pasted into the URL are
  stripped before the URL is stored or shown. 82 tests.
- `scan --staged`: scans only what is staged (`git diff --cached`,
  added lines, real line numbers). Any staged credential exits 1,
  whatever its validity. Unstaged changes are not scanned.
- `install-hook [--path <repo>] [--force]`: writes
  `.git/hooks/pre-commit` running `scan --staged --no-verify` (offline,
  so commits stay fast). Refuses to overwrite an existing hook without
  `--force`; if the tool is not importable it warns and lets the commit
  through instead of breaking the workflow.

## v0.2.0 — 2026-11-15

Slack, GitLab and Stripe validity checks — every detected provider now
has a live check.

- Slack: `POST /api/auth.test` (HTTP 200 even for a bad token, so the
  `ok` field decides; `invalid_auth` = dead) + scopes from the
  `X-OAuth-Scopes` response header. 68 tests.
- GitLab: `GET /api/v4/personal_access_tokens/self` — scopes, active,
  revoked, expiry in one call; fallback to `GET /user` for
  group/project tokens and older GitLab (scopes unlisted, report says so).
- Stripe: `GET /v1/account` — 200 = live (account id + livemode),
  401 = dead, 403 = live but restricted. Stripe exposes no permissions
  list for a key, so the report names the key type (full secret key vs
  restricted key) instead of inventing one.
- Ranking now scores Slack/GitLab/Stripe privilege from their real
  permissions (GitLab `api`/`sudo` = 40, Stripe full secret key = 40,
  Slack write scopes = 35, restricted key = 25).
- Reports carry the package version instead of a hardcoded string.

## v0.1.0 — 2026-11-15

First release: the wedge MVP. CLI + GitHub App-ready scanner for
GitHub and AWS, with validity checks, permissions, ranking, and
revoke/rotate guides.

- Detectors: GitHub (classic + fine-grained PATs, OAuth, user-to-server,
  server-to-server, refresh), AWS key ID + paired secret, Slack, GitLab,
  Stripe, private keys, JWTs, generic high-entropy secrets.
- Git history scan (`git log -p`, added lines) + working-tree scan
  (including gitignored files like `.env`).
- Validity: GitHub `GET /user` with `X-OAuth-Scopes` (classic) or
  endpoint probing (fine-grained — no scope header); AWS
  `sts:GetCallerIdentity` via a stdlib-only SigV4 signer.
- Permissions: GitHub scopes / probed permissions; AWS attached +
  inline policies and `GetAccessKeyLastUsed`.
- Ranking 0–100 (privilege 40, exposure 30, age 15, usage 15) with
  auditable components; bands Low/Medium/High/Critical; "safe to kill".
- Revoke/rotate guides per credential (AWS = two-key rollover).
- Reports in text, JSON, Markdown. `--allowlist` by salted fingerprint.
- Safety contract enforced by tests: no rendered output contains a
  full test secret.
- 46 tests. Fixtures generated deterministically by
  `scripts/make_scan_fixtures.py`.
