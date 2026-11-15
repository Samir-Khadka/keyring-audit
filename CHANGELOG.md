# Changelog

## v1.4.0 — 2026-11-15

Phase 6 coverage, fifth and final piece: Slack/GitLab connectors.
Phase 6 is now COMPLETE.

- `keyring-audit connectors --gitlab` lists the group and project
  access tokens and deploy tokens visible to a GitLab personal
  access token, with scopes, expiry and revoked status, ranked with
  the shared scoring (an `api`-scoped token is admin-level, 40; a
  deploy token is read-only, 15; exposure 12, "in GitLab, not in
  code"). A token with no expiry is flagged as a sprawl risk. 221
  tests.
- `keyring-audit connectors --slack` identifies a Slack token
  (`auth.test` — workspace, bot or user) and lists the workspace's
  installed apps (`apps.list`). Slack never returns an app's token,
  so the report names the apps and says the token itself cannot be
  listed. A token without the `apps:read` scope falls back to the
  identity only, and the report says why.
- Honest limits: GitLab never returns a token's value after
  creation, so the report lists identities, not secrets. A full live
  enumeration was not dogfooded — no real GitLab or Slack token was
  available; the enumeration logic is proven by mocked tests, and
  the live path was verified by the real providers rejecting a bad
  token (GitLab 401, Slack `invalid_auth`). The first live attempt
  timed out on a transient sandbox-proxy stall; the retry was fast.

## v1.3.0 — 2026-11-15

Phase 6 coverage, fourth piece: SaaS integrations.

- OpenAI, Anthropic, Notion and Hugging Face API keys are detected
  and validated with one safe read-only call each (list models,
  `users/me`, `whoami`). A live AI key scores 35 on privilege — it
  can call any model and spend on the account, and a leak can run
  usage up into thousands of dollars within hours, so a verified-live
  key lands High or Critical and the guide says to revoke it within
  minutes. A Notion token's type is read from `users/me` (a personal
  access token acts as the user, 35; a bot token is scoped to shared
  pages, 25); a Hugging Face token's role is read from `whoami`
  (write 35, read 15). 213 tests.
- Honest limits: the models endpoints do not say whether an OpenAI
  key is project-scoped or organisation-wide; a Notion token's pages
  are not listed.
- Dogfood: a demo repo with one fake key per provider. All four were
  verified DEAD against the real provider endpoints (401 from each),
  in ~2 seconds. The first run timed out on all four (a transient
  sandbox-proxy stall); the retry was fast — the checks themselves
  are correct, and a network stall is reported as "unknown", never
  as dead.

## v1.2.0 — 2026-11-15

Phase 6 coverage, third piece: cloud accounts (GCP, Azure).

- GCP service-account keys and Azure service-principal client secrets
  are detected and validated by exchanging the credential for a token.
  A GCP key is checked with the OAuth2 JWT grant — RS256 implemented
  in the standard library (no crypto dependency), verified byte-for-byte
  against OpenSSL's own signature. An Azure secret is checked with
  the client-credentials grant. The GCP token's scope and the Azure
  token's roles are reported as the permission list, so the ranking
  scores what the credential can actually do (cloud-platform scope and
  directory/application write roles score 40). 196 tests.
- Honest limits, stated in the report: a GCP API key's validity is
  always "unknown" (whether it works depends on which APIs are enabled
  for its project); an Azure check against a tenant id that does not
  exist returns "unknown", not "dead". The IAM policy read is not in
  v1.2 — the token's scope/roles are the evidence.
- Dogfood: a demo repo with a test GCP service-account key and a test
  Azure secret. The GCP key was verified DEAD against the real Google
  token endpoint (the grant was rejected), scored 30 with "safe to
  kill: yes". The Azure secret returned "unknown" (the fake tenant id
  does not exist, so the endpoint rejected the request itself).

## v1.1.0 — 2026-11-15

Phase 6 coverage, second piece: CI/CD variables.

- `ci-secrets --repo <owner/repo>` lists a repo's GitHub Actions
  secrets and cross-references them with its workflow files. A secret
  no workflow references is flagged safe to remove; a secret not
  updated in over two years is flagged stale. The age component is
  measured from `updated_at` (the last time the secret was set — the
  closest thing to a rotation date); CI exposure scores 12 (not in
  code, but available to every workflow run). 180 tests.
- Honest limit, stated in the report: GitHub never returns a secret's
  value, so liveness is always "unknown" and the privilege is scored
  in the middle (20) rather than assumed safe. "Used" means a workflow
  references `${{ secrets.NAME }}` — whether the workflow actually
  runs is not something the API says.
- Dogfood: three of Samir's repos (keyring-audit, portfolio, kavach)
  all have 0 Actions secrets — the API path works, and the answer is
  clean. The used/unused/stale cross-reference is proven by mocked
  tests.

## v1.0.0 — 2026-11-15

Phase 6 coverage, first piece: container images. The two repos stay
separate — Samir's call, recorded here: Keyring Audit and Agent
Gateway share the identity graph (`agents --format json`), not a repo.

- `scan-image <image.tar>` scans a `docker save` archive for
  credentials baked into its layers — the same detectors, the same
  validity checks, the same ranked report as a repo scan. A finding's
  source is "layer <n>: <file path>", so the fix is obvious: the
  secret was baked in at that layer. No Docker daemon is needed; a
  plain tar of files is scanned as a single layer. 171 tests.
- Image exposure scores 15 (between a working tree at 7 and git
  history at 17): the secret ships with the image, to anyone who
  pulls it. A secret that appears in several layers is deduped to its
  earliest layer — that is the layer to fix. Whiteout files and
  binary files are skipped; a layer that cannot be read is a warning,
  not a failure.
- Dogfood: a two-layer demo image (a GitHub PAT in layer 0, an AWS
  pair in a gzipped layer 1) — both found, both verified dead against
  the real providers, with the layer and file named in the report.

## v0.9.0 — 2026-11-15

Phase 5, second half: the live key check. The remaining Phase 5
piece is the single combined install, which the plan flags as a
bigger decision for later — Samir's call, not a build step.

- `agents --live-check <url>` checks each agent key against a running
  gateway: a POST to `<url>/mcp` with the key in `x-agent-key` and a
  method the gateway does not support. The gateway checks the key
  before dispatching, so a 401 means the key is unknown (dead) and
  any other answer means the key was accepted (live) — without
  calling any tool, touching the upstream, or writing an audit entry
  (verified against the real gateway: the probe wrote nothing to the
  audit log). A gateway that cannot be reached leaves the key
  "unknown", never "dead". 163 tests.
- A dead key now scores 0 on privilege and is flagged "safe to kill",
  whatever its policy allows — a dead credential cannot be used.
- Dogfood against the real gateway (both demo keys + a bogus key):
  support-bot High 70 (live), analyst-bot Medium 38 (live, never
  used, safe to kill), ghost-bot Low 23 (dead, safe to kill).

## v0.8.0 — 2026-11-15

Phase 5 (agent identities), first half. The Agent Gateway tie-in:
every agent key the gateway governs is a Keyring Audit credential,
and every Gateway policy decision is logged against it.

- `agents --gateway <dir>` discovers and scores the AI agent keys an
  Agent Gateway install governs — the keys file (or `AGENT_KEYS`),
  the policy directory, and the audit log. Each agent key is
  fingerprinted (salted hash + first/last 4, never printed), owned by
  its agent, and scored with the same 0–100 components as any other
  credential: privilege from what its policy allows (a tool that can
  send, refund or delete scores highest) and the risk_tier, usage
  from the audit log's last-used time, exposure as the gateway key
  config. 156 tests.
- The audit log's hash chain is verified (the gateway's own
  algorithm) and the result reported — a broken chain is itself a
  finding. An agent with no audit entries is a "safe to kill"
  candidate; an agent with many denied attempts is flagged (it keeps
  trying tools its policy denies).
- `--format json` is the shared identity graph both products can
  read: gateway, audit-log status, and one record per agent.
- Honest limit: a gateway key's liveness cannot be checked (no
  provider endpoint checks a gateway key), so it is reported
  "unknown" and the usage score comes from the audit log. The policy
  files are read with a focused extractor, not a YAML parser —
  Keyring Audit stays stdlib-only.

## v0.7.0 — 2026-11-15

Phase 4 complete: PR automation. The rotation flow (v0.6) plus this
release close out Phase 4.

- `fix --fingerprint <fp>` opens a pull request that replaces a
  hardcoded credential with an environment-variable reference — the
  vault reference. Python reads `os.environ` (adding `import os`
  when the file lacks it), JS/TS reads `process.env`, shell reads
  `"${VAR}"`, YAML reads `${VAR}` (`${{ secrets.VAR }}` inside
  `.github/workflows/`), and a `.env` line becomes a comment naming
  where the value lives. For AWS both the key id and the secret are
  replaced. 145 tests.
- A dry run first, always: without `--approve` it prints the diff
  (secret redacted) and the PR title and body, and changes nothing.
  With `--approve` it creates the branch
  `keyring-audit/fix-<fp8>`, commits via the GitHub API, and opens the
  PR. The token comes from `GITHUB_TOKEN` or a prompt, used once.
- Anything it cannot fix safely — a value inside a longer string, a
  JSON file, an unknown extension — is a manual step in the PR body,
  not a guess. A value that lives only in history is refused outright
  (a PR cannot fix history). The fixed files are verified to hold no
  occurrence of the old value before anything is committed.

## v0.6.0 — 2026-11-15

Phase 4: safe remediation — the rotation flow. The PR automation
(replacing a hardcoded key with a vault reference) is the remaining
Phase 4 piece and is not built yet.

- `rotate --fingerprint <fp>` prints the remediation plan and changes
  nothing — a dry run first, every time. A credential used in the last
  24 hours is flagged "ROTATE WITH CARE", with CloudTrail named as the
  place to check recent callers. 125 tests.
- `--execute --approve` performs the AWS two-key rollover: create a
  new access key, verify it answers sts:GetCallerIdentity, print the
  new secret once (never stored), old key untouched. `--complete`
  deletes the old key with the new key's credentials and confirms it
  is gone from the user's key list. Both refuse non-AWS providers,
  dead keys, and assumed-role principals, and say why.
- `--verify` re-checks the old credential afterwards: dead means the
  rotation worked. For AWS with `--rotated-at`, any last-used time
  after the rotation is flagged — something still holds the old key.
- The old secret is read from the terminal (hidden) and used once, in
  memory. The new secret is shown once and never written to a file.

## v0.5.0 — 2026-11-15

Phase 3: ownership. Every finding now names who is responsible for the
credential — or says plainly that no owner could be found.

- Owner sources, in order: AWS Owner/Team tags (read during the
  validity check, while the secret is available), the commit author,
  then `git blame` for working-tree and staged lines. An uncommitted
  line names the local git user; a file git cannot blame at all falls
  back to the local user too. 102 tests.
- "No owner" is a risk factor in the score, not a missing field: the
  score is now five components — privilege 40, exposure 20, age 15,
  usage 15, ownership 10. Exposure was rebalanced from 30 to 20 to
  make room (history 25→17, working tree 10→7); privilege, age and
  usage are unchanged, and the canonical admin-PAT-in-history finding
  still scores 80 / Critical.
- The report shows an `owner:` line on every finding (with the source:
  aws-tag, commit, or blame) and the ownership component in the risk
  breakdown.

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
