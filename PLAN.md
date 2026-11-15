# Keyring Audit — Full Plan v1.0

**Working name:** Keyring Audit (open to change)
**Status:** plan v1.0, written 2026-11-15. Verified against primary and
secondary sources on 2026-11-15 (see §9). No code yet.
**Author's note:** this plan corrects the pasted idea in two places the
verification forced. First, the competitor list is stale: Astrix, Oasis
and Entro were all acquired in 2026, and CyberArk is now Idira inside
Palo Alto Networks — the independent pure-plays are mostly gone, which
strengthens the open-source wedge rather than weakening it. Second,
"scanners don't show what a secret can do" is only half true:
TruffleHog already verifies liveness on 700+ detectors. The gap is
narrower and sharper: nobody open-source maps a live credential to its
permissions, its usage, and a safe rotation in one tool. That is the
wedge. Everything below is written from the verified facts, not the
pasted draft.

---

## 1. Vision and positioning

**One sentence:** Keyring Audit answers "what credentials exist, who owns
them, what can each one reach, and which ones can I safely kill or rotate
today?" — for teams too small to buy an enterprise NHI platform.

**The wedge, stated sharply:** a free, open-source CLI + GitHub App that
scans repos and history for secrets, proves which ones are still live,
lists what each live one can actually do, ranks them by risk, and guides
a safe rotation — starting with GitHub and AWS, the two places small
teams actually keep secrets.

**What it is not:** not another regex scanner (Gitleaks and TruffleHog
already exist and are good at that part); not a vault (Vault, Doppler,
Infisical, 1Password already store secrets well); not an enterprise NHI
platform (that is a sales motion, not a one-person build). It is the
layer between detection and remediation that nobody open-source owns:
**blast radius + safe rotation**.

**The Agent Gateway tie-in (the strategic reason to build this):**
Agent Gateway controls what AI agents may do. Every agent it governs
holds credentials — API keys, tokens, service-account keys — and those
credentials are non-human identities. Keyring Audit discovers and scores
them; Agent Gateway enforces policy on them. Phase 5 (agent identities)
is where the two products meet, and it is the strongest differentiator
in the whole plan: no other open-source scanner has a policy-enforcement
sibling.

---

## 2. Verified research

### 2.1 The scale of the problem (all verified 2026-11-15)

- **Machine identities outnumber humans and the ratio is accelerating.**
  CyberArk's 2025 Identity Security Landscape (2,600 security
  decision-makers, 20 countries): **82 machine identities per human**.
  Palo Alto Networks' 2026 Identity Security Landscape: **109:1**, up
  from 82:1 a year earlier — and **~79 of every 109 are AI agents**.
  Entro's telemetry: **144:1 in cloud-native environments** (H1 2025,
  up from 92:1). CyberArk 2024: 45:1. The trend, not any single number,
  is the story: the ratio roughly doubled in two years, and AI agents
  are now the majority of the machine population.
- **Governance has not kept up.** 88% of organisations still define
  only human users as "privileged" (CyberArk 2025). 42% of machine
  identities have access to sensitive data. IAM teams own, on average,
  only 44% of their organisation's machine identities (Gartner survey).
  69% of organisations still authenticate machine identities with
  long-lived API keys (2026 State of AI Agent Identity Security Report).
- **The breach vector is already here.** Gartner projects that by 2028,
  **25% of enterprise breaches will be traced to the compromise or abuse
  of AI agent identities**. The 2025 Verizon DBIR identified credential
  abuse as the top initial-access vector, with machine credentials
  prominent in cloud-targeted attacks.
- **Secrets keep leaking, and leaked secrets stay live.** GitGuardian's
  State of Secrets Sprawl 2026 (17 Mar 2026): **28.65 million new
  hardcoded secrets in public GitHub commits during 2025, +34% year over
  year** (2024: 23.8 million). **64% of credentials confirmed valid in
  2022 were still valid when retested in January 2026.** Truffle
  Security found **543,000+ active credentials exposed in public code**
  that still granted production access.

### 2.2 Competitors — and the 2026 consolidation wave

The pasted idea listed the right names but the wrong ownership. Between
May and September 2026 the NHI pure-plays were bought up:

| Vendor | What it does | Status (verified 15 Nov 2026) |
|---|---|---|
| **CyberArk** | PAM + secrets (Conjur) + machine identity (Venafi) + CIEM | **Acquired by Palo Alto Networks, ~$25B, closed 11 Feb 2026; rebranded Idira 12 May 2026.** Open-source Conjur has stopped receiving regular updates. |
| **Astrix Security** | NHI discovery, governance, AI-agent security | **Acquired by Cisco, ~$400M reported, announced 4 May 2026.** New-license sales as a separate entity ended. |
| **Oasis Security** | NHI lifecycle management | **Acquired by Cyera, ~$1B (~$700M cash + shares), announced 28 Jul 2026, completed 3 Sep 2026.** Now Cyera Identity. |
| **Entro Security** | NHI + secrets security | **Acquired by SailPoint, ~$200M reported, announced 15 Jun 2026, closed 29 Jun 2026.** Powers SailPoint's Agentic Fabric. |
| **Okta / Permiso** | Identity platform / NHI posture | Okta acquired Permiso (2026). |
| **HashiCorp Vault** | Secrets management | **Part of IBM since 2024.** |
| **Token Security** | Machine-first NHI security | Independent (founded 2023). |
| **Aembit** | Workload IAM, secretless access | Independent. $25M Series A (Acrew, Okta Ventures, CrowdStrike Falcon Fund). Publishes on MCP + OAuth 2.1 for AI authorisation. |
| **Clutch Security** | NHI security | Independent. |
| **Hush Security / Act Security** | Agent access governance | Raised ~$90M combined on 28 Jul 2026 (Hush $30M Series A). |

**What this means for the wedge:** the three best-known NHI pure-plays
are now features inside platform vendors. A small team cannot buy
"just" NHI governance anymore — it comes bundled with a platform
contract and enterprise pricing. The open, developer-friendly, buy-only-
what-you-need slot is empty. That is the opening.

### 2.3 The open-source floor (what already exists, and its gaps)

| Tool | What it does | Gap Keyring Audit exploits |
|---|---|---|
| **Gitleaks** (MIT, Go, ~30.9k stars, v8.30.1 Mar 2026) | Regex + entropy scan of repos/history, 222 rules, pre-commit/CI | **No validity checking** — a human triages every finding. Author declared it feature-complete; the maintainer is now Truffle Security. |
| **Betterleaks** (MIT, Aikido-backed, v1.8.1 Aug 2026) | Gitleaks author's rebuild, adds live-key validation | New; validation only, no blast radius, no rotation. |
| **TruffleHog** (AGPL-3.0, ~28k stars, v3.97.9 Sep 2026) | 800+ detectors, **700+ live-verifying**, history/S3/GCS/Docker/Postman/Jenkins scans, `--results=verified` | Verifies liveness but **does not map permissions, usage, or ownership**, and does not guide rotation. Enterprise platform by quote. |
| **GitGuardian ggshield** (MIT CLI + SaaS platform) | 550+ detectors, ML generic detection, honeytokens, NHI governance, remediation playbooks | NHI governance and honeytokens are paid platform features. Free Starter ≤25 devs; Growth/Enterprise by quote. |
| **GitHub secret scanning + push protection** | Native detection of known token formats, blocks pushes | The free floor. Detects, does not assess blast radius or rotate. |

**The honest gap, stated precisely:** validity checking is solved
(TruffleHog does it well). Permissions mapping, usage analysis,
ownership, and safe rotation — in one open tool, for small teams — is
not. That is the product.

### 2.4 The technical wedge, verified

**GitHub — classic PATs are fully enumerable; fine-grained PATs are not.**
A classic PAT (`ghp_`) reports its scopes in the `X-OAuth-Scopes`
response header on any authenticated call (e.g. `GET /user`), and the
endpoint names what it needs in `X-Accepted-OAuth-Scopes`. One call
gives validity (200 vs 401) and the full scope list — the blast radius
in one header. A fine-grained PAT (`github_pat_`) returns **no**
`X-OAuth-Scopes` header at all: permissions are per-repository and must
be probed endpoint by endpoint (404 = not permitted; a 403 carries
`x-accepted-github-permissions` naming the permission the endpoint
wanted). GitHub App tokens (`ghs_`) behave the same way. **Design
consequence:** the GitHub connector reports scopes directly for classic
PATs and OAuth tokens, and probes a fixed endpoint set for fine-grained
and App tokens — and says which method it used, so a "no scopes found"
result is never misread as "no permissions".

**AWS — validity is one call; permissions need IAM read or simulation.**
`sts get-caller-identity` returns the account, ARN and user ID: the
validity check. Permissions come from `iam list-attached-user-policies`
/ `list-user-policies` / `get-policy` (needs IAM read, which is often
denied to the key itself) or from `iam simulate-principal-policy`
against named actions (the simulator does **not** read resource-based
policies, so an "allowed" result is partial evidence — the report must
say so). Last use comes from `iam get-access-key-last-used` per key, or
`generate-credential-report` for all users (needs IAM admin). The
read-only probing pattern (enumerate-iam style: fire read-only
`list_*`/`describe_*`/`get_*` calls and record which succeed) is the
fallback when IAM read is denied — and it is also the pattern an
attacker uses, which is why the safety contract (§4.5) matters.

**What "safe, read-only" means, concretely:** validity = one identity
call per credential. Permissions = IAM metadata reads and policy
simulation only — never a data read (no S3 GetObject, no secret fetch,
no repo content read beyond the scope header). Every check is logged
with the exact API call made, so the customer can audit what the tool
did with their credential.

---

## 3. The product

### 3.1 The question it answers

"What credentials exist, who owns them, what can each one reach, and
which ones can I safely kill or rotate today?"

### 3.2 The six capabilities (and what each one is, precisely)

1. **Discover.** Scan git repos and full history, CI/CD variables,
   cloud accounts, SaaS app integrations, and container images for
   credentials. Detection = provider-specific patterns (the `AKIA…`,
   `ghp_…`, `xoxb-…` shapes) plus entropy for generic secrets, with a
   false-positive filter. Never store a found secret: the scanner keeps
   a salted hash + the first/last 4 characters for identification, and
   the full value only in memory for the duration of the validity check.
2. **Identify.** Match each credential to its provider and check whether
   it is still valid, using the safe, read-only checks in §2.4. Result
   is one of: live, dead (401/revoked/expired), or unknown (could not
   check — network, permissions, or an unsupported provider).
3. **Map blast radius.** For each live credential, list what it can
   access: GitHub scopes (or probed permissions), AWS attached policies
   + simulated actions, and — where the provider allows it — the
   resources in scope. The output is a permission list, not a data
   sample: the tool never reads the data the credential protects.
4. **Assign owners.** Link each credential to a team or person using
   commit history (who committed the file, who owns the repo), cloud
   tags, and ticketing data. An unowned credential is itself a finding:
   "no owner" is a risk factor in the score, not a missing field.
5. **Rank risk.** Score 0–100 from four measured inputs: privilege
   (what the credential can do — admin/write-all scores highest),
   exposure (where it was found — public repo > private repo > CI
   variable > vault), age (time since creation, where known), and usage
   (last-used from provider logs; unused for 90+ days scores higher
   because it is both safe to kill and evidence of sprawl). Every
   component is shown, so the score is auditable, not a black box.
6. **Remediate.** Rotate or revoke through provider APIs, open a pull
   request that replaces a hardcoded key with a vault reference or a
   short-lived credential, and verify nothing broke using usage logs
   after the change. Every remediation is a dry run first, and risky
   changes require an approval (a human confirms, or a second credential
   holder approves — the same approval pattern Agent Gateway uses).
7. **Prevent.** Pre-commit and CI checks that block a new secret from
   landing, plus expiry policies and alerts for unused credentials.

### 3.3 The wedge MVP (Phase 1)

**"Which of our leaked or old keys are actually dangerous?"**
A CLI and a GitHub App that scan repos and history for secrets. For
GitHub and AWS first: check whether each key is live and list its
permissions. Output: a ranked list — "this active AWS key from 2022 has
admin access and was last used yesterday" — with a one-click revoke or
rotate guide. Nothing more in v0.1. The MVP is deliberately small: the
value is the ranking, not the detector count.

### 3.4 Delivery

CLI first (the developer's tool), then the GitHub App (continuous
scanning on every push), then a web dashboard (ownership and risk
views). The CLI is the product's trust anchor: it runs locally, the
customer sees exactly what it does, and it never phones home with a
secret.

---

## 4. Technical design

### 4.1 Scanners

Python first (the team's language; the same stack as Kavach, Crypto
Atlas and Recovery Proof — stdlib + a small set of deps, pytest, GitHub
Actions CI). Go is the alternative if scan speed becomes the bottleneck
(Gitleaks and TruffleHog are both Go, and both scan a repo in seconds);
the plan defaults to Python for v0.1 and revisits at Phase 5 if the
profiler says so. Detection: provider-specific regexes + entropy
(Shannon, thresholded per detector, with an allowlist file) — the same
shape as Gitleaks' 222 rules, but starting with ~30 detectors for the
providers in scope (GitHub, AWS, Slack, GitLab, GCP, Azure) and growing
from real findings, not from a copied rule list.

### 4.2 Provider connectors

| Provider | Validity check | Permissions check | Rotation |
|---|---|---|---|
| GitHub (classic PAT) | `GET /user` (200 vs 401) | `X-OAuth-Scopes` header | Revoke via API; new fine-grained PAT via the web UI (API cannot create PATs — the guide says so) |
| GitHub (fine-grained / App) | `GET /user` | Endpoint probing (fixed set) + `x-accepted-github-permissions` | Same as above |
| AWS (IAM user key) | `sts get-caller-identity` | `list-attached-user-policies` + `simulate-principal-policy`; `get-access-key-last-used` for usage | `create-access-key` + `delete-access-key` (two-key rollover: create new, verify, delete old) |
| Slack | `auth.test` | Scopes from the token response | Revoke via API |
| GitLab | `GET /user` | Scopes from the token (API returns them) | Revoke via API |
| GCP / Azure | Token introspection / `az account show` | IAM policy reads | Service-account key rotation via API |

Each connector is a small module with the same interface:
`detect(value) -> bool`, `validate(value) -> live|dead|unknown`,
`permissions(value) -> list`, `rotate(value) -> guide|action`,
`revoke(value) -> action`. A connector that cannot validate honestly
returns `unknown`, never a guessed `live` or `dead`.

### 4.3 Graph store

Identities, credentials and resources as a graph, so the product can
answer "what can this reach?" in one query: a credential → its identity
(user/service account) → its permissions → the resources those
permissions touch. v0.1 stores it as JSON (one file per scan, the same
shape as the other tools' reports); the dashboard phase moves it to
SQLite, and only moves to a real graph database if a customer needs it.
No graph database in the MVP.

### 4.4 Usage analysis

Cloud and audit logs to find unused credentials and safe rotation
windows. AWS: `get-access-key-last-used` + CloudTrail (last event per
key). GitHub: audit log (last use of a PAT, org-level). A credential
unused for 90 days is a "safe to kill" candidate; a credential used in
the last 24 hours is a "rotate with care" candidate, and the rotation
guide says which services called it (from the logs) so the owner knows
what to update.

### 4.5 The safety contract (non-negotiable)

1. **Never store a secret.** The scanner keeps a salted hash + the
   first/last 4 characters. The full value exists only in memory during
   the validity check, and is wiped after. No secret ever touches disk,
   a log, a report file, or a network call except the provider's own
   validity endpoint.
2. **Read-only checks, minimal scope.** Validity = one identity call.
   Permissions = metadata reads and policy simulation only. No data
   reads, ever. Every check is logged with the exact API call.
3. **Only scan what the customer authorised.** The CLI scans the repos
   and accounts the user points it at. The GitHub App scans only the
   repos it is installed on. Testing a credential you do not own is
   unauthorised access in most jurisdictions — the tool refuses to
   validate a credential it was not given by its owner, and the README
   says so in plain language.
4. **Dry runs and approvals.** Every remediation runs as a dry run
   first. Revoking or rotating a credential that was used in the last
   24 hours requires an explicit approval. Rotation is a two-key
   rollover (create new → verify → delete old), never a delete-first.
5. **Verify nothing broke.** After a rotation, the tool re-checks usage
   logs for the old credential (any call after rotation = something
   still holds the old key) and reports it.

### 4.6 Reuse from the existing estate

- **Kavach** (web scanner): the CLI shape, the A–F-style grading
  language, the `--format text|json` output contract, the
  never-store-secrets discipline.
- **Crypto Atlas** (scanner + CBOM): the detector/scoring pattern
  (finding → weakness × exposure → ranked list), the report format.
- **Agent Gateway** (policy + audit log): the approval flow for risky
  actions, the hash-chained audit log (every remediation recorded),
  the per-agent identity model that Phase 5 extends.
- **Recovery Proof** (verify, don't trust): the "prove it, don't claim
  it" posture — a credential is `live` only when the provider said so,
  and `unknown` when the check could not run.

---

## 5. Roadmap

| Phase | Weeks | Deliverable |
|---|---|---|
| 0. Research | 1–2 | Interview 8–10 platform/security engineers about how they track keys today. (Do this before writing the scanner — the interviews decide which providers matter and what "owner" means in practice.) |
| 1. Repo scanner | 3–5 | CLI: secrets in code + full git history, validity checks for GitHub + AWS, ranked output. The wedge MVP. |
| 2. Blast radius | 6–8 | Permissions listing per live credential (GitHub scopes / probed permissions; AWS policies + simulation). |
| 3. Ownership + ranking | 9–11 | Owner mapping (commit history, cloud tags) and the 0–100 risk score with auditable components. |
| 4. Safe remediation | 12–16 | Guided rotation (two-key rollover), revoke, PRs that replace hardcoded keys with vault/short-lived credentials, post-rotation usage verification. Dry runs + approvals throughout. |
| 5. Agent identities | 17–20 | **Pulled forward from Phase 6.** Discovery and control for AI agent credentials, built on Agent Gateway's per-agent identity model: every agent key is a Keyring Audit credential, every Agent Gateway policy decision is logged against it. The two products share the identity graph. |
| 6. Coverage | 21–26 | CI/CD variables, SaaS integrations, cloud accounts (GCP, Azure), container images, Slack/GitLab connectors. |

**Why Phase 5 moved up:** the 2026 landscape says ~79 of every 109
machine identities are AI agents, and Gartner projects 25% of breaches
by 2028 trace to agent identity. The agent-identity piece is the
fastest-growing part of the problem and the one no competitor owns in
open source — and it is the piece only this estate can build, because
Agent Gateway already exists. Waiting until week 23 to start it would
waste the advantage.

---

## 6. Business model

- **Open-source scanner** for adoption and trust (MIT or Apache-2.0 —
  see §8). The CLI and the GitHub App's scanning core are open; the
  dashboard, continuous discovery, automated rotation with approvals,
  and compliance reports are the paid platform.
- **Pricing:** per credential managed or per connected account, aimed at
  startups and mid-size companies — the teams the enterprise platforms
  price out. (No number in this plan: pricing is set after Phase 0
  interviews, not before.)
- **Buyers:** platform, DevOps and security teams — often after an
  incident or an audit, when "how many keys do we have?" suddenly has
  a deadline.
- **Why open source wins here:** a tool that handles credentials must
  be inspectable. A closed scanner asking for your keys is a trust
  problem; an open one the customer can read is a trust answer. This
  is also the moat: the enterprise vendors cannot open-source their
  platforms without giving away the product.

---

## 7. Honest risks

1. **Crowded and funded — and now consolidated.** The wedge must stay
   sharp: blast radius + safe rotation for small teams. "Another
   scanner" loses to TruffleHog (free, 800 detectors, verifies) and to
   GitHub's own push protection (free, on by default). The plan's
   answer is to compete on the ranking and the rotation, not the
   detector count.
2. **Handling credentials is itself risky.** One bug that logs a secret
   destroys the product's trust. Mitigation: the safety contract (§4.5)
   is enforced by tests (a test that greps every output file for a
   known test secret, run in CI), and the scanner never holds a secret
   longer than one validity check.
3. **Rotation can break production.** Mitigation: usage-first
   (never rotate a credential without knowing who called it last),
   dry runs, two-key rollover, approvals for recently-used credentials,
   post-rotation verification.
4. **Integration breadth.** Every provider API is work, and every one
   has its own quirks (fine-grained GitHub tokens are the example in
   §2.4). Mitigation: two providers done excellently (GitHub + AWS)
   before a third is started.
5. **Legal care.** Testing credentials you do not own can raise legal
   issues. Mitigation: scope every scan to authorised accounts and
   repos, document the read-only contract, and refuse to validate a
   credential the user did not supply as their own.
6. **The maintenance trap.** Gitleaks' author called it feature-complete
   and moved on; the open-source scanner space has a maintenance gap
   for a reason — it is unglamorous work. Mitigation: the paid platform
   funds the open scanner, and the scanner stays small (detectors grow
   from real findings, not from chasing a count).
7. **The consolidation risk, inverted.** The acquirers (Cisco, Cyera,
   SailPoint, Palo Alto) now own the NHI story for enterprises. If one
   of them ships a free developer tier, the wedge narrows. Mitigation:
   ship the CLI first and fast — the open tool in developers' hands is
   the position, not the feature list.

---

## 8. Open decisions (Samir's call)

1. **Name.** "Keyring Audit" is the working name. Alternatives: the
   plan has no strong second candidate — his call, or keep it.
2. **Language for the scanner.** Python (default — the estate's stack,
   fastest to build) or Go (the scanner community's language, faster
   scans, a single static binary)? Python for v0.1, revisit at Phase 5
   if the profiler says so — unless he wants Go from day one.
3. **Licence.** MIT (most permissive, most adoptable) or AGPL-3.0
   (TruffleHog's choice — forces hosted competitors to contribute
   back)? MIT is the default; AGPL is the defensive pick.
4. **Phase 0 interviews vs build-first.** The plan says interview 8–10
   engineers first (the pasted draft's Phase 0). Build-first is the
   alternative — the wedge MVP is small enough to build in a week, and
   the interviews can run in parallel with Phase 1. His call.
5. **Repo creation.** New repo `Samir-Khadka/keyring-audit` at Phase 1,
   or keep the plan in this directory until the first build? The other
   projects all got their repo at build time.
6. **Agent Gateway integration depth (Phase 5).** Shared identity graph
   only, or a single combined install (Keyring Audit as the discovery
   half of Agent Gateway)? The plan assumes a shared graph and separate
   repos; a merge is a bigger decision for later.
7. **CYBERSURE relevance.** Non-human identity is a Year-2 track
   (cryptography) adjacent, not central — the plan does not claim it as
   CYBERSURE evidence. If he wants a CYBERSURE angle, the agent-identity
   work (Phase 5) is the closest fit.

## 9. Verification log

All verified 2026-11-15 by systematic web search + official-page reads.

- **NHI ratios:** CyberArk 2025 Identity Security Landscape (82:1,
  2,600 decision-makers, 20 countries); Palo Alto Networks 2026
  Identity Security Landscape (109:1, ~79/109 AI agents); Entro
  telemetry (144:1 cloud-native, H1 2025); CyberArk 2024 (45:1).
  Governance gaps: 88% define only humans as privileged; 42% of
  machine identities touch sensitive data; IAM teams own 44% of machine
  identities (Gartner survey); 69% still use long-lived API keys (2026
  State of AI Agent Identity Security Report). Gartner: 25% of breaches
  by 2028 trace to AI agent identity.
- **Secrets sprawl:** GitGuardian State of Secrets Sprawl 2026
  (17 Mar 2026): 28.65M new hardcoded secrets in public GitHub in 2025
  (+34% YoY); 64% of credentials valid in 2022 still valid Jan 2026.
  2024: 23.8M. Truffle Security: 543,000+ active credentials exposed
  in public code.
- **M&A wave:** CyberArk → Palo Alto ~$25B, closed 11 Feb 2026,
  rebranded Idira 12 May 2026; Astrix → Cisco ~$400M reported,
  announced 4 May 2026; Oasis → Cyera ~$1B, announced 28 Jul 2026,
  completed 3 Sep 2026; Entro → SailPoint ~$200M reported, announced
  15 Jun 2026, closed 29 Jun 2026; Okta acquired Permiso; HashiCorp →
  IBM 2024; Hush ($30M Series A) + Act Security ~$90M combined
  28 Jul 2026. Independents left: Token Security, Aembit, Clutch.
- **Scanners:** Gitleaks MIT, ~30.9k stars, v8.30.1 (21 Mar 2026),
  222 rules, no validity checking, author moved to Betterleaks
  (Aikido-backed, MIT, v1.8.1 Aug 2026, live-key validation);
  TruffleHog AGPL-3.0, ~28k stars, v3.97.9 (24 Sep 2026), 800+
  detectors, 700+ live-verifying, `--results=verified`; GitGuardian
  550+ detectors, ML generic detection, honeytokens, NHI governance,
  free Starter ≤25 devs; GitHub secret scanning + push protection as
  the free floor.
- **GitHub validity:** classic PAT scopes via `X-OAuth-Scopes` header
  (docs.github.com, OAuth scopes); fine-grained PATs return no scope
  header — permissions probed per endpoint, `x-accepted-github-
  permissions` on 403 (github-mcp-server scope-filtering docs and
  community write-ups, Nov 2026).
- **AWS validity:** `sts get-caller-identity` (validity);
  `iam list-attached-user-policies` / `list-user-policies` /
  `simulate-principal-policy` (permissions; simulator does not read
  resource policies); `iam get-access-key-last-used` /
  `generate-credential-report` (usage/age).
- **Not verified / do not cite:** the "39 million API keys" GitHub-leak
  figure (secondary only, no primary source found); the "97% of granted
  cloud access is never used" figure (secondary, unattributed);
  per-credential pricing of any named competitor (all by quote).
