# Changelog

All notable changes to this repository. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries record **what actually changed and was checked**. A step is listed as verified only when its
acceptance checks ran and passed. Blocked and unsupported work is stated as plainly as completed
work, because a reader cannot otherwise tell the difference.

`0.1.0` is the planned first release version (`first_release_version` in `01-owner-decisions.md`).
Nothing is released. The package is `private` and `UNLICENSED` because the licence decision is
still `TODO`.

## [Unreleased]

### Batch S — standards at requirement level (10 October 2026)

The remediation plan's standards batch. Every mapped standard now has a requirement-level mapping
(518 entries across eight files), a generated coverage matrix, and — in every audit report — a
per-application statement of which requirements the composed profiles could actually check.
Checkpoint: `docs/checkpoints/batch-s.md`.

**The data model (S1).** `standard-mapping` schema + `controls/mappings/*.yaml` + generated
`controls/coverage/*.md`. The old rule stands and is now tested both ways: nothing is
`verified_coverage` until an application is assessed, and every `gap`/`not_applicable` carries a
reason.

**ASVS 5.0.0 — all 345 requirements mapped.** The official CSV is vendored (SHA-256 recorded;
CC BY-SA licence notice with the review-before-distribution note), every ID/level/chapter is
checked against it by test, and no summary reproduces the standard's phrasing — enforced by test
against the official text. L1 (70): 12 automated, 20 manual, 38 recorded gaps. The areas the plan
predicted (V7 sessions, V10 OAuth, V3/V5/V11/V14/V15) each have named controls or recorded
reasons.

**AUTH-03 (RFC 9700) at catalogue v3.** OAuth/OIDC flow security: the implicit grant is now a
wired static finding (`hardening.oauth-implicit-grant`, fixture detected, clean twin silent),
and PKCE/state/nonce/redirect handling ride a declared manual recipe. Never exceptable.

**Six new static rules** in the reviewed pack: SSRF (API7), unvalidated external-response
consumption (API10), implicit grant, and the Electron trio (nodeIntegration, contextIsolation,
sandbox) — each with vulnerable/fixed fixtures and the real pinned binary verifying both sides.
The SSRF fixture deliberately includes the indirect-routing shape the rule misses, so the
limitation is recorded in evidence rather than prose.

**Top 10 2025, corrected against the source.** Names fetched from the published edition and
pinned by test — which caught this repository's own Batch Q error (A10 is Mishandling of
Exceptional Conditions, not integrity failures) and moved the chapter-level mappings to the
2025 letters. API1–API10 mapped; WSTG citations or recorded no-WSTG reasons on every test
recipe; SSDF's 42 active tasks mapped from the official PDF (5 v1.1 consolidations recorded);
OSPS's 64 active requirements mapped (the plan's 67 was an estimate) with Level 1 applied to
SecHard itself — met, owner-blocked (licence, visibility, contacts: recorded decisions), or
release-pending, stated per item in the checkpoint. MVSP (25, CC0), ASD SBD (current 6-foundation
edition), MCP Top 10 link-only as its licence demands.

**Approvals invalidated, deliberately:** WSTG citations edited fourteen v1 definitions, and
AUTH-03 is new — 20 of 35 approvals still resolve, the catalogue test pins the full unresolved
list, and Batch D re-approves the sheet.

**Staged with reasons, not skipped:** S3 (agent-guidance curation — the three sources are
already licence-recorded; regenerating agent instructions deserves its own reviewed pass), the
SLSA release row (no release exists; Batch D), the astoj comparison project (the plan names it
without a URL; a guessed repository would be a fabricated source).

Suite at this point: **535 unit + 8 integration + 31 scanner + 5 example tests**, all passing on
Node 24.21.0.

### Batch Q — the quality section: "engineered, not vibe-coded" (10 October 2026)

The remediation plan's quality batch. Every audit now carries a quality section reported
separately from security — neither can change the other's verdict — and the quality findings are
measured, calibrated instruments, not vibes. Checkpoint: `docs/checkpoints/batch-q.md`.

**The catalogue grew up (gap D3).** Catalogue **version 2**: the 35 v1 IDs are unchanged and their
approvals still resolve; QUAL-02…QUAL-13 are added as `draft` definitions with a `migration` note
that names exactly what changed, enforced by the schema and by a test — a catalogue whose ID set
changes without a migration note is now a test failure, not a silent release change. Release
evaluation blocks on the twelve new controls until the owner approves them, the same rule as every
other control.

**Six quality recipes wired** (Q1/Q4), each producing real findings through the compiled CLI:

- `quality/error-handling` — the reviewed opengrep pack `quality-errors.yaml`: empty catch blocks,
  `.then()` chains with no `.catch()`, and `console.log` in production source directories (scoped
  by tested recipe code — semgrep `paths` filters proved unreliable and the pack says so).
- `quality/vibe-tells` — the SecHard-owned analyser: narration comments (with the rationale/
  narration distinction as its central, calibrated design decision), step narration, marketing
  adjectives, banners, emoji, placeholder comments and values, hardcoded local URLs, debugger
  statements, commented-out code, comment dominance. Every finding is a **signal with an
  explanation, never proof of authorship**; the plan's "deliberately" tell is judged by absence of
  reasoning, not the word alone.
- `quality/test-quality` — focused, skipped, tautological, and assertion-free tests.
- `quality/strict-correctness` — type-suppression markers and `any`/JSDoc-`{any}` escapes, with
  per-file and project thresholds; `@ts-expect-error` **with** a reason counts but does not flag.
- `quality/repo-hygiene` — lockfile, `.gitignore` (dependencies and `.env`), README, CHANGELOG,
  CI, licence (whose deliberate absence is a recorded decision the finding acknowledges).
- `quality/dependency-health` — duplicate libraries for one job, from a reviewed equivalent-roles
  map in the thresholds policy.

Thresholds live in the reviewed `policy/quality-thresholds.yaml` (validated by a new schema); a
consumer configuration can never widen them.

**Measured, not promised (Q6).** `tests/corpus/` holds a deliberately vibe-coded fixture with
**18 seeded issues** and a clean twin. Calibration on it: **recall 1.0, precision 1.0 (20 findings,
all matched to seeds), clean twin 0 findings** — floors (0.8/0.6/0) cleared and the measured
numbers printed by the test. The opengrep pack is verified the same way with the real pinned
binary in the scanners suite.

**SecHard passes its own quality audit** — and getting there was the calibration working: the
first self-audit reported **48 findings**, and each was judged honestly. That process found a
real defect (a literal `.skip` inside the change-report test's detection fixture — now composed at
runtime, the repository's established technique), fixed five false-positive classes in the rules
(CSS hex colours read as comments, wrapped prose read as narration, Playwright destructuring read
as assertion-free tests, the analyser's own pattern text read as findings, mention-vs-use for
localhost), and ended at **one accepted LOW finding**: the deliberately absent licence, a recorded
owner decision. Zero high or critical, pinned by `tests/quality/self-audit.test.ts`.

**The reference app's M8 defects are fixed (gap A2), verified live:** `updateNote` no longer drops
the body field, every note write inspects and surfaces its error instead of discarding it,
`X-Powered-By` is off, and CSP + COOP + CORP headers ship — confirmed with `curl` against the
running production build (X-Powered-By absent, all seven headers present).

**Toolchain defects found while wiring the pack, recorded:**

1. The pinned **opengrep reads local rule packs with a locale-dependent codec** and crashes on
   non-ASCII content under the minimal recipe environment (`'ascii' codec can't decode…` in
   `config_resolver.py`). The security pack was pure ASCII by luck; reviewed rule packs are now
   ASCII-only by rule, and the pack header records why.
2. Semgrep-style tools **prefix a local config path onto every rule id**; the adapter now
   normalises to the reviewed pack namespace (the earlier suffix-tolerant tests anticipated the
   mangling).

**Staged, recorded rather than implied:** jscpd (duplication), Lizard (complexity), Knip/Vulture
(dead code), dependency-cruiser (module structure), formatters, axe-core/Lighthouse (frontend), and
QUAL-01's own-scripts recipes (executing application code needs the isolation model, gap D1) all
report `unsupported` with the tool's name as the reason. Q5 (advisory AI review) awaits the owner's
opt-in; registry-based dependency health (deprecation, major drift) and the external calibration
targets are staged work.

Suite at this point: **522 unit + 8 integration + 31 scanner + 5 example tests**, all passing on
Node 24.21.0.

### Batch U — `hardening audit`: point it at any folder and get a report (9 October 2026)

The remediation plan's audit-mode batch (renamed U by the gap analysis, D11). `hardening audit PATH`
runs with no manifest, no setup, and no modification of the audited project: it detects the stack
and features from recorded evidence, composes the profile set, generates an ephemeral manifest
outside the target, and drives the existing plan/check/gate machinery. Checkpoint:
`docs/checkpoints/batch-u.md`; contract: `docs/audit-mode.md`.

**The command — A1 plus gap items D1, D2, D6, D8, D9**

- `hardening audit PATH [--url ORIGIN] [--out DIR] [--depth quick|standard|deep] [--allow-local]`;
  `--policy` defaults to the shipped policy root. Output goes to `--out` (default
  `sechard-audit-<timestamp>/` in the working directory), which **must live outside the target** —
  refused otherwise. The acceptance test checksums the target tree before and after each audit and
  requires byte-identical results: audit mode never writes to the audited project (D9).
- **No recipe executes application code** (D1): every wired recipe reads files or makes bounded
  requests to an operator-approved target. `quick` is the fast static set; `standard` adds the
  git-history scan, client-bundle inspection, and live checks; `deep` states in the report that it
  adds nothing in this build because deeper work needs an isolation model that does not exist yet —
  it is refused, not faked (D8, each level's behaviour tested).
- **The `--url` guard (D6)** refuses loopback, link-local (cloud metadata), RFC1918, unique-local,
  and mapped-IPv6 targets, credential URLs, non-HTTP(S) schemes, and deep paths — resolving the
  hostname and checking every resolved address, which is recorded in the report. `--allow-local`
  is the explicit local-development opt-in. The generated target inventory is validated by the
  recipe's own loader before anything runs.
- **The Git-URL claim is dropped rather than faked (D2)**: audit takes a local folder; the trust
  rules for cloning untrusted repositories are recorded as not built. Clone it yourself, then
  audit.

**Detection and profiles — A2, A4**

- Detection (`src/audit/detect.ts`) is a bounded, read-only walk with per-detection evidence
  (file + pattern). Stacks: Next.js, Vite/React SPA, SvelteKit, Node API, Python web, Go, Expo,
  React Native, Flutter, Electron, unknown. Features: payments, runtime AI, uploads, webhooks,
  persistent storage, accounts, outbound requests. Undetectable features stay `unknown`, never
  `disabled`. Unsupported stacks produce a gap banner in the report while the generic checks
  (secrets, dependency advisories, workflows) still run — an Expo fixture proves the banner, not a
  clean report.
- Six composable profiles (`nextjs`, `react-spa`, `node-api`, `python-web`, `supabase`,
  `payments`), all `draft`, loaded from `profiles/` by directory so a shipped-but-unloaded profile
  cannot exist. Audit mode composes them from detection; gate mode keeps explicit selection.
  `nextjs-supabase` is kept (not replaced) so the example's records keep resolving. The `quality`
  profile waits for Batch Q's controls; firebase/uploads/runtime-ai/multi-tenant have no controls
  or recipes to select yet, so detection states them as gaps instead.

**The report — A3 plus gap item D5**

- `report.md`, a self-contained `report.html`, `report.json`, and schema-valid `report.sarif`, all
  from one evaluation. Two scores with plain verdicts (quality honestly "not assessed in this
  build" — Batch Q), "Fix these first" ordered by severity × deployed-surface exposure, and a
  "What we could not check" box that lists every unsupported, errored, and depth-excluded check
  with its reason.
- Every finding carries: what it is, where, why it matters in plain English, how to fix it, effort
  (S/M/L), confidence (confirmed/likely/signal — a heuristic is never presented as proof), control
  and standards references, and a ready-to-paste prompt for the owner's AI assistant. Untrusted
  text is redacted and structurally escaped in Markdown and HTML.
- `report.sarif` validates against the vendored OASIS SARIF 2.1.0 schema (provenance and the
  OASIS-licence review note in `upstream/sources.yaml`), carries no snippets, and emits only
  relative or remote artifact URIs (D5).

**Defects found and fixed in this batch**

1. **The control matrix classified every all-`mixed` control as `manual_only`** — contradicting
   that word's own definition ("a scan result can never satisfy these") after Batch W introduced
   `required_coverage`. Eight controls were listed wrong; Batch W had also edited SEC-01 to v2
   without regenerating the matrix, hiding the drift. The classifier is fixed, a regression test
   pins SEC-01 as `mixed`, and the matrix and review sheet are regenerated.
2. **The live HTTP adapter misread an unverified TLS connection as a generic unreachable route**:
   Node's fetch nests the socket error in `error.cause`, and the adapter read only the outer
   "fetch failed" message. Found by the audit live-target acceptance test; fixed with a
   cause-chain regression test.
3. A test-harness defect is recorded for the same reason code defects are: the first live
   acceptance test hosted its HTTPS server in the vitest process while the CLI helper blocked that
   event loop, producing a timeout that looked like an unreachable route. The server now runs as an
   independent child process.

**Not in this batch, recorded rather than implied:** local-folder only (Git-URL audit not built);
`deep` equals `standard` pending the isolation model; Python static analysis not run (the rule
pack is JS/TS only); the audit live path is proven against `--allow-local` https targets, not a
real deployed origin; the authorization, functional, dependency-policy, agent, and release
recipes remain unwired; TLS remains `unsupported` (Batch X); LAN binding and AUTH-02 recovery/
session remain unowned; the SARIF schema's OASIS licence needs review before any distribution.

Suite at this point: **510 unit + 8 integration + 27 scanner + 5 example tests**, all passing on
Node 24.21.0.

### Batch W — the scanners are wired into `hardening check` (9 October 2026)

The 2026-10-08 audit's C1: `hardening check` ran no scanners, so 32 of 33 checks came back
"not implemented" and no application could receive an analysis. Batch W connected the adapters to
the CLI, extended the client-secret markers (H5), and made pull requests evaluate against the base
branch's records (H4). Checkpoint: `docs/checkpoints/batch-w.md`.

**Recipes — C1**

- `src/execution/recipes.ts`: a recipe registry mapping recipe id → handler. Wired and verified
  against real targets: `gitleaks/repository`, `gitleaks/history`, `osv/lockfile`, `opengrep/rules`,
  `zizmor/workflows`, `build/client-assets`, and `web/http-requirements` (the live HTTP checks,
  folded in from `tools/run-live-checks.mjs`). A recipe not in the registry still reports
  `unsupported` with its reason; a recipe that does not apply (no git worktree, no lockfile, no
  workflows, no build output) reports `unsupported` with the specific reason, never a pass.
- `hardening check` is now asynchronous and runs independent recipes concurrently with a bounded
  pool; one recipe failing never stops the others, and a handler exception becomes an `error` result.
- Raw reports are written under `<run>/raw/` and each result records the report basename and its
  SHA-256.
- A missing or mismatched tool yields `error` with the registry's reason; the toolchain now supports
  an explicit child environment, and the gitleaks recipe passes a PATH containing only the reviewed
  git binary so gitleaks' internal git lookup cannot be redirected.
- **Acceptance, through the CLI** (`tests/scanners/recipes-cli.test.ts`): on a scratch application
  with the vulnerable fixtures, all four scanners produce real findings — gitleaks repository and
  history, opengrep, zizmor, and osv-scanner — and a bare application reports honest
  `unsupported` reasons for the recipes that do not apply.

**Coverage semantics**

- A pass is now judged against the check's own `required_coverage`: complete is required for an
  `automated` method, partial is acceptable for a `mixed` one. Previously any partial coverage
  failed every pass, which made mixed-method controls impossible to satisfy.
- `SEC-01`'s two gitleaks recipes are reclassified `mixed` (definition version 2): gitleaks reports
  bytes, not the files it read, so per-file coverage cannot be attested; the tracked-file inventory
  is recorded as a compensating scope and the limitation is stated on the control. This
  deliberately invalidates SEC-01's 2026-10-07 approval — 34 of 35 approvals still resolve — and
  Batch D re-approves the whole sheet.

**Client secrets — H5**

- Marker set extended to OpenAI, Anthropic, Stripe live keys, Google API keys, GitHub tokens,
  Slack, Twilio, SendGrid, Resend, Firebase service-account JSON, and PEM blocks.
- JWT-shaped values are decoded and judged by their `role` claim: `service_role` (or anything that
  cannot be decoded) is a privileged finding, `anon`/`publishable` is classified as intended-public.
  This catches the legacy Supabase service-role key the audit's probe showed was missed.

**Pull-request trust — H4**

- `hardening-pr.yaml` checks out the base commit's `.hardening/` records and evaluates against them.
  A changed record set is diffed and fails the job as review-required while the evaluation still
  runs on the base records. The first adoption (no base records) is a bootstrap and says so.
  `docs/ci-trust.md` documents the behaviour; a harness test executes the record step against
  unchanged, changed, and missing base records.

**Not in this batch, recorded rather than implied:** TLS remains `unsupported` (testssl unpinned,
X3), ZAP remains a standalone Step 11 tool rather than a control recipe, the authorization and
functional-test recipes are not wired yet, and `hardening audit` (Batch U) does not exist. The
example's quality, manual-evidence, and live-target checks still report as before.

Suite at this point: **474 unit + 8 integration + 18 scanner + 5 example tests**, all passing on
Node 24.21.0.

### Owner decisions and Batch R acceptance (9 October 2026)

- **`repo-checks` passed on GitHub for `6e5cec4`**: build and test, scanner self-scan, workflow
  analysis, and hardening-gate all successful (the pull-request-only change report skipped by
  design). Batch R's platform acceptance is closed; the R1 Linux-x64 assets and the R2 ordering were
  exercised on a real runner.
- **R4 H2 review accepted.** The owner reviewed the never-exceptable floor and the two waiver rules
  in `policy/gate-policy.yaml`; the implemented behaviour stands.
- **No licence, deliberately (`release_scope: private-sole-maintainer`).** The repository is private,
  maintained and used by the owner alone, and not distributed; the package stays `private` and
  `UNLICENSED`, and the R7 licence item is a decision rather than a blocker.
- **Security contact not applicable while private.** OPS-03's release obligation remains unmet;
  release evaluation correctly blocks while no release is planned.
- **Repository visibility is `private`** (public only for the external audit; may be made public
  temporarily for testing).

### Batch R — repair, from the external audit (8 October 2026)

The 2026-10-08 external audit (`docs/audit/2026-10-08-external-audit.md`) found that the gate could
be weakened, the consumer workflow failed open, the scanners only worked on one machine, and the
repository's own CI had never passed. Batch R of the remediation plan fixed those, plus items the
plan's own gap analysis identified. Checkpoint: `docs/checkpoints/batch-r.md`.

**Exception handling — the audit's H1–H3, all reproduced and fixed**

- **A "never waivable" control can no longer be waived by scope shape.** The never policy is resolved
  from the finding's or check's control, unioned with the gate policy's `never_exceptable` floor;
  an exception that names a different control does not apply, and a `rule_id` with neither a
  `control` nor a `check_id` is rejected by the schema and the evaluator.
- **A valid waiver now lets the gate pass, visibly.** H2 decision recorded in
  `policy/gate-policy.yaml`: a permitted, precisely scoped waiver makes the decision satisfied while
  the finding appears in a new "Waived" report section. Critical findings can never be waived; a high
  finding at release needs `self_review: false`.
- **A waiver can no longer be applied over an execution error, unsupported, skipped, or pending
  result.** A result that produced no answer has nothing to accept.
- The gate policy's `never_exceptable` and `risk.blocking_severities` lists are now enforced rather
  than dead data.

**Report safety and counting**

- Every untrusted string entering Markdown is redacted and escaped (`escapeMarkdown(redactSecrets(…))`);
  console output is redacted and newline-flattened; finding titles are redacted at result creation.
- `control_outcomes` is one row per control (worst check outcome, union of reasons), with
  `required_checks`/`satisfied_checks` populated. Summary counts are controls, not checks.

**Fail-closed CLI and workflows — the audit's C2 and M2**

- `hardening check` exits 1 when a required check is `unsupported`, `skipped`, or `pending`, and 2 on
  `error`, still writing results first. Previously it always exited 0.
- `hardening-pr.yaml` and `hardening-release.yaml`: no `|| echo`, no `continue-on-error`; the report
  and gate always run; the final `hardening-gate` job downloads `plan.json` + `results.json` and
  re-runs the gate with trusted tooling, failing on a missing artefact.
- A trust test executes the gate step's own script with a failing `pnpm` stub and requires a nonzero
  exit — the audit's reproduction, now a regression test.

**Platform-aware toolchain — the audit's C3 and M6**

- `policy/toolchain.yaml` records 4 tools × 4 platforms (`darwin-x64`, `darwin-arm64`, `linux-x64`,
  `linux-arm64`) with release asset, archive digest, executable digest, and version. No absolute
  machine path remains; fetched tools resolve as `tools/bin/<name>/<version>/<platform>/<binary>`.
- `tools/fetch-tools.mjs` is platform-aware, verifies the reviewed pin before the hosting API
  digest, sends `GITHUB_TOKEN` when present, and exits `unsupported_platform` for anything unpinned.
- Non-native platform versions are the release tag's declared version, verified by `runTool` on
  first run there; native versions were observed by execution. Provenance is stated per entry.

**CI — the audit's C4, M4, M5**

- `tools/**` is typechecked by `tsconfig.tools.json` after `build`; CI builds before anything that
  imports `dist/`.
- Suites split: `test` (no external preconditions), `test:scanners`, `test:example`,
  `test:integration`. The example-build inspection moved to `tests/example/`.
- Every workflow install is filtered (`--filter sechard`), so consumer jobs no longer install
  Next.js, Playwright, and the Supabase CLI.
- The example manifest is generated from `.hardening/app.template.yaml` into a gitignored path, so
  `pnpm test` no longer rewrites a tracked file.

**Documentation truth — the audit's M3**

- `README.md` rewritten to state what works and what does not; `docs/status.md` generated from the
  progress record by `tools/generate-status.mjs` (`--check` fails on drift); `docs/status-report.md`
  removed; the audit, remediation plan, and gap analysis live in `docs/audit/`.
- `docs/ci-trust.md` documents the fail-closed behaviour and the still-open H4 gap (a PR supplies its
  own records until Batch W3).
- The generated control review sheet carries a "pending re-approval" banner (audit H6).
- A test replays the README's CLI block against a scratch consumer. Writing that test found a real
  defect: `process.exit()` does not wait for asynchronous stdout writes, so a CLI captured through a
  pipe could lose the first commands' output. The CLI now writes to its descriptors synchronously.

Suite at this point: **468 unit + 8 integration + 16 scanner + 5 example tests**, all passing on
Node 24.21.0.

### Added — Batch B: Step 06 tool execution (6 October 2026)

Batch B was authorised on the owner's instruction. Step 06 was implemented and verified; Steps
07–10 are blocked on a missing container runtime and were not started.

**Policy**

- `policy/dependency-policy.yaml`: the 10080-minute (7-day) release-age delay, reviewed registries,
  install scripts disabled by default with an empty allowlist, exact-version expiring exceptions for
  urgent fixes, the separation of provisioning from checking, and the operator-isolation requirement
  for application execution.
- `policy/toolchain.yaml`: an `execution` section recording how tools may be launched, and every
  scanner marked `identity: unverified` so the runner refuses to run it. The refusal is the honest
  state until a tool is downloaded, digested, and pinned in Step 09.

**Execution layer** (`src/execution/`)

- `process.ts` — the only place this repository starts a process. Argument arrays with no shell, an
  absolute executable path (never resolved through `PATH`), an allowlisted environment, capped
  output, and a deadline enforced with SIGTERM then SIGKILL against the whole process group.
- `registry.ts` — a tool runs only with an absolute path, a recorded version matching the installed
  one, and a digest verified against the binary on disk. Every scanner is refused as
  `identity_unverified`.
- `provision.ts` — provisioning separated from checking: `check` never installs a missing tool. A
  plan is validated (exact version, reviewed registry, age confirmation, reviewed hooks, download
  digests) before anything executes, and a refused plan runs nothing.
- `download.ts` — digest-gated, HTTPS-only (loopback excepted for tests), registry-matched,
  size-capped even against an understated `content-length`, and redirect-refusing, because a
  redirect is an origin reviewed policy did not approve.
- `policy.ts` — loads and validates the dependency policy, rejecting a wrong age delay, an HTTP
  registry, a wildcard or expired exception, and an exception beyond its maximum duration.

**Tests** — 65 new tests across 5 files, all with real processes, a real local HTTP server, and real
digests. Suite now **345 tests, 17 files**.

**Verified for this repository's own dependencies:** 53 installed packages scanned; 4 have hooks but
none is an install-time hook, and the build and full suite pass with `ignore-scripts=true`. Guarded
by a test that fails if a future dependency adds one.

### Verified — Step 06 unblocked (6 October 2026)

The owner granted `agent_may_install_runtimes: true` and `network_access_to_registries: true`.
The blocked Step 06 verification was completed, and **two long-standing environment blockers are
resolved**.

- **Node 24.21.0 installed on the supported runtime.** Official `darwin-x64` tarball, SHA-256
  verified against `SHASUMS256.txt` (`1462cb3b…e8097`). All verification now runs on Node 24.
  **E2 resolved.**
- **pnpm 12.9.1 installed; `pnpm install --frozen-lockfile` builds the CLI.** `pnpm-lock.yaml` is
  committed. This is the Step 01 acceptance check that had been blocked since Batch A.
  **E1 resolved.**
- **Full suite on Node 24.21.0 with pnpm: 338 unit + 8 integration tests, all passing.**
- **The seven-day release-age policy is enforced.** `minimumReleaseAge: 10080` refused
  `nanoid@6.0.2` (18.5h old) with `ERR_PNPM_NO_MATURE_MATCHING_VERSION`, naming the cutoff.
- **Install scripts are denied by default and an unapproved one fails the install**
  (`ERR_PNPM_IGNORED_BUILDS`, exit 1, script did not run). Verified with `core-js@3.37.1` and a local
  tarball fixture. `allowBuilds: { pkg: true }` ran the reviewed hook; `false` recorded a denial.

**Corrections applied** (each was previously stated as if true and was not):

1. **pnpm 12 does not read pnpm settings from `.npmrc`.** `minimumReleaseAge` and `engine-strict` in
   `.npmrc` were silently ignored; their `pnpm-workspace.yaml` forms (`minimumReleaseAge`,
   `engineStrict`) are enforced. A new `pnpm-workspace.yaml` holds all pnpm settings; `.npmrc` is
   documented as npm-only.
2. **`ignore-scripts=true` in `.npmrc` is ignored by pnpm** and was wrongly described as the control
   that blocks dependency hooks. The real control is `allowBuilds` default-deny, which is stronger:
   it fails the install rather than skipping quietly. Documentation and tests corrected.
3. **The age policy caught our own dependencies.** `vitest@5.0.3` and `@types/node@26.6.4` were
   younger than 7 days, so the install was refused. Instead of a forbidden package-wide exemption,
   they were moved to mature versions: `vitest@5.0.2` and `@types/node@24.19.0` (the latter also
   matches the Node 24 runtime better). `vite@8.3.1` added as an explicit peer because strict peer
   resolution requires it.
4. **Range fallback**: with a caret range, pnpm silently resolves to the newest *mature* version.
   Exact pins plus `minimumReleaseAge` produce a hard refusal, which is what this repository relies
   on. `minimumReleaseAgeStrict`'s distinct effect was not isolated, so it is not set.
5. **`minimumReleaseAgeExclude` is package-wide, not version-specific**, so the exact-version
   exception cannot be expressed directly in pnpm. Compensating control recorded in
   `policy/dependency-policy.yaml`: pin the exact version, add a temporary exclusion, hold an
   expiring policy exception, and remove the exclusion when the version matures.

### Added — Step 09: four scanner adapters with pinned, verified tools (6 October 2026)

**Tools pinned and verified.** Fetched through the reviewed download path (approved origin, approved
redirect host, bounded size, SHA-256 checked) and their versions confirmed by running them:

| Tool | Version | Digest provenance |
| --- | --- | --- |
| Gitleaks | 8.30.1 | Publisher checksums cross-checked against the release-asset digest |
| OSV-Scanner | 2.6.0 | Publisher checksums cross-checked against the release-asset digest |
| Opengrep | 1.30.0 | Release-asset digest only (no checksums file published) |
| zizmor | 1.30.1 | Release-asset digest only (no checksums file published) |

Weaker provenance is stated per tool rather than smoothed over, and ZAP and testssl remain
`identity: unverified` with their steps still blocked.

**Adapters** (`src/adapters/`): Gitleaks, zizmor, OSV-Scanner, and Opengrep, each parsing the tool's
real report format, redacting credential material unconditionally, and reporting what the tool
actually examined. Coverage is tool-specific and honest: Gitleaks is `partial` (it reports bytes, not
files); OSV is `partial` unless the lockfile's package count is supplied; zizmor and Opengrep name
the files they audited.

**Fixtures and rules:** vulnerable and fixed fixture pairs for secrets, static analysis, workflows,
and a vulnerable lockfile; a reviewed local Opengrep rule pack in `ci/configs/opengrep-rules/`; and a
Gitleaks product config that narrowly excludes the fixture directory so product scans do not report
them while adapter verification still detects them.

**Verified by running the real tools:** 15 scanner tests; 3 Gitleaks findings vs 0 on the fixed file;
4 zizmor findings vs 0; OSV advisories for `lodash@4.17.15`; 3 Opengrep findings vs 0. Full suite:
**357 unit + 8 integration tests.**

**Initial history review run.** `gitleaks git .` over 13 commits found 1 finding: a synthetic
non-functional placeholder token in `tests/cli/cli.test.ts` at commit `5ac4a0b4`. The working tree is
clean; history is not. It is recorded as an assessed, visible finding rather than allowlisted, since
suppressing a token-shaped value is how a real leak is missed later. History rewrite was not
performed: it changes commit identities and was not authorised.

**Defects found by running the tools, and fixed:**

1. **The first real scan of this repository found 4 leaks** — synthetic GitHub tokens committed as
   literals in two test files. They are now composed at runtime, so no secret-shaped string exists in
   the repository. Allowlisting the files was rejected because it would hide a future real leak.
   Re-scan: 0 findings.
2. **The toolchain recorded the archive digest rather than the executable digest.** The registry's
   digest check caught it: an extracted binary does not share the tarball's hash. The executable
   digest is now the pin, with the archive digest kept as provenance.
3. **The adapter retained the raw report**, letting an unredacted secret ride inside the parsed
   outcome. The raw report is no longer held there; the runner hashes the report file instead.
4. A host-comparison inconsistency in the download path (`host` vs `hostname`) and the newly observed
   GitHub asset CDN host (`release-assets.githubusercontent.com`) were corrected and recorded.

### Added — Step 12: generated agent guidance and protected configuration (6 October 2026)

Batch C was authorised on the owner's instruction. Batch B is complete as far as this machine allows
(Steps 06 and 09 verified; 07, 08, and 10 blocked on the absent container runtime). Step 12's stated
dependency is Steps 03–06, all complete, so it was the one executable step.

- **`agent-rules/core/rules.yaml`** — 15 rules covering authorized work, untrusted context,
  dependencies, secret boundaries, actual execution, preserved tests, and unresolved findings. Every
  rule is `must` or `must_not`; there is no `should`, because an optional rule is an option the agent
  will take. `review_status: draft` pending owner review.
- **Generator** (`src/agent/generate.ts`) producing `AGENTS.md` and `CLAUDE.md` from that single
  source. Deterministic (no embedded timestamp), records the source digest and generator version, and
  **refuses to overwrite a hand-written file** so a consumer's own guidance cannot be silently
  replaced. Both outputs say plainly that a prompt is not a permission boundary.
- **Review manifest** (`agent-rules/review-manifest.yaml`) naming every security-sensitive path, why
  review is required, and what to check — controls, mappings, patterns, policy, gate logic, security
  tests, scanner configs, workflows, agent settings, lockfiles, and consumer records. It is data, not
  enforcement; the platform wiring is Step 13.
- **Change report** (`tools/review-changes.mjs`) that notices deleted test files, removed test cases,
  added skips, removed assertions, added mocks, and scan-scope changes, and reports what it cannot
  judge. It requires review on the mechanics rather than claiming an AST heuristic proves intent.
- **Operator requirements** (`agent-rules/operator-requirements.md`): filesystem, credential, network,
  and runtime restrictions as operator obligations, each with a check, and the statement that prompt
  text cannot satisfy AGT-01.
- A test asserts the generated guidance contains **no permissive construction**, so a future source
  edit cannot quietly permit a skipped test or a simulated scan.

**Defects found and fixed while building this:** the generator assumed its output directory existed
(found by the tests); the manifest referenced an invented control, caught by its own validation; the
mock pattern missed helper names like `mockDatabase`; and the generated headers initially asserted
tool loading behaviour as fact, which is now labelled unverified because `coding_tool` is unfilled.

Suite: **390 unit + 8 integration tests, all passing.**

### Added — Step 13: workflows and the trusted final gate, local half (6 October 2026)

- **`.github/workflows/repo-checks.yaml`** — build/test, scanner self-scan, a security-test change
  report on pull requests, zizmor analysis, and a final `hardening-gate` job that depends on all of
  them, runs `if: always()`, and fails unless every dependency result is exactly `success`.
- **Callable workflows** `hardening-pr.yaml` and `hardening-release.yaml` for consumers, requiring a
  pinned `hardening_ref`, checking out the reviewed tooling separately from the untrusted
  application, with `contents: read` and no privileged trigger.
- **`templates/consumer-workflow.template.yaml`** pinning the called workflow and the policy ref to
  the same commit, and **`templates/CODEOWNERS.template`**.
- **`tests/workflows/trust.test.ts`** — 23 tests asserting SHA pins, no write permissions, no
  template interpolation into scripts, no `pull_request_target`, disabled credential persistence, the
  always-running gate, pinned caller refs, and a real zizmor run.
- **`docs/ci-trust.md`** — what the local tests establish, what they cannot, the inherent trust limit,
  and the platform settings the owner must configure.

**Defect found by running the analyser:** zizmor reported **3 high-severity `template-injection`
findings in these workflows** — `${{ }}` interpolated directly into `run:` scripts. Fixed by passing
values through `env:`; the re-scan is clean. A test now enforces the same property.

**Platform verification is `awaiting_external_verification`**: no GitHub test environment or token
exists, so required checks, CODEOWNERS resolution, fork behaviour, and merge queues are unverified.
`.github/CODEOWNERS` is deliberately absent while the owner identity is unfilled — a fabricated file
naming a display name would match nobody while looking like protection.

Suite: **413 unit + 8 integration tests, all passing.**

### Published — SecHard on GitHub (8 October 2026)

- **Repository published** at `github.com/domgeller2022-arch/SecHard`, commit `88df318`, 33 commits,
  185 files. Public for the initial external audit, to be moved to private once that audit is
  complete; the visibility decision and its reason are recorded in `01-owner-decisions.md`.
- **`repo_name` recorded as `SecHard`.** The npm package name is `sechard` (package names must be
  lowercase) and the CLI executable remains `hardening` per the plan.
- **The callable workflows now name the real repository** instead of `REPLACE_WITH_HARDENING_REPOSITORY`,
  and the consumer template keeps only the reviewed-commit placeholder. This resolved an open finding.
- **The machine's LAN address was withheld from the progress record before publication.** The binding
  finding and its evidence remain; only the address was removed.
- **Verified after the push:** remote `main` equals local `HEAD` (`88df318`); 185 files on the remote;
  **zero machine-output files** (`node_modules`, `.next`, `tools/bin`, `.env.local` are excluded as
  intended); secret scan over committed content and history reports none.

### Fixed — audit findings (8 October 2026)

A full audit of every claim in the progress record, with each check run rather than remembered,
found two problems in the secret-scan scope:

- **The product scan was defined by `dir`, so it scanned build output and local files.** A `dir` scan
  over the working tree reported 14 findings: the example's `.next/**` artifacts, its gitignored
  `.env.local`, and — the real one — **`tests/fixtures/build/`**, the fixture that deliberately
  contains a publishable key so the client-asset classifier can be shown to accept it. None of those
  is repository content, and this is how a secret scanner's output stops being read. The product scan
  is now **`gitleaks git`** (committed content and history), and the build fixture is in the reviewed
  exclusion list with the scanner fixtures. Re-run: **0 findings**, with adapter verification still
  detecting every fixture.
- **`gitleaks dir` takes a single path.** Passing several silently scanned the whole tree, which is
  how the misleading counts appeared in the first place. Corrected usage verified.

Audit result otherwise: typecheck, build, and lint clean; 465 unit + 8 integration tests; CLI
validate/approvals/gate behave as recorded; all four scanner digests still match their binaries;
generated artifacts current; zizmor 0 findings; no unfinished-work markers in engineered files.

### Added — manual evidence rules, a restore drill, and runbooks (8 October 2026)

- **Per-control freshness intervals are now enforced.** 90 days for restore/response exercises and
  data review, 30 for access, credential, and configuration evidence, taken from each control's own
  declaration. A 60-day-old drill is current for OPS-02 and stale for SEC-03, asserted both ways.
- **Scope-bound reuse.** A manual record observed at a different source is reusable only when it also
  pins the configuration fingerprint — an operational fact survives an unrelated code change but not
  a storage migration. Without the fingerprint it is refused with `manual.reuse_without_scope`.
- **Profile `never` now means never.** An exception for a control a profile marks not-exceptable no
  longer applies; the profile list was previously data nothing enforced.
- **Exceptions are invalidated by a definition change**, via a recorded `control_definition_version`.
- **Disposable restore drill** (`tests/operations/restore-exercise.sh`): backup, destroy, restore, and
  verification of row count, per-owner distribution, and a run-specific marker. **It found a real
  defect in my own procedure** — a data-only dump loaded without replacing the target's rows is an
  append, not a restore; it failed with a duplicate key and the procedure was corrected. Schema,
  grants, and policies are deliberately not in the backup, because they come from versioned
  migrations.
- **Runbooks** for restore/rollback, credential rotation, incident response, and logging/alerting,
  each naming its controls and the evidence to record. Operator confirmations remain `pending` until
  performed; the local drill is never evidence for the hosted environment.

Suite: **465 unit + 8 integration tests, all passing.**

### Added — guarded live recipes and a passive ZAP baseline (8 October 2026)

- **Approved-target model.** `examples/nextjs-supabase/.hardening/targets.yaml` and a new schema: an
  inventory of scheme, host, port, environment, routes, approved redirect hosts, response limits, TLS
  requirements, and per-route requirements. Wildcards, plain HTTP outside local, and HTTPS without a
  TLS requirement are rejected. Nothing contacts a host because a finding or a page mentioned it.
- **`src/adapters/http.ts`** — asserts declared requirements per route (headers with values, private
  routes that must not be publicly cacheable, content that must not appear), with bounded requests,
  checked redirects, and honest coverage: unreachable route → `partial`, nothing observed → `unknown`.
- **The first run found a real design issue**: `/auth/callback` built its redirect from the request's
  **Host header** — a host-header open redirect. The route now requires a configured `APP_ORIGIN`.
  The app also set no security headers; it now sets four, with HSTS deliberately absent locally.
- **Passive ZAP baseline**, image pinned by digest (`sha256:781a2bda…`, ZAP 2.17.0), run against the
  controlled local target: **60 passes, 7 warnings, 0 failures**, report captured with a SHA-256.
  Six real gaps recorded as unresolved: missing CSP, absent anti-CSRF tokens, missing COEP/COOP/CORP,
  and `X-Powered-By` disclosure. The image's root-owned work directory and the macOS share problem
  are documented with the working invocation.
- **TLS stays separate**: `testssl.sh` is recorded as unverified, and an integration assertion now
  requires a release plan to carry a TLS check that is `unsupported`, so production evaluation blocks
  while TLS evidence is missing.
- `docs/live-checks.md` states every boundary: anonymous requests only, no active or authenticated
  scanning, no cipher or protocol assessment.

Suite: **457 unit + 8 integration tests, all passing.**

### Added — build verification and the client secret boundary (7 October 2026)

- **`src/build/client-assets.ts`** — inspects browser-shipped output and **classifies rather than
  flags**: a publishable key is recorded as intended-public, while `sb_secret_`, service-role
  literals, private-key blocks, AWS key IDs, and browser-shipped source maps are findings. Coverage
  states exactly what was inspected and what was not.
- **Fixtures with proven detection** — a clean output with a publishable key passes; a leaking output
  with a synthetic privileged marker and a source map fails with critical and medium findings. The
  real production build reports **11 files, zero findings, zero source maps**.
- **`tools/inspect-build.mjs`** — connects assessed source, pinned policy, artifact digest, and
  inspection result into one evidence record, and **fails if the source identity changes during the
  run**. Quality information (file counts, sizes) is reported separately with no threshold applied.
- Verified: the browser bundle contains **no Supabase key at all**, because all access is server-side
  — stronger than the classified-publishable-key outcome the check was built to accept.

Outstanding and recorded: QUAL-01's configured thresholds, and server-side/deployment coverage, which
belongs to Steps 11 and 14.

Suite: **440 unit + 8 integration tests, all passing.**

### Added — authorization matrix with proven detection (7 October 2026)

- **`tests/authorization/matrix.yaml`** — 14 cases as machine-readable data: anonymous, owner A, and
  unrelated user B against list, read, create, update, and delete, plus a manipulated identifier and
  owner-field injection on create and update.
- **`run-authorization.mjs`** — executes the matrix against the unprivileged data API with each
  actor's own session, verifies every denial against stored state through a separate privileged
  channel, inspects the provider's policy and grant inventory, and **fails if the number of executed
  cases differs from the number declared**.
- **`weakened-detection.sh`** — adds one permissive SELECT policy, requires the matrix to **detect**
  it, resets the database, and requires the same matrix to pass again. Detection is proven, not
  assumed.
- **Results:** 14 cases executed, 0 failed, plus 4 inventory checks. Anonymous is refused at the grant
  layer with PostgREST **42501**; an invalid token with **PGRST301**; owner-field injection fails on
  both create and update; RLS is verified **enabled and forced**, with exactly one policy targeting
  `authenticated` and no grant held by `anon`.
- Two of my own bugs were caught by the checks and fixed: a boolean comparison (`true/true`, not
  `t/t`) and a percent-encoded path.

Outstanding and recorded: recovery isolation (AUTH-02), genuine session expiry, and QUAL-01's
configured thresholds for the example.

### Added — reference application verified end to end (7 October 2026)

The Next.js application is built and its session and authorization behaviour is verified in a real
browser against the real stack.

- **`examples/nextjs-supabase/app/**`** — landing page and sign-in, the private notes page, Server
  Actions for authentication and notes, and the auth callback route. Pinned: Next 16.3.7, React
  19.3.0, `@supabase/ssr` 0.12.7, `@supabase/supabase-js` 2.117.2, Playwright 1.63.0.
- **Security decisions in the code:** the server client acts as the signed-in user from cookies and
  the **secret key is never used**; the middleware validates with `getUser()` rather than
  `getSession()`; the notes query has no `owner_id` filter because the policy is the boundary; the
  auth callback validates its `next` parameter against a fixed allowlist.
- **`e2e/notes.spec.ts` — 7 Playwright tests, all passing** against a production build, one worker,
  **no retries**: anonymous redirect with content never sent; A sees A's and never B's; B sees B's and
  never A's; sign-out and sign-in as another user does not leak the previous user's notes; create,
  rename, and delete all work; and the notes response is not publicly cacheable.
- `tools/sync-example-env.mjs` writes the gitignored `.env.local` from the running stack, and writes
  **only the publishable key**.
- `next build` succeeds; root suite **428 unit + 8 integration**, lint green.

Recorded as outstanding rather than implied complete: recovery-flow isolation, the Step 08
manipulated-ID and direct-API matrix, and QUAL-01's configured lint/duplication thresholds for the
example.

### Added — standards and upstream resources incorporated (7 October 2026)

- **`upstream/sources.yaml`: 4 → 35 records.** Every standard and candidate tool from the blueprint's
  "Standards and upstream resources" section now has a canonical URL, edition, licence, support
  status, and review date. Twenty URLs were fetched and their titles checked on 2026-10-07; fifteen
  repository licences were checked via the GitHub API, and CodeGuard's `LICENSE.md` was fetched
  directly, confirming CC-BY-4.0.
- **`controls/mappings/standards.yaml`**: editions expanded from 6 to 10, each traceable to a source
  record, plus a `not_referenced` list giving a reason for every standard deliberately outside v1
  (SLSA, AISVS, LLM/Agentic/MCP Top 10, MASVS, Electron).
- **`docs/standards.md`**: what each standard is used for, the `related_risk` versus
  `verified_coverage` distinction, and why candidate tools such as TruffleHog (AGPL-3.0), CodeQL,
  Scorecard, and Syft/Grype/Checkov are recorded but not adopted.
- **`tests/domain/standards.test.ts`**: enforces that no mapping cites an unrecorded standard, that
  nothing claims `verified_coverage`, that out-of-scope standards carry reasons, and that only tools
  the toolchain actually invokes may claim `invoking` + `verified`.

Honest findings recorded rather than smoothed over: ASVS uses a moving `latest` tag so the numbered
edition is recorded as intended, not re-verified; AISVS has no release; MCP Top 10 is
non-commercial; and no mapping claims conformance because no application has been assessed.

**Firewall verification:** the owner enabled the firewall and stealth mode, both confirmed. But the
explicit `limactl` block did **not** take effect, and a test from the colima VM — a separate host —
still reached the forwarded ports with 200. The macOS firewall does not filter VM-network traffic.
The LAN finding is **narrowed, not closed**, and is recorded as an open finding with the corrected
commands and the operating rule (stack stopped when idle; it is stopped now).

**GitHub test environment deferred to the final step** at the owner's request; Step 13's platform
verification stays `awaiting_external_verification`.

Suite: **428 unit + 8 integration tests, all passing.**

### Added — reference application database layer with verified RLS (7 October 2026)

- `examples/nextjs-supabase/.hardening/app.yaml` — the application's manifest, with every feature
  declared explicitly and the exclusions visible.
- `supabase/migrations/20261007000001_notes.sql` — notes table, `owner_id` defaulting to
  `auth.uid()`, `force row level security`, one owner-scoped policy with `WITH CHECK`, and grants that
  revoke anonymous access.
- `supabase/seed.sql` — two synthetic users and one note each, seeded privileged and separate from the
  unprivileged clients used for assertions.
- **First real authorization evidence:** as user A, 1 note visible and 0 of another user's; A's attempt
  to update B's note affected **0 rows** and B's note was verified **unchanged** through a privileged
  connection; A's attempt to insert with `owner_id` = B was rejected by the policy; anonymous access
  is denied at the grant layer.
- `tools/relink-example.mjs` keeps the example's policy lock current, invoked from the test setup.
- **CODEOWNERS installed** for `domgeller2022-arch`, with a trust test that checks the handles match
  the owner decisions exactly. `github_owner` and `repo_visibility: private` recorded.
- `docs/ci-trust.md` now carries the exact GitHub test environment setup steps.

**Flakiness recorded:** one Opengrep test failed at 30.7s under load from the Supabase VM build and
passed in 15.6s when idle; the full suite is green. Not auto-retried.

Suite: **418 unit + 8 integration tests, all passing.**

### In progress — Step 07 local reference stack (7 October 2026)

- The Supabase local stack **runs on this machine**: `supabase start` completes after disabling the
  `realtime` and `analytics` services in the example's own `config.toml` (the reference app does not
  use them; on this host they came up unhealthy and made the CLI tear the whole stack down).
  Postgres on 54322, data API on 54321, and the CLI reported the new-style `sb_publishable_…` /
  `sb_secret_…` keys.
- The example is a workspace package, so the reviewed dependency policy — including the seven-day
  release-age delay — applies to it. Supabase CLI pinned at 2.118.0.
- **Open security finding:** the local stack is **reachable from the LAN** — `curl` to the machine's
  LAN address on port 54321 returns 200. The port forwarder binds all interfaces and neither colima
  0.10.3 nor Supabase CLI 2.118.0 offers a loopback-only switch in the versions tested. Step 07's
  requirement to bind disposable dev services to local interfaces is therefore **not met**, and the
  step is not verified while this holds. Mitigations are recorded in the progress record.

### Changed — owner decisions actioned (7 October 2026)

- **All 35 control definitions approved by the owner.** `controls/approvals.yaml` holds 35 records
  naming each reviewed-content digest; the definitions are `owner_reviewed` with `reviewed_by: owner`.
  `kind: owner` records self-review honestly — a sole maintainer is not independent assurance, and
  `owner_legal_name` is unfilled so the reviewer field names a role, not a person. A release gate now
  reports **0** approval reasons, where it previously reported one per applicable control.
- **Container runtime installed and verified** (see the E3 entry): colima 0.10.3 + lima 2.2.1 +
  docker CLI 29.8.2, chosen over Docker Desktop to avoid a proprietary licence decision.
- **`coding_tool` recorded as opencode (primary), with Claude Code and Codex available.**
  Step 12's compatibility check is verified against opencode's documented behaviour; the generated
  notes state the verified rule — opencode prefers `AGENTS.md` over `CLAUDE.md` — with the source and
  date, and a test stops it regressing.
- **Git history rewritten** to purge two synthetic credential-shaped literals at the owner's
  direction. `gitleaks git .` over the full history now reports **0** findings. A `.git` backup was
  taken outside the repository first. **Earlier checkpoint and progress entries reference pre-rewrite
  commit SHAs, which no longer resolve.**

Suite: **414 unit + 8 integration tests, all passing.**

### Blocked — Batch B remainder

- **Steps 07–10 are blocked.** Docker is **absent** from this machine — the CLI symlink points at a
  removed application, there is no socket, and no alternative runtime (`podman`, `colima`,
  `limactl`, `nerdctl`, `orbctl`) is installed. The reference application needs local Supabase, which
  needs a container runtime. Nothing was scaffolded in its place.
- **Step 06 sub-items blocked.** pnpm's `minimumReleaseAge` and install-script enforcement are
  unverified because pnpm is not installed (`agent_may_install_runtimes` unfilled). Scanner identity
  verification and the live download path are blocked on `network_access_to_registries`.

### Fixed — Batch A completion pass (6 October 2026)

An audit of Steps 00–05 against their stated acceptance criteria found work the checkpoint had
counted as done that was not. Fixed and tested:

- **Manual-only controls were never planned or evaluated.** SEC-03, OPS-02, and OPS-03 were absent
  from every plan, so a release could ignore required restore, response, and credential-lifecycle
  evidence entirely. Manual requirements are now planned, satisfied only by a current passing
  attestation with a matching recipe, and left unmet when the record is missing, expired, pending,
  or negative.
- **Profile stage requirements had no effect.** A hardcoded all-methods list dominated them, so the
  profiles could only add methods, never scope a stage. Profiles are now authoritative, and
  `manual_attestation` was added to the release stage, so production release requires current
  operator evidence.
- **`assessments.yaml` was never loaded or validated.** It is now validated: duplicate controls are
  rejected, a definition-version conflict against the catalogue is reported, and the records reach
  the evaluator (where a recorded `status` remains a claim, never proof).
- **Interval and reference validation were unwired.** `validate` now rejects malformed intervals,
  reports expired records as warnings, confines local evidence references to the application root
  (including through symlinked ancestors, without requiring the evidence to exist yet), and treats
  remote URLs as references that are never fetched.
- **Two templates did not validate** — assessment records lacked `schema_version`, manual records
  used an outcome the enum rejected, and unquoted placeholders parsed as YAML flow maps. All four
  templates now produce schema-valid records, and a test enforces that.
- **Dead code removed**: `toJson`, `escapeJsonString`, `countFiles`, `confineToRun`, `readRunRecord`,
  `displayPath`.

Behaviour the owner should note: a pull-request plan now derives **33** checks rather than 45, and a
release plan derives **55** (15 manual). The reduction at PR is the profile method list taking effect
for the first time, not lost coverage. Suite grew from 264 to **280 tests**.

### Added — review incorporation (6 October 2026)

Applied after the Batch A checkpoint, from the owner-supplied build-pack review and
skill-integration review. Behavioural items were implemented and tested, not only documented.

**Control approval is now a real release gate**

- `controls/approvals.yaml` (empty until the owner acts) and `schemas/control-approvals.schema.json`.
- An approval names the control ID, definition version, and a SHA-256 digest of the definition's
  reviewed content, with approval metadata excluded so recording an approval does not invalidate it.
  Editing a definition invalidates its approval **even without a version bump**.
- Release evaluation requires a valid approval for every applicable control. PR, local, and
  operations stages may exercise draft definitions. An agent-written reviewer is not proof of
  review: the gate reads the approval record, not the definition's own `review_status`.
- `self_review` is recorded: `kind: owner` on a solo project is self-review, not independent
  assurance, and reports say so.
- New CLI command `hardening approvals --policy .` prints the exact digest the owner must approve
  and the current state of all 35 definitions.

**Evidence is bound to the run, not just the commit**

- Plans and results now carry `run_id` and `attempt`. Matching source, policy, and target is not
  enough: an old report for the same commit cannot be replayed into a new run.
- `policy/gate-policy.yaml` sets `allow_cross_run_reuse: false`. Narrow aged reuse with unchanged
  tool/rule/configuration identity is a future reviewed policy change, not a default.

**Advisory freshness is mode-specific**

- Results record `advisory_mode` (`online_query` or `offline_database`) and mode-specific
  provenance. An online query is measured by its query time; an offline database by its retrieval
  time and, when the interface supplies one, its upstream update time. A freshly executed scan over
  an old cached database is `stale`, not fresh.

**JCS restrictions applied at the input boundary**

- The loader now rejects integers outside exact representation, non-finite numbers, and lone
  surrogates, and preserves Unicode without normalization. A value that would lose precision on
  parse is refused rather than silently rounded into a digest.

**Reviewed pattern library and provenance**

- `controls/patterns/patterns.yaml` and `schemas/pattern.schema.json`: 12 patterns adapted from the
  reviewed security skill, each carrying the factual corrections applied before reuse, a vulnerable
  and a permitted example, related control IDs, limitations, verification methods, and provenance.
- Corrections include: a PostgreSQL UPDATE policy without an explicit `WITH CHECK` is not
  automatically a bypass; storage is denied without policies rather than open; `SECURITY DEFINER`
  functions are inventoried rather than assumed to bypass RLS; HttpOnly cannot be a universal rule
  for the SSR refresh-token flow; a forwarded header is not a trusted rate-limit identity; a budget
  alert is not an enforced spending cap; source maps are classified rather than universally
  disabled; parameterized raw SQL differs from concatenated SQL.
- A pattern is a supporting record. Tests assert it produces no plan checks, has no path into the
  evaluator, and cannot produce execution success. Pattern IDs cannot be mistaken for control IDs.
- `upstream/sources.yaml` and `upstream/notices/vibe-security-skill.LICENSE` record the imported
  component, its MIT licence, attribution to the original author, the supplied file digests, and the
  fact that the upstream commit could not be established from the local snapshot.

**Owner decision sheet restructured (structural additions only, no values invented)**

- A table maps every decision to the first step it blocks, so a later-batch field can stay `TODO`.
- `github_codeowners` is separate from the display-name handle, because a display name is not a valid
  code owner.
- GitHub test permissions are split into create / push / change settings / delete, each defaulting
  to `false`, each limited to the named test repositories and never the master repository. The
  merge-queue capability limit and the single-resource-owner limit of fine-grained tokens are
  recorded alongside.

### Added — Batch A (Steps 00–05)

**Step 00 — build decisions and preflight**

- `docs/architecture.md`, `docs/trust-model.md`, `docs/supported-versions.md`,
  `docs/implementation-progress.md`, `policy/toolchain.yaml`.
- Host preflight recorded: macOS 26.3.1 x86_64, zsh 5.9, Git 2.55.0, Node v25.8.2, npm 11.11.1,
  Docker CLI 296.2 present with the **daemon not running**. npm registry, github.com, and
  nodejs.org all reachable.
- Node LTS rechecked against official sources: **Node 24 (Krypton) confirmed as the supported line**,
  EOL 2028-04-30. Node 26 does not enter LTS until 2026-10-28. No switch.
- Dependency identities, versions, and licences verified from the registry: `ajv` 8.20.0 (MIT),
  `ajv-formats` 3.0.1 (MIT), `yaml` 2.9.1 (ISC), `typescript` 7.0.2 (Apache-2.0), `vitest` 5.0.3
  (MIT), `@types/node` 26.6.4 (MIT), `pnpm` 12.9.1 (MIT).
- Repository initialised as a local Git repository with **no remote configured**. Nothing pushed.

**Step 01 — minimal repository**

- `package.json` with pinned `engines` (`>=24 <25`) and `packageManager` (`pnpm@12.9.1`), kept
  `private` and `UNLICENSED`. `.npmrc` with `engine-strict`, `save-exact`, `ignore-scripts`, and
  peer-dependency strictness.
- `build`, `typecheck`, `lint`, `test`, `test:integration`, `generate:matrix`, `build:fixtures`
  scripts. `hardening` executable compiled to `dist/`.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`.

**Step 02 — schemas and safe input loading**

- Ten JSON Schema draft 2020-12 schemas (`schemas/`) plus `controls/control.schema.json` and
  `schemas/control-catalogue.schema.json`.
- RFC 8785 JSON canonicalization in `src/evidence/digest.ts`, verified against the RFC's own section
  3.2.3 example and Appendix B number table. That example's SHA-256 is
  `2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb`.
- Bounded loader rejecting duplicate keys (in YAML and JSON), multiple documents, custom tags,
  anchors and aliases, oversized files, over-deep nesting, long strings, and long arrays.
- Path confinement that resolves symlinks before deciding, so a link inside the root pointing out
  of it is rejected.
- Typed applicability model where a missing feature declaration is `unknown`, never `false`.

**Step 03 — 35 control definitions and two profiles**

- `controls/controls.yaml`: all 35 blueprint IDs, no duplicates, **every one `review_status: draft`**.
  Each carries acceptance criteria, at least one verification method, evidence requirements, stated
  limitations, an owner role, and reassessment triggers.
- `controls/mappings/standards.yaml`: `related_risk` only. `reviewed: false`. **No exact standards
  requirement IDs are asserted anywhere**, because no mapping has been checked against a pinned
  source edition.
- `profiles/core.yaml` (11 controls) and `profiles/nextjs-supabase.yaml` (35 controls), with explicit
  excluded features and per-control exception policies. AUTHZ-01/02/03, CI-01, CI-03, GOV-02,
  REL-01, EXC-01, and AGT-03 are **never** exceptable.
- Consumer templates for the manifest, assessments, exceptions, manual evidence, and policy lock.
- Generated `controls/matrix.md` and `docs/checkpoints/control-review-sheet.md` from the same
  definitions the runner uses. Generation is byte-for-byte repeatable.
- Coverage split: 15 automated, 8 mixed, 12 manual-only.

**Step 04 — planning and the decision engine**

- `src/domain/planner.ts` derives the expected check list before execution, with a plan identity that
  changes when a required check is removed.
- `src/domain/evaluator.ts` is a **pure function** over validated records. Derives control outcomes
  from required check results, valid manual evidence, and resolved exceptions. A stored
  `status: pass` in a consumer record has no effect.
- `policy/gate-policy.yaml` with stage requirements, 168h/24h advisory freshness, 30/90-day manual
  intervals, and a 5-minute clock-skew allowance.
- Gates on: missing results, duplicate results, wrong source/policy/config/target identity, empty
  examined scope, partial coverage claiming pass, stale advisory snapshots, implausible future
  evidence, untriaged unknown severity, unjustified false positives, expired or blanket exceptions,
  dirty-tree release decisions, fixture evidence at a stage requiring real tools, and consumer
  attempts to drop required checks.

**Step 05 — working CLI and report**

- `validate`, `plan`, `check`, `gate`, `report` implemented. Exit codes 0/1/2 all demonstrated
  against the compiled CLI run from outside the repository.
- Per-run output directories with atomic writes. An old run's report cannot satisfy a new plan.
- Source commit and working-tree state recorded in `run.json` with a deliberately narrow environment
  record.
- Redaction of synthetic secret patterns before emission, Markdown escaping of untrusted text, and
  verified absence of process environment values from evidence.
- JSON and Markdown reports from the same evaluation, reporting kit readiness and application
  production readiness **separately**.

### Fixed — defects found and corrected during this revision

- **The test suite ran a stale compiled CLI.** `tests/global-setup.ts` now rebuilds `dist/` before
  the suite runs. Until this was fixed, the CLI and integration tests could report on code that was
  not the code in the working tree — exactly the class of misleading result this repository exists
  to prevent.
- Three approval tests asserted over all 35 controls instead of the applicable ones; the engine was
  correct and the tests were scoped properly.
- An unused `reuse` policy block was declared in the type without being read by any code. It was
  replaced with an explicit `allow_cross_run_reuse: false` that the behaviour matches.

### Fixed — defects found and corrected during the build

Recorded because a changelog that lists only successes hides the part a reviewer most needs.

- Loader reported duplicate YAML keys as a generic parse error; now `input.duplicate_key`.
- Path confinement misclassified an absolute path outside the root as a symlink escape; it now
  distinguishes lexical escape from symlink escape.
- Planned checks omitted `recipe_version`, so `check`, `gate`, and `report` all rejected their own
  plans as unusable.
- `validate` did not cross-check records against each other, so a manifest pinning the wrong policy
  commit passed. The plan command already refused it; this was an inconsistency, now closed.
- A missing consumer manifest produced derived errors instead of naming the missing record.
- Three gate tests asserted the wrong behaviour (a boundary-age snapshot, a valid exception, and a
  plan/manifest mismatch). The **tests** were corrected; the engine behaviour was not weakened.
- One gate behaviour was too strict: a triaged unknown-severity finding was blocked anyway. Now
  explicit triage is accepted, and a triage label with no stated reason is rejected at any severity.

### Blocked

- **No `LICENSE` file.** `code_licence` and `docs_licence` are still `TODO`. The package is marked
  `UNLICENSED` so nothing is published under an accidental default.
- **pnpm acceptance check not run.** pnpm 12.9.1 is pinned but not installed; installing runtimes
  requires `agent_may_install_runtimes`, still `TODO`. Dependencies were installed with npm in
  `--no-package-lock` mode. **No npm lockfile is committed.** `pnpm install --frozen-lockfile`
  building the CLI has not been verified.
- **15 owner-decision fields are unfilled**, recorded as blockers B1–B15 in
  `docs/implementation-progress.md`. B6 (`repo_name`) and B14 (`agent_may_install_runtimes`) have
  the widest effect.
- **All results were produced on Node v25.8.2**, which is outside the supported Node 24 line and is
  excluded by `vitest@5`'s declared engines. `engines` makes this fail loudly. Re-verification on
  Node 24.21.0 is required before release.
- **Docker daemon not running.** Required from Step 07 (local Supabase) and Step 11 (ZAP).

### Known limitations at the end of Batch A

- **One recipe actually runs.** `policy/record-consistency` confirms the policy records still hash to
  what the plan recorded. It inspects no application source. Every other selected recipe reports
  `unsupported`, so the end-to-end demo blocks with 44 of 45 checks unmet — deliberately.
- **No scanner is integrated and none has run.** Gitleaks, Opengrep, OSV-Scanner, and zizmor are
  recorded as `planned` selections with no verified version.
- **No reference application exists.** No authorization test, build check, live HTTP check, TLS
  check, or GitHub workflow has run.
- **Manual-evidence expiry is not yet gate-blocking.** `validate` checks the interval and the report
  records freshness; the evaluator does not yet block on it. Step 14 owns that.
- **`lint` is a dependency-free hygiene check**, not a linter. No ESLint or equivalent is installed.
- All 35 control definitions remain `draft`. No mapping is reviewed. No platform verification has
  been performed.
