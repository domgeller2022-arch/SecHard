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
