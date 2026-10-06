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
