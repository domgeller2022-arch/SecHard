# Batch A checkpoint

Steps 00–05. Generated 2026-10-06. Authorised batch at the time of writing: **A**.

> **Post-checkpoint revision (6 October 2026).** A completion audit found several Batch A items that
> this checkpoint had treated as done but which were not: manual-only controls were never planned or
> evaluated, profile stage requirements were dominated by a hardcoded list, `assessments.yaml` was
> not validated, interval and reference checks were unwired, and two templates did not validate.
> All were fixed and tested; the suite grew from 205 to 280 tests, and the pull-request plan now
> derives 33 checks rather than the 45 stated below (release derives 55). See
> `docs/implementation-progress.md` → "Batch A completion pass" for the full account. The status
> table, blockers, and owner review list below remain accurate; the check counts and test totals in
> "Checks actually run" are superseded.

## Status

| Step | State | Reason |
| --- | --- | --- |
| 00 — Establish the build decisions | `verified` | Preflight, Node LTS recheck, dependency identities and licences all recorded. 15 owner-decision blockers and 3 environment blockers recorded. |
| 01 — Create the minimal repository | `verified` | Build, typecheck, lint, help, and version all run and pass. The pinned-package-manager acceptance check is **blocked** (pnpm not installable, B14). |
| 02 — Schemas and safe input loading | `verified` | 10 schemas + control schema; RFC 8785 verified against the RFC's own vectors; loader and path confinement failure modes tested. |
| 03 — Author the 35 controls and two profiles | `verified` | Exactly 35 IDs, all `draft`; both profiles validate; matrix generation repeatable; review sheet produced. Owner approval outstanding. |
| 04 — Planning and the decision engine | `verified` | 73 gate and failure-mode tests pass. Blocks on missing, wrong-commit, stale, expired, empty-scope, and consumer-weakening cases. |
| 05 — First working CLI and report | `verified` | All five commands run from outside the repository; exit codes 0/1/2 demonstrated. One real recipe runs; all others honestly report `unsupported`. |

## What now works

A compiled CLI that takes an application's declarations, derives the checks that ought to run, runs
the one recipe that exists, and blocks honestly on everything else.

```bash
cd /Users/dd/Desktop/Security\ Hardening/hardening

# Build. Node 24.21.0 is the supported line; this host runs Node 25 (see Known limitations).
npm install --engine-strict=false --no-package-lock
npm run build

# Validate a consumer's records and the policy catalogue.
node dist/cli.js validate --app tests/fixtures/consumer --policy .

# Derive the expected work, run it, decide, and report.
node dist/cli.js plan --app tests/fixtures/consumer --policy . \
  --stage pr --environment local --out /tmp/runs
node dist/cli.js check --app tests/fixtures/consumer --policy . \
  --plan /tmp/runs/<run-id>/plan.json --out /tmp/runs/<run-id>
node dist/cli.js gate --app tests/fixtures/consumer --policy . --run /tmp/runs/<run-id>
node dist/cli.js report --app tests/fixtures/consumer --policy . --run /tmp/runs/<run-id>
```

Owner commands for the repository itself:

```bash
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run generate:matrix
```

## Checks actually run

All commands below were executed on 2026-10-06 and their output captured in the terminal session
that produced this report. Nothing here is summarised from documentation.

| Command | Outcome | Evidence |
| --- | --- | --- |
| `sw_vers`, `uname -a`, `git --version` | macOS 26.3.1 x86_64, Darwin 25.3.0, Git 2.55.0 | `docs/implementation-progress.md` preflight |
| `git rev-parse --is-inside-work-tree` | `fatal: not a git repository` — the folder was not a repo; a local one was created with no remote | preflight |
| `node --version`, `npm --version` | v25.8.2, 11.11.1 | preflight |
| `command -v pnpm` | not found; `process.versions.corepack` is `undefined` on Node 25 | preflight |
| `docker info` | CLI 29.6.2 present, **daemon not running** (`no such file or directory` on the socket) | preflight |
| `npm view ajv version` | 8.20.0 — registry reachable | preflight |
| `curl https://nodejs.org/dist/index.json` | HTTP 200 | preflight |
| Node release schedule fetch | v24 Krypton LTS 2025-10-28, EOL 2028-04-30; v26 LTS only from 2026-10-28 | `docs/supported-versions.md` |
| `npm view <pkg> version license engines` ×7 | ajv 8.20.0 MIT, ajv-formats 3.0.1 MIT, yaml 2.9.1 ISC, typescript 7.0.2 Apache-2.0, vitest 5.0.3 MIT, @types/node 26.6.4 MIT, pnpm 12.9.1 MIT | `policy/toolchain.yaml` |
| RFC 8785 text fetch and vector extraction | Canonical output matches the RFC's section 3.2.3 example byte for byte; SHA-256 `2d5e01a3…baacb` | `tests/evidence/digest.test.ts` |
| `npm install --engine-strict=false --no-package-lock` | 47 packages, exit 0. `--engine-strict=false` required: `.npmrc` sets `engine-strict=true` and this host runs Node 25 | session log |
| `npm run typecheck` | exit 0, no diagnostics | session log |
| `npm run lint` | exit 0. Caught one real defect mid-step: JSONC comments in `tsconfig.json` | session log |
| `npm run build` | exit 0, `dist/cli.js` produced | session log |
| `node dist/cli.js help` / `version` / `bogus` | exit 0 / exit 0 (`0.1.0-dev.0`) / exit 2 | session log |
| `npm test` | **197 tests, 8 files, pass** | session log |
| `npm run test:integration` | **8 tests, 1 file, pass** — compiled CLI run from a separate directory | session log |
| `npm run generate:matrix` twice with `diff` | byte-identical output | session log |
| `node dist/cli.js validate --app tests/fixtures/consumer --policy .` | exit 0, 35 controls, 2 profiles | session log |
| `node dist/cli.js plan … --stage pr` | exit 0, **45 expected checks** derived | `/tmp/runs` |
| `node dist/cli.js check …` | exit 0, 45 results; built-in recipe `pass (complete)`, all others `unsupported` | `results.json` |
| `node dist/cli.js gate …` | **exit 1**, blocked, 44 reasons | session log |
| `node dist/cli.js report …` | **exit 1**, `report.json` + `report.md` written, decision `blocked` | `report.json` |
| Invalid-input cases | unknown profile, wrong policy-lock commit, duplicate YAML key each → exit 2 with a specific reason code | `tests/cli/cli.test.ts` |
| Path-with-spaces consumer | exit 0 on validate, exit 1 on gate (blocked, as expected) | `tests/integration/consumer.test.ts` |

Failures encountered and fixed during the build are listed in `CHANGELOG.md` under "Fixed" and in
the per-step entries of `docs/implementation-progress.md`. Six are worth the owner's attention:

1. Duplicate YAML keys were reported as a generic parse error rather than `input.duplicate_key`.
2. Path confinement misclassified an absolute path outside the root as a symlink escape.
3. Planned checks omitted `recipe_version`, so `check`, `gate`, and `report` all rejected their own
   plans as unusable.
4. `validate` did not cross-check records against each other, so a manifest pinning the wrong policy
   commit passed validation.
5. Three gate tests asserted incorrect behaviour and were corrected. The engine was not weakened.
6. One gate behaviour was too strict: a triaged unknown-severity finding was blocked regardless.

## Controls

**35 controls, all `draft`.** Zero are `owner_reviewed`; that is the owner's decision to make, and
this agent did not make it.

| State | Count |
| --- | --- |
| Draft | 35 |
| Owner-reviewed | 0 |

| Verification coverage | Count |
| --- | --- |
| Automated (every method runs by the runner) | 15 |
| Mixed (tool evidence plus reviewed manual/configuration evidence) | 8 |
| Manual-only (no automation; a scan can never satisfy these) | 12 |

**Controls whose acceptance criteria differ from the blueprint:** all 35 were written concisely from
blueprint section 6 rather than copied verbatim, which the plan permits ("original concise wording
where possible"). No control was added, removed, merged, or had its applicability changed. The
substantive difference is in the standards mappings: **no exact standards requirement IDs are
asserted anywhere**, because no mapping has been reviewed against a pinned source edition. Every
mapping is `related_risk` and `mappings.reviewed` is `false`. Manufacturing precise-looking IDs
that nobody checked would be worse than an honest gap, so the plan's instruction to "leave unreviewed
mappings visibly unverified" was followed.

## Deviations from the plan

| Deviation | Reason |
| --- | --- |
| Repository created at `Security Hardening/hardening/` rather than in place | The pack's own `README.md` would collide with this repository's `README.md`. The pack files were left unmodified. `repo_name` is still `TODO`, so the directory name is a placeholder. |
| Dependencies installed with npm in `--no-package-lock` mode instead of pnpm | pnpm 12.9.1 is not installed and `agent_may_install_runtimes` is `TODO`. **No npm lockfile is committed**, so the pnpm lockfile remains the only lockfile. The plan's "clean install with the pinned package manager" acceptance check has **not** run. |
| `lint` script is a dependency-free hygiene check, not a linter | No ESLint or equivalent was added. The plan requires a `lint` script and requires installing only what the current step needs; a hygiene check that catches JSON parse errors, line-ending damage, and lockfile conflicts covers what a type checker cannot, without a new dependency tree. A real linter is still owed. |
| Four builder tools run as `.ts` files under `node` | Node 25 strips types natively. `tools/generate-matrix.ts` imports from `dist/`, so it requires `npm run build` first; the npm script chains them. |
| Consumer fixtures are generated and untracked | The fixture pins this repository's current commit as its `policy_lock.commit`, so any commit makes a committed copy stale. `tools/build-fixtures.ts` is tracked; `tests/global-setup.ts` regenerates the output before each test run. |
| `check` exits 2 only on an `error` result; `unsupported` and `fail` exit 0 | The plan requires `check` to collect independent checks after a finding so the user gets a useful report. The decision belongs to `gate`. |

**No conflict between documents was found that precedence did not already settle.** One case is
worth flagging because it produced a judgement: the plan says manual evidence uses "per-control
intervals in policy (initial defaults in Step 14)" while Step 04 requires freshness handling now.
The engine implements the per-control interval mechanism and records freshness, but does **not**
yet block on an expired manual record — that is Step 14's work, and claiming it now would overstate
what was verified.

## Blockers and owner actions needed

### Owner decisions (each field is still `TODO` in `01-owner-decisions.md`)

| # | Field | What it blocks | What the owner must do |
| --- | --- | --- | --- |
| **B14** | `agent_may_install_runtimes` | **Step 01's pinned-package-manager acceptance check**, Step 06's pnpm policy test, Step 09 tool installation | Grant or deny installing Node 24 and pnpm on this machine. **Highest priority: it blocks a stated acceptance criterion.** |
| **B6** | `repo_name` | Package name (currently `hardening-repo`), distribution, Step 15 adoption | Provide the lowercase hyphenated name |
| B1 | `owner_legal_name` | `LICENSE`, `NOTICE`, release artifacts | Provide the legal name |
| B4 | `code_licence` | `LICENSE` (currently absent), publication | Choose `Apache-2.0` or `MIT` |
| B5 | `docs_licence` | Docs licence statement, publication | Choose `CC-BY-4.0` or `same-as-code` |
| B3 | `security_contact_email` | `SECURITY.md` (currently states the blocker), OPS-03 | Provide a vulnerability-reporting address |
| B2 | `owner_handle` | `README`, `CODEOWNERS` (Step 13) | Provide the display name |
| B7 | `repo_visibility` | Step 16 publication | Decide `public` or `private` |
| B8 | `github_owner` | Step 13 `CODEOWNERS` and workflows | Provide the owning account or organisation |
| B9 | `github_test_owner` | Step 13 platform verification (Batch C) | Create and name a throwaway account/organisation |
| B10 | `github_test_repos` | Step 13 platform verification (Batch C) | Name the disposable test repositories |
| B11 | `build_os` | Support statements, Step 16 readiness | State the intended build/CI operating system |
| B12 | `docker_available` | Step 07 local Supabase, Step 11 ZAP (Batches B/C) | Confirm Docker works. **Observed: CLI present, daemon not running.** |
| B13 | `network_access_to_registries` | Step 06 provisioning, Step 09 downloads | Confirm provisioning may reach registries. Observed reachable, but the permission is unfilled. |
| B15 | `coding_tool` | Step 12 generated agent rules | Name the coding tool in use |

### Review actions (no field to fill, but the work is outstanding)

- **Approve or amend all 35 control definitions** (`docs/checkpoints/control-review-sheet.md`).
  Until then every definition stays `draft` and no control can be treated as reviewed.
- **Review the standards mappings** against pinned source editions, or accept that they remain
  `related_risk`. No exact requirement ID can be published without this.
- **Approve `policy/gate-policy.yaml` thresholds**: 168h PR / 24h release advisory freshness, 30/90-day
  manual intervals, 5-minute clock skew, blocking severities.

### Environment items (not owner decisions, but the owner must act)

- Install Node 24.21.0 and pnpm 12.9.1 (depends on B14). All Batch A results were produced on Node
  25.8.2, which is outside the supported line and excluded by `vitest@5`'s engines. **Re-verification
  on Node 24.21.0 is required before release.**
- Start the Docker daemon before Step 07.

## Owner review list

Inspect these before authorising Batch B. Ordered by consequence.

| File / section | What to look for |
| --- | --- |
| **`docs/checkpoints/control-review-sheet.md`** (all 35 rows) | The single most important review in this batch. For each control: does the applicability condition match when you would actually want it? Is each acceptance criterion testable rather than aspirational? Is the stated verification method real, or is it a method whose recipe does not exist yet — those must be `manual_only`? Are the limitations honest? |
| **`controls/controls.yaml`** (per-control `acceptance`, `applicability`, `limitations`) | The authoritative wording. Confirm nothing was invented that the owner does not intend to maintain, and that no control is missing from the threat model. |
| **`controls/mappings/standards.yaml`** | Confirm `reviewed: false` and `related_risk`-only is the right state to publish, or supply the pinned editions so exact IDs can be verified. |
| **`src/domain/evaluator.ts`** (`evaluate`, `evaluateCheck`, `evaluateFinding`, `resolveExceptions`) | The security-critical core: this code turns a block into a pass. Check that an accepted risk never becomes a clean pass, that unknown severity is never treated as low, and that an expired exception leaves the underlying finding visible. |
| **`tests/gate/gate.test.ts`** | That the tests genuinely fail when the behaviour they guard is removed. The most important cases: missing required check, empty scope with zero findings, wrong commit, stale advisory snapshot, expired exception. Try deleting one assertion and confirm the suite notices. |
| **`tests/failure-modes/failure-modes.test.ts`** | That the failure modes are the real ones: replayed evidence, an expired waiver scoped to a different finding, a plan that dropped a required check, a stored `pass` that must not count. |
| **`policy/gate-policy.yaml`** | Every threshold and window. This file decides what blocks. Relaxing anything here silently weakens every gate. |
| **`profiles/nextjs-supabase.yaml`** (`permitted_exceptions`) | Whether the `policy: never` list is right. AUTHZ-01/02/03, CI-01, CI-03, GOV-02, REL-01, EXC-01, AGT-03 are marked never-exceptable. |
| **`profiles/*.yaml`** (`excluded_features`) | `nextjs-supabase` excludes payments, webhooks, uploads, tenancy, runtime AI. Confirm each exclusion is deliberate and that no adopter silently relies on one. |
| **`src/validation/loader.ts`, `src/validation/paths.ts`** | The trust boundary for every consumer file. Check that the limits are sane and that nothing is fetched, executed, or followed across a root. |
| **`src/evidence/redaction.ts`** | The redaction patterns and the Markdown escaping. A gap here leaks into reports and console output. |
| **`schemas/*.schema.json`** | Nothing was loosened to make a test pass. Spot-check `additionalProperties`, `required`, and patterns. |
| **`src/cli.ts`, `src/commands/run.ts`** | The CLI contract and exit codes. Confirm `0`/`1`/`2` still means satisfied/blocked/invalid, and that `report` cannot change a decision `gate` produced. |
| **`CHANGELOG.md`** (the "Fixed" section) | Six defects were found and corrected during the build, plus three corrected tests. Confirm you agree each fix was the right call, particularly fix #5 (the three corrected tests). |
| **`docs/trust-model.md`** | That the stated trust limit matches your intent. A maintainer who can replace workflows or policy can defeat the gate; that is inherent, not fixable here. |
| **`docs/implementation-progress.md`** (Blockers section) | Whether B1–B15 and E1–E3 are complete and correctly scoped. |

## Known limitations and risks

**Not covered at all**

- No scanner is integrated. Gitleaks, Opengrep, OSV-Scanner, and zizmor are recorded as `planned`
  with no verified version, no pinned reference, and no executed run. SEC-01, SEC-02, CODE-01, DEP-03
  have plans and definitions and **nothing else**.
- No reference application exists. AUTH-01, AUTH-02, AUTHZ-01, AUTHZ-02, AUTHZ-03, and DATA-01 have
  not been exercised against anything.
- No live check, TLS check, build check, or client-asset inspection. DEPLOY-01, WEB-02, REL-02, and
  SEC-02 are untested.
- No GitHub workflow, `CODEOWNERS`, or protected-check configuration exists. GOV-01 and CI-01 are
  definitions with no implementation.
- No agent guidance has been generated. AGT-01, AGT-02, and AGT-03 are Step 12 work.
- No independent consumer has adopted this. Step 15 exists precisely because adoption has not been
  proven.
- Container, IaC, mobile, desktop, runtime-AI, and signed-attestation support: absent by design.

**Partially covered**

- **One recipe runs.** `policy/record-consistency` (GOV-02) confirms the policy records still hash to
  what the plan recorded. It inspects no application source and establishes no coverage beyond the
  records it read.
- **Manual-evidence expiry does not block.** `validate` checks the interval is well formed and the
  report records `fresh`, but the evaluator does not yet treat an expired record as blocking. Step 14
  owns that.
- **Authorization decisions are modelled but not tested against a real boundary.** AUTHZ-01/02/03 are
  correct as policy (a deny-everything policy cannot pass; denied writes are required to be verified
  through a separate channel) but nothing enforces that against a live database yet.
- **`lint` is not a linter.** It checks JSON parseability, line endings, trailing whitespace, and
  lockfile conflicts. It will not catch unused variables, complexity, or style.
- **Fixtures are synthetic.** No fixture has yet demonstrated detection of a real vulnerability in a
  vulnerable file and its absence in a fixed one. That is Step 09 work.

**Untested or unverifiable here**

- **The host runtime is unsupported.** Node v25.8.2 is outside the supported Node 24 line and is
  excluded by `vitest@5`'s declared engines. Every Batch A result was produced on it. `engines`
  makes the mismatch fail loudly, but the results need re-verification on Node 24.21.0.
- **pnpm is unverified.** No pnpm command has run. `.npmrc` is written but untested, and
  `minimum-release-age` and the install-script allowlist are deliberately absent until Step 06
  selects and tests them.
- **macOS is not the supported execution environment.** Linux CI is. All results come from macOS, so
  they are useful feedback rather than release evidence.
- **The 45-check plan is almost entirely `unsupported`.** The end-to-end demo is deliberately red:
  forcing 35 controls to pass to make it green would have been exactly the shortcut this project
  exists to prevent.
- **No external verification of any kind.** No GitHub platform check, no published package, no
  external scan.

## Proposed next batch

**Batch B: Steps 06–10.**

1. **Step 06** — `policy/dependency-policy.yaml`, completed `policy/toolchain.yaml`,
   `upstream/sources.yaml`, and the execution layer: reviewed executables, argument arrays with no
   shell interpretation, bounded output, deadlines, a narrow environment, and child termination. This
   is where the pinned-pnpm acceptance check and the seven-day install-delay policy get tested, so
   it is blocked on **B14** and should not start until Node 24 and pnpm are installed.
2. **Step 07** — the reference Next.js + Supabase application. **Blocked on B12** (Docker daemon not
   running).
3. **Step 08** — the authorization matrix and real tests, including the deny-everything case and
   verification that denied writes leave stored data unchanged.
4. **Step 09** — the four scanner adapters, each with a vulnerable and a fixed fixture, and a real
   positive detection with the pinned tool. Fixture parsing alone is not sufficient.
5. **Step 10** — build verification and the client secret boundary, including a fixture that leaks a
   synthetic privileged credential and proof that the secure app passes.

**What the owner must prepare before Batch B**

1. **Fill in B14** (`agent_may_install_runtimes`) and install Node 24.21.0 plus pnpm 12.9.1. Step 06
   cannot be verified without them.
2. **Fill in B13** (registry access) and **B12** (Docker).
3. **Fill in B4 and B5** (licences) if a `LICENSE` file is wanted in Batch B's commits.
4. **Complete the control-definition review** from `docs/checkpoints/control-review-sheet.md`, or
   state explicitly that Batch B should proceed with all 35 still `draft`. Either is workable; the
   review is the substantive gate.
5. **Decide whether a real linter should be installed.** The current `lint` script is a hygiene check
   by design, and that is a deviation the owner should either accept or override.
6. **Confirm the gate-policy thresholds**, or state the intended values.

Batch B should not begin until `authorised_batch` is updated in `01-owner-decisions.md`.
