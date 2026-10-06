# Implementation progress

Single append-only record for the hardening repository build. Updated at the end of every step.
States: `not_started` | `in_progress` | `verified` | `blocked` | `awaiting_external_verification`.

`verified` is used only when the step's stated acceptance checks actually ran and passed.
Authority for this batch: `authorised_batch: A` (Steps 00–05) in `01-owner-decisions.md`.

## Repository location

The build pack (`00-KICKOFF-PROMPT.md`, `01-owner-decisions.md`, `02-implementation-plan.md`,
`03-blueprint.md`, pack `README.md`) lives one directory above this repository. The repository root
is `Security Hardening/hardening/`. The pack was left in place and not modified; the pack's own
`README.md` would otherwise collide with this repository's `README.md`.

- Layout decision recorded in Step 00. `repo_name` is still `TODO`, so the directory name is a
  placeholder. Rename before any publication step.

---

## Step 00 — Establish the build decisions

- **State:** `verified` with recorded blockers (see Blockers below and the four documents).
- **Files changed:** `docs/implementation-progress.md`, `docs/architecture.md`,
  `docs/supported-versions.md`, `docs/trust-model.md`, `policy/toolchain.yaml`, `CHANGELOG.md`.
- **Actual checks run:** see "Preflight" below. All commands are recorded with their observed output.

### Preflight (kickoff prompt section 4)

Recorded 2026-10-06 from the build host.

| Item | Observed | Source of truth |
| --- | --- | --- |
| Operating system | macOS 26.3.1, build 25D771280a, Darwin 25.3.0, `x86_64` | `sw_vers`, `uname -a` |
| Shell | `/bin/zsh`, zsh 5.9 (x86_64-apple-darwin25.0) | `echo $SHELL`, `zsh --version` |
| Git | 2.55.0 | `git --version` |
| Git repo state | The build folder was **not** a Git repository and had no uncommitted work to preserve | `git rev-parse --is-inside-work-tree` → `fatal: not a git repository` |
| Node present | `v25.8.2` at `/usr/local/node` (via `/usr/local/bin/node`), npm `11.11.1` | `node --version`, `npm --version` |
| Node version managers | none present (`~/.nvm`, `~/.fnm`, `~/.volta` all absent) | `ls -d ~/.nvm ~/.fnm ~/.volta` |
| Corepack | **not bundled** in Node 25 (`process.versions.corepack === undefined`), so `corepack enable pnpm` is unavailable on this host | `node -e "process.versions.corepack"` |
| pnpm | **not installed** | `command -v pnpm` → not found |
| Docker | CLI 29.6.2 installed at `/usr/local/bin/docker`, but the **daemon is not running**: `failed to connect to the docker API at unix:///Users/dd/.docker/run/docker.sock ... No such file or directory` | `docker info --format '{{.ServerVersion}}'` |
| npm registry | reachable; `npm view ajv version` → `8.20.0` | `npm view` |
| github.com | reachable, HTTP 200 | `curl -o /dev/null -w '%{http_code}'` |
| nodejs.org | reachable, HTTP 200 for `/dist/index.json` | `curl` |

Docker being unavailable does not block Batch A. It is required from Step 07 (local Supabase) and
Step 11 (ZAP), both in later batches. Recorded here so those steps start from a known state.

### Node LTS status (rechecked against official sources)

Sources: `https://nodejs.org/dist/index.json` and the Node.js release schedule
(`https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`).

| Line | Newest patch | LTS codename | LTS since | Maintenance | End of life |
| --- | --- | --- | --- | --- | --- |
| v26 | v26.10.0 | not yet in LTS | — | — | 2029-04-30 |
| v25 | v25.9.0 | current (odd line, never LTS) | — | — | — |
| **v24** | **v24.21.0** | **Krypton** | **2025-10-28** | 2026-10-20 | **2028-04-30** |
| v22 | v22.23.3 | Jod | 2024-10-29 | 2025-10-21 | 2027-04-30 |

**Decision: keep Node 24 LTS.** `node_major: 24` in `01-owner-decisions.md` matches the only
currently active LTS line that has not entered maintenance-only status. Node 26 does not enter LTS
until 2026-10-28, so switching now would move to a non-LTS line. No switch recorded. Pinned tested
target is **Node 24.21.0**; the host actually running the build is Node 25.8.2 (see Blockers).

### Tool and package identities verified

Registry metadata read with `npm view <pkg> version license engines` on 2026-10-06. Exact pins are
in `policy/toolchain.yaml`; licences are recorded per component in `docs/supported-versions.md`.

| Package | Verified version | Licence | Notes |
| --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | Ships `Ajv2020` for JSON Schema draft 2020-12 |
| `ajv-formats` | 3.0.1 | MIT | Format validation for Ajv |
| `yaml` | 2.9.1 | ISC | `engines: node >= 14.6`; supports unique-key and tag/alias control |
| `typescript` | 7.0.2 | Apache-2.0 | `engines: node >=16.20.0` |
| `vitest` | 5.0.3 | MIT | `engines: ^22.12.0 \|\| ^24.0.0 \|\| >=26.0.0` |
| `@types/node` | 26.6.4 | MIT | — |
| `pnpm` | 12.9.1 | MIT | pinned as the project package manager; not installed on this host |

Integrity verification method used for v1: the package manager verifies the registry-published
`dist.integrity` (sha512) on install, and the lockfile records the resolved integrity for each
package. Per-package digest pinning of every transitive dependency is Step 06 work
(`policy/dependency-policy.yaml`), not Step 00.

**Recorded toolchain conflict:** `vitest@5.0.3` declares engines `^22.12.0 || ^24.0.0 || >=26.0.0`,
which **excludes the Node 25.8.2 runtime installed on this host**. Node 24.21.0 is inside the
supported range. Installing Node 24 on this machine requires `agent_may_install_runtimes`, which is
`TODO`. See Blockers.

**Not selected for v1:** no CLI argument-parsing library (Node's `node:util` `parseArgs` is used),
no canonical-JSON library (RFC 8785 is implemented in `src/evidence/canonical.ts` and tested against
the RFC test vectors), no schema-generation or policy-language dependency.

### Deferred tool selections (recorded, verified when their step begins)

These are needed in later batches only. Versions are recorded as *planned* and are **not** treated
as verified selections: Gitleaks, Opengrep, OSV-Scanner, zizmor (Step 09), Supabase CLI and Playwright
(Step 07), ZAP baseline image and testssl.sh (Step 11), GitHub Actions (Step 13).

### Trust boundary recorded

`docs/trust-model.md` separates: (a) operations that only read files and compute digests, and
(b) operations that execute untrusted application code or external binaries. A separate directory
and an environment-variable allowlist are explicitly **not** a sandbox, and are not described as one
anywhere in this repository.

### Decisions taken under the plan's defaults

1. Single core package, no workspace split, no second implementation under top-level `tools/`.
2. Repository root is `Security Hardening/hardening/` (pack files preserved unmodified).
3. Node 24.21.0 / pnpm 12.9.1 are the pinned toolchain targets.
4. `LICENSE` is **absent**, per plan Step 00 task 6, because `code_licence` and `docs_licence` are
   still `TODO`. This is a recorded blocker, not an oversight.
5. No git remote was configured and nothing was pushed. `agent_may_commit_locally: true` was used
   for local commits only.

- **Control coverage added:** none directly; this step fixes the toolchain and scope that later
  steps implement.
- **Limitations and unresolved findings:** no scanner has been integrated or run; no application
  exists; no external verification performed. `toolchain.yaml` lists later-batch tools as planned,
  not verified.
- **Owner decisions or external setup still needed:** all 15 `TODO` fields listed under Blockers.
- **Next step:** Step 01.

---

## Blockers

A blocker stops only the work that depends on it. Nothing here is worked around silently.

### Owner-decision blockers (from `01-owner-decisions.md`)

| # | Field | Value | Blocks | What the owner must do |
| --- | --- | --- | --- | --- |
| B1 | `owner_legal_name` | `TODO` | Step 00 (`NOTICE`), Step 01 (`LICENSE`), Step 16 (release artifacts) | Provide the legal name for copyright and notice lines |
| B2 | `owner_handle` | `TODO` | Step 01 (`README`), Step 13 (`CODEOWNERS`) | Provide the public handle/display name |
| B3 | `security_contact_email` | `TODO` | Step 01 (`SECURITY.md`), Step 14 (OPS-03 triage) | Provide a vulnerability-reporting address, ideally dedicated |
| B4 | `code_licence` | `TODO` | Step 01 (`LICENSE`), Step 16 (publication) | Choose `Apache-2.0` or `MIT` |
| B5 | `docs_licence` | `TODO` | Step 01 (docs licence statement), Step 16 | Choose `CC-BY-4.0` or `same-as-code` |
| B6 | `repo_name` | `TODO` | Step 01 (package name), Step 15 (consumer adoption), Step 16 (distribution) | Provide the lowercase hyphenated name |
| B7 | `repo_visibility` | `TODO` | Step 16 (publication) | Decide `public` or `private` |
| B8 | `github_owner` | `TODO` | Step 13 (`CODEOWNERS`, workflows), Step 16 | Provide the owning account or organisation |
| B9 | `github_test_owner` | `TODO` | Step 13 platform verification (Batch C) | Create a throwaway account/organisation and name it |
| B10 | `github_test_repos` | `TODO` | Step 13 platform verification (Batch C) | Name the disposable test repositories |
| B11 | `build_os` | `TODO` | Support statements in `docs/supported-versions.md`, Step 16 readiness | State the intended build/CI operating system |
| B12 | `docker_available` | `TODO` | Step 07 (local Supabase), Step 11 (ZAP) — Batch B/C | Confirm Docker works on the build host (observed: CLI present, **daemon not running**) |
| B13 | `network_access_to_registries` | `TODO` | Step 06 provisioning, Step 09 tool downloads | Confirm whether provisioning may reach registries; observed reachable, but the permission decision is unfilled |
| B14 | `agent_may_install_runtimes` | `TODO` | Step 01 clean-install acceptance, Step 06 pnpm policy test, Step 09 tool install | Grant or deny installing Node 24 and pnpm on this machine |
| B15 | `coding_tool` | `TODO` | Step 12 (which agent instruction formats are generated and verified) | Name the coding tool(s) in use |

### Environment blockers observed, not owner decisions

| # | Blocker | Evidence | Effect | Handling |
| --- | --- | --- | --- | --- |
| E1 | pnpm 12.9.1 not installed and may not be installed (B14) | `command -v pnpm` → not found; corepack not bundled in Node 25 | Step 01 "clean install with the pinned package manager builds the CLI" cannot be executed | Dependency graph built and verified with npm in `--no-package-lock` mode; **no npm lockfile is committed**; pnpm acceptance left explicitly unverified |
| E2 | Host runtime is Node 25.8.2, outside the supported Node 24 line, and excluded by `vitest@5` engines | `node --version`, `npm view vitest engines` | Checks run on an unsupported host runtime | All results recorded as "verified on Node 25.8.2; re-verification on Node 24.21.0 required". `engines` in `package.json` restricts to `>=24 <25` so the mismatch fails loudly rather than silently |
| E3 | **Docker is absent** (earlier: CLI present, daemon stopped) | 2026-10-06 preflight: `/usr/local/bin/docker` 29.6.2, daemon unreachable (`no such file or directory` on `~/.docker/run/docker.sock`). Later observation the same day: the symlink points at a removed `/Applications/Docker.app`, and no `podman`, `colima`, `limactl`, `nerdctl`, or `orbctl` exists. | Steps 07 (local Supabase), 08–10 (they need the app), and 11 (ZAP) | **Batch B stopped at Step 07.** The owner must install a supported container runtime or authorise a different approach |

---

## Progress log

### Step 01 — Create the minimal repository

- **State:** `verified` except the pinned-package-manager acceptance check, which is `blocked` (E1).
- **Files changed:** `package.json`, `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`,
  `.npmrc`, `.gitignore`, `src/cli.ts`, `tools/lint.mjs`, `README.md`, `SECURITY.md`,
  `CONTRIBUTING.md`.
- **Actual checks run:**
  - `npm install --engine-strict=false --no-package-lock` → 47 packages, exit 0. `--engine-strict=false`
    was required because `.npmrc` sets `engine-strict=true` and this host runs Node 25.
  - `npm run typecheck` → exit 0, no diagnostics.
  - `npm run build` → exit 0, produced `dist/cli.js`.
  - `node dist/cli.js help` → exit 0, usage printed.
  - `node dist/cli.js version` → exit 0, printed `0.1.0-dev.0`.
  - `node dist/cli.js bogus` → exit 2, "unknown command".
  - `node tools/lint.mjs` → exit 0. It caught one real defect during the step: `tsconfig.json` was
    JSONC with comments and failed the JSON parse, so the comments were removed.
- **Observed outcomes and evidence references:** all commands above, run from the repository root on
  Node v25.8.2.
- **Control coverage added:** none directly. `policy/toolchain.yaml` and the installation policy in
  `.npmrc` are groundwork for DEP-01, DEP-02, and CI-02.
- **Limitations and unresolved findings:**
  - **E1 unverified:** the plan requires "a clean install with the pinned package manager builds the
    CLI". pnpm 12.9.1 is not installed and may not be installed (B14). npm was used in
    `--no-package-lock` mode instead. **No npm lockfile is committed.** The pnpm acceptance check
    has not run.
  - `.npmrc` is written but untested against a pinned pnpm. `minimum-release-age` and the
    install-script allowlist are deliberately absent until Step 06 selects and tests them.
  - `npm` warns that `strict-peer-dependencies`, `auto-install-peers`, and `resolution-mode` are not
    npm settings. That is expected: they are pnpm settings, and the file is validated in Step 06.
- **Owner decisions or external setup still needed:** B1–B8, B11, B13, B14 (see Blockers).
- **Next step:** Step 02.

### Step 02 — Schemas and safe input loading

- **State:** `verified`.
- **Files changed:** `schemas/{app,assessment,check-result,exception,execution-plan,manual-evidence,
  profile,release-evidence,source,control-catalogue}.schema.json`, `controls/control.schema.json`,
  `src/validation/{errors,loader,paths,schema,semantic}.ts`, `src/evidence/digest.ts`,
  `src/domain/applicability.ts`, `tests/evidence/digest.test.ts`,
  `tests/validation/{loader,schema}.test.ts`, `tests/domain/applicability.test.ts`.
- **Actual checks run:**
  - `npx vitest run` → all suites passing at the time of the step (72 tests in the four suites that
    existed then).
  - `npm run typecheck` → exit 0.
  - `npm run lint` → exit 0.
  - RFC 8785 conformance was verified against the RFC's own text, retrieved during the step:
    `https://www.rfc-editor.org/rfc/rfc8785.txt`. The section 3.2.3 example output and the Appendix B
    number table were extracted programmatically and compared. See the failure and correction
    recorded below.
- **Observed outcomes and evidence references:**
  - `canonicalize` reproduces the RFC 3.2.3 example byte for byte, and its SHA-256 is
    `2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb`.
  - The loader rejects duplicate YAML keys (including inside JSON, which `JSON.parse` would have
    silently resolved to the last value), multiple documents, custom tags, YAML anchors and aliases,
    oversized files, over-deep nesting, over-long strings, and over-long arrays.
  - Path confinement resolves symlinks before deciding. A symlink inside the root pointing outside it
    is rejected as `path.symlink_escape`, and a sibling directory sharing a name prefix is not
    treated as inside the root.
  - A missing feature declaration yields applicability `unknown`, never `not_applicable`.
- **Control coverage added:** foundations for CTX-01, GOV-02, EXC-01, and every control whose
  applicability depends on a declared feature.
- **Limitations and unresolved findings:**
  - **Two real defects were found and fixed during this step, not worked around.** First, the loader
    reported duplicate keys as `input.parse_error` because the YAML parser raises them as parse
    errors with `code: DUPLICATE_KEY`; the loader now maps that to `input.duplicate_key`. Second,
    path confinement classified an absolute path outside the root as `path.symlink_escape` because
    it compared the resolved path against the unresolved one; it now compares against the
    *lexical* location to decide which code applies. A wrong code here would have been a misleading
    diagnostic in exactly the case where precision matters most.
  - A resolved-but-stale path case remains: a symlink that points *inside* the root is accepted, and
    the caller receives the resolved real path. This is deliberate, and the returned `path` is the
    real path rather than the requested one.
  - No remote evidence reference is fetched. A `uri`-shaped reference is treated as a reference only.
- **Owner decisions or external setup still needed:** none specific to this step.
- **Next step:** Step 03.

### Step 03 — Author the 35 controls and two profiles

- **State:** `verified`. All 35 control definitions are `draft`; owner review is pending by design.
- **Files changed:** `controls/controls.yaml`, `controls/mappings/standards.yaml`,
  `profiles/core.yaml`, `profiles/nextjs-supabase.yaml`, `src/domain/{definitions,matrix}.ts`,
  `tools/generate-matrix.ts`, `templates/{app-manifest,assessments,exceptions,manual-evidence}
  .template.yaml`, `templates/policy-lock.template.json`, `controls/matrix.md`,
  `docs/checkpoints/control-review-sheet.md`, `tests/domain/catalogue.test.ts`.
- **Actual checks run:**
  - `npm run generate:matrix` → exit 0; regenerated twice and `diff` confirmed byte-identical output.
  - `npx vitest run tests/domain/catalogue.test.ts` → 28 tests passing.
  - `npm run typecheck` → exit 0. `npm run lint` → exit 0.
- **Observed outcomes and evidence references:**
  - Exactly 35 IDs, matching the blueprint list in section 6 with no duplicates and none added or
    removed. Verified by test against a hardcoded expectation of the blueprint IDs.
  - Every control carries at least one verification method, evidence requirements, limitations, an
    owner role, and reassessment triggers. Any control declaring an automated method without a recipe
    fails the test.
  - Coverage classification: 15 `automated`, 8 `mixed`, 12 `manual_only`.
  - Both profiles validate. `AUTHZ-01`, `AUTHZ-02`, `AUTHZ-03`, `CI-01`, `CI-03`, `GOV-02`, `REL-01`,
    `EXC-01`, and `AGT-03` are marked `policy: never` for exceptions.
  - Enabling payments plans BIZ-01 and reports a coverage gap. Omitting a tenancy or roles
    declaration leaves AUTHZ-02 applicability `unknown`, not absent.
- **Limitations and unresolved findings:**
  - **Acceptance criteria were written concisely from the blueprint rather than copied verbatim.**
    The plan permits "original concise wording where possible". Every control's wording is in
    `controls/controls.yaml` and the owner review sheet lists it. No control was added, removed, or
    merged, and no applicability condition was changed.
  - **No standards mapping is verified.** Every entry is `related_risk` and
    `mappings.reviewed` is `false`. No exact ASVS requirement IDs are asserted anywhere, because no
    mapping has been checked against a pinned source edition. The owner review must do this.
  - The reference profile's Next.js and Supabase versions are declared as `planned`/`supported:
    planned`. Step 07 pins and verifies them.
- **Owner decisions or external setup still needed:** **B6 `repo_name`** affects nothing here but
  does affect distribution later. The owner's approval of all 35 definitions is the substantive
  outstanding action for this step.
- **Next step:** Step 04.

### Step 04 — Planning and the decision engine

- **State:** `verified`.
- **Files changed:** `src/domain/{planner,evaluator,types}.ts`, `policy/gate-policy.yaml`,
  `tests/gate/gate.test.ts`, `tests/failure-modes/failure-modes.test.ts`,
  `tests/helpers/fixtures.ts`.
- **Actual checks run:**
  - `npx vitest run tests/gate` → 53 tests passing.
  - `npx vitest run tests/failure-modes` → 20 tests passing.
  - `npx vitest run` → 173 tests passing across 7 suites at the end of the step.
  - `npm run typecheck` → exit 0. `npm run lint` → exit 0.
- **Observed outcomes and evidence references:**
  - A missing required check blocks; an empty result set blocks with one reason per planned check.
  - A valid zero-finding scan whose examined scope was empty blocks with `scope.incomplete`.
  - All-pass evidence for a different source commit, policy commit, or configuration blocks.
  - An advisory snapshot older than the stage limit makes the result `stale`. The release limit
    (24h) is demonstrably tighter than the PR limit (168h).
  - An expired exception blocks and leaves the underlying finding blocking.
  - A valid, precisely scoped, low-risk acceptance stays visible as a waiver with the finding
    recorded under it.
  - Disabling a required recipe through consumer configuration fails: a plan that omits a check no
    longer matches the identity recomputed from policy.
  - A recorded `status: pass` in a consumer assessment has no effect on the derived outcome.
  - Enabling an excluded feature both plans the obligation and reports a coverage gap.
  - The evaluator is pure: the same input yields the same decision, it does not mutate its input,
    and freshness follows the injected clock rather than the wall clock.
- **Limitations and unresolved findings:**
  - **Three tests were corrected during the step because they asserted the wrong thing, not because
    the behaviour was wrong.** Each correction is recorded in the test source:
    1. A freshness test expected a snapshot exactly 24h old to be stale against a 24h limit. "Older
       than the limit" is the rule; exactly at the limit is not older. The fixture was moved to a
       clearly older timestamp.
    2. An exception test asserted that a valid, precisely scoped exception should be rejected. It
       should be accepted. The test was rewritten to assert acceptance, and a separate test now
       records that `self_review` is preserved rather than implied to be independent review.
    3. An applicability test built the plan from a *complete* manifest and then evaluated it against
       an undeclared one. The realistic sequence plans from the manifest under test; the test was
       corrected to do that.
  - **`unknown_severity_untriaged` was initially too strict in one direction and too lax in another.**
    The first implementation blocked a triaged unknown-severity finding anyway. It now requires
    explicit triage, and a triage label with no stated reason is rejected whatever the severity.
  - Manual-evidence freshness is evaluated by `validate` and recorded in the report, but the
    evaluator itself does not yet treat an *expired* manual record as blocking. Step 14 owns that
    behaviour, and the current test asserts only what is true today rather than claiming more.
  - The gate does not yet evaluate changed source during a run or detect a source commit that moved
    mid-run. Step 10 task 4 owns that.
- **Owner decisions or external setup still needed:** approval of `policy/gate-policy.yaml`
  thresholds (168h PR / 24h release advisory limits, 30/90-day manual intervals, 5-minute skew).
- **Next step:** Step 05.

### Step 05 — First working CLI and report

- **State:** `verified`.
- **Files changed:** `src/cli.ts`, `src/commands/{io,run,check,report}.ts`,
  `src/evidence/{store,redaction}.ts`, `tools/build-fixtures.ts`, `vitest.config.ts`,
  `tests/cli/cli.test.ts`, `tests/integration/consumer.test.ts`, `tests/fixtures/consumer/**`.
- **Actual checks run** (all against the **compiled** CLI in `dist/`, from outside the repository):
  - `node dist/cli.js help` → exit 0.
  - `node dist/cli.js version` → exit 0, `0.1.0-dev.0`.
  - `node dist/cli.js bogus` → exit 2.
  - `node dist/cli.js validate --app tests/fixtures/consumer --policy .` → exit 0.
  - `node dist/cli.js plan ... --stage pr --environment local` → exit 0, 45 expected checks.
  - `node dist/cli.js check ...` → exit 0, 45 results written; the built-in recipe reported
    `pass (complete)`, every other recipe reported `unsupported`.
  - `node dist/cli.js gate ...` → exit 1, blocked with 44 reasons.
  - `node dist/cli.js report ...` → exit 1, wrote `report.json` and `report.md`.
  - Invalid-input cases: unknown profile, wrong policy-lock commit, and a duplicate YAML key each
    produced exit 2 with a specific machine-readable reason code.
  - `npx vitest run` → 205 tests passing across 9 suites.
  - `npm run typecheck` → exit 0. `npm run lint` → exit 0.
- **Observed outcomes and evidence references:**
  - Exit code 0 (satisfied), 1 (blocked), and 2 (invalid) are each demonstrated. The satisfied case
    is asserted at the evaluator level with a core-only profile and complete evidence, because
    satisfying the gate through the CLI would require every profile recipe to exist — Batch B work.
  - The demo is deliberately red: 44 of 45 checks report `unsupported` and the gate blocks. Forcing
    all 35 controls to pass to make a demo green was rejected.
  - Run directories are per-run. A report from one run does not satisfy a different plan; the second
    run's gate reports `check.missing`.
  - Reports state kit readiness and application production readiness separately. A blocked kit run
    reports `pending` for both.
  - Synthetic secret patterns are redacted to `[REDACTED]` before emission, untrusted text is escaped
    before entering Markdown, and no process environment value appears in evidence.
- **Limitations and unresolved findings:**
  - **Only one recipe runs.** `policy/record-consistency` (GOV-02) re-reads the policy records and
    confirms they still hash to what the plan recorded. It inspects no application source and
    establishes no coverage beyond the records it read. Everything else reports `unsupported`, which
    is the honest outcome.
  - **No scanner, no application, no live check.** SEC-01 through SEC-03, CODE-01, AUTH*, AUTHZ*, and
    DATA-01 exist as definitions and plans but have run nothing.
  - **Defects found and fixed during the step**, each recorded in source rather than worked around:
    1. Planned checks omitted `recipe_version`, so the plan failed its own schema and `check`, `gate`,
       and `report` all rejected it as unusable. Fixed by always recording a recipe version.
    2. `validate` did not cross-check records against each other, so a manifest pinning the wrong
       policy commit passed validation. Fixed by adding a cross-check; the plan command already
       refused it, so this was inconsistent rather than a gate bypass.
    3. A missing consumer manifest produced a wall of derived errors instead of naming the missing
       record. Fixed so the manifest is named first.
  - The `lint` script is a dependency-free hygiene check (JSON parse, line endings, whitespace, lockfile
    conflict), not a linter. No ESLint or equivalent is installed.
  - `check` exits 2 only when a result is `error`; unsupported and failed checks exit 0 from `check`
    and are left for `gate` to block on. This is intentional: `check` collects everything it can and
    leaves the decision to `gate`.
- **Owner decisions or external setup still needed:** B6 `repo_name` before distribution. Owner review
  of `policy/gate-policy.yaml` thresholds.
- **Next step:** Batch A checkpoint. Stop here; do not begin Step 06.

---

## Revision: build-pack and skill-integration reviews (2026-10-06)

Two review documents supplied by the owner were incorporated. Items that change behaviour were
implemented and tested; items that belong to later batches were recorded in the patterns and plan.
This revision was applied **after** the Batch A checkpoint and does not change the batch boundary.

- **State:** `verified` for the implemented items; the owner-sheet additions are structural and
  unfilled by design.

### What changed

| Item | Files | Checks run |
| --- | --- | --- |
| Control approval: content digest excluding approval metadata, digest-change invalidation, release-only enforcement, self-review labelling | `controls/approvals.yaml`, `schemas/control-approvals.schema.json`, `src/domain/approval.ts`, `src/domain/evaluator.ts`, `src/commands/io.ts`, `src/commands/run.ts`, `src/cli.ts` | `tests/domain/approval.test.ts` (22 tests), gate approval scenarios (5 tests), `node dist/cli.js approvals --policy .` |
| Run/attempt binding so the same commit's old report cannot be replayed; cross-run reuse disabled | `schemas/execution-plan.schema.json`, `schemas/check-result.schema.json`, `src/domain/planner.ts`, `src/domain/evaluator.ts`, `policy/gate-policy.yaml` | gate run-replay tests (3), full suite |
| Mode-specific advisory freshness (online query versus offline database; upstream update time when supplied) | `schemas/check-result.schema.json`, `src/domain/evaluator.ts` | gate freshness tests (4 new) |
| JCS at the input boundary: unsafe integers, non-finite numbers, lone surrogates rejected; Unicode preserved without normalization | `src/validation/loader.ts`, `src/validation/errors.ts` | loader tests (5 new) |
| Reviewed pattern library with corrected rationale and provenance | `controls/patterns/patterns.yaml`, `schemas/pattern.schema.json`, `src/domain/definitions.ts`, `src/domain/matrix.ts` | `tests/domain/patterns.test.ts` (19 tests) |
| Upstream provenance and licence/notice for adapted material | `upstream/sources.yaml`, `upstream/notices/vibe-security-skill.LICENSE` | source-schema tests, matrix generation |
| Owner-sheet structure: decision-to-step table, `github_codeowners`, split GitHub test permissions | `01-owner-decisions.md` (pack), `README.md` (pack) | n/a — document structure, no values invented |
| Pack revision notes and imported-guidance rule | `00-KICKOFF-PROMPT.md`, `02-implementation-plan.md`, `03-blueprint.md`, `README.md`, `CONTRIBUTING.md`, `docs/architecture.md`, `docs/trust-model.md` | review |

### Checks actually run

- `npx tsc --noEmit` → exit 0.
- `npm run build` → exit 0.
- `npx vitest run` → **258 tests, 11 files, all passing.**
- `npm run lint` → exit 0.
- `node dist/cli.js approvals --policy .` → exit 0; prints 35 content digests, all `not approved`.
- `node dist/cli.js gate --stage release` → exit 1 with `policy.control_not_approved` for every applicable control.
- `node dist/cli.js gate --stage pr` → 0 policy reasons; draft definitions do not block development.

### Limitations and unresolved findings

- **Pattern verification is not implemented.** All 12 patterns carry `implemented: false`; the
  fixtures and recipes they describe are Steps 07–11 work. A test asserts no pattern claims
  otherwise.
- **The advisory-mode fields are modelled and gated but no adapter writes them yet.** Step 09
  records `advisory_mode` and `advisory_provenance` when OSV-Scanner is integrated. Until then the
  behaviour is exercised only by tests.
- **The upstream skill snapshot was not independently verified here.** The digests in
  `upstream/sources.yaml` were supplied by the integration review; the upstream commit is recorded
  as unestablished. The notice file states it was reconstructed and must be checked before
  distribution.
- **Owner-sheet fields were added, not answered.** `github_codeowners`, the four
  `agent_may_*_test_*` permissions, and the decision-to-step table are structural additions. No
  values were invented, and the new fields are `TODO`/`false` by default.
- **The pack documents were amended, not rewritten.** `00`, `02`, and `03` gained revision notes
  pointing to where each correction landed; the substantive details live in the repository.

### Approvals status after this revision

Every control's content digest changed (controls were not edited, but the digest is computed over
the definition as loaded, and the approval records are new). All 35 remain `draft` and **zero** have
a valid approval. Release evaluation blocks on that, by design.

---

## Batch B — Steps 06–10

**Authorisation.** `authorised_batch` was changed from `A` to `B` by the build agent on the owner's
explicit instruction ("continue") after the Batch A completion pass, with the change annotated in
`01-owner-decisions.md`. No Batch A work was reopened.

**Outcome.** Step 06 was implemented and verified as far as the machine permits. Steps 07–10 are
**blocked** and were not started: the reference application needs a container runtime, and Docker is
absent (E3). Producing a "reference app" without the stack it is supposed to demonstrate would be a
fabricated deliverable, so the batch stops here.

### Step 06 — Control dependency and tool execution

- **State:** `verified` for everything the environment permits; three sub-items `blocked` (pnpm
  behaviour, scanner identity verification, and the network provisioning path).
- **Files changed:** `policy/dependency-policy.yaml`, `policy/toolchain.yaml`,
  `src/execution/{process,registry,provision,download,policy,version}.ts`,
  `tests/execution/{process,policy,download,registry,install-policy}.test.ts`,
  `docs/architecture.md`, `docs/trust-model.md`.
- **Actual checks run:**
  - `npx vitest run tests/execution` → **65 tests, 5 files, pass.** These run real child processes,
    a real local HTTP server, and real file digests; none of it is mocked.
  - `npx tsc --noEmit` → exit 0. `npm run build` → exit 0. `npm run lint` → exit 0.
  - Full suite `npx vitest run` → **345 tests, 17 files, pass.**
  - Direct observation of the machine's dependency hooks: scanned 53 installed package directories;
    4 have hooks (`ajv` prepublish, `fast-deep-equal` prepublish, `lightningcss` prepare, `tinyexec`
    prepare). **None is an install-time hook** (`preinstall`/`install`/`postinstall`), and the build
    and the full suite pass with `ignore-scripts=true`. Recorded as committed evidence, and guarded
    by a test so a future dependency that adds an install hook fails and forces a policy decision.
  - `docker` rechecked for Step 07: absent (E3).
- **Observed outcomes and evidence references:**
  - **A malicious argument stays data.** `; touch <file>`, `$(...)`, and backticks passed as
    arguments appear literally in the child's argv and create nothing. A relative executable is
    refused before spawn, so `PATH` cannot redirect execution.
  - **The environment is an allowlist.** A parent variable not named in the list is absent in the
    child; the parent environment is never inherited wholesale.
  - **Missing tools produce an error.** A nonexistent binary and a nonexistent working directory both
    return `spawn_error` rather than throwing or hanging.
  - **A deadline terminates the child and its descendants.** A child scheduled to write a marker file
    after 3s, with a 700ms deadline, is killed (SIGTERM, then SIGKILL after the grace period); the
    marker never appears, checked after the write would have occurred.
  - **Output is bounded.** A process flooding stdout is truncated at the cap, stopped, and reported
    with `outputTruncated`.
  - **A digest mismatch prevents execution.** The registry verifies a recorded SHA-256 against the
    binary on disk; a substituted binary is refused with `digest_mismatch` and is not spawned. A
    download whose content does not match is refused and nothing is written.
  - **Every scanner is refused.** Gitleaks, Opengrep, OSV-Scanner, zizmor, ZAP, and testssl are all
    recorded `identity: unverified`, so `resolveTool` returns `identity_unverified` for each. This is
    the correct outcome and is asserted as such.
  - **Provisioning is separate from checking and validated before it runs.** A missing tool during
    `check` never installs anything. A plan is refused for a version range, an unreviewed registry,
    a missing digest on a download, an unapproved install hook, or an expired exception — and when a
    plan is refused, `executeProvisionPlan` returns with **zero** subprocess outcomes.
  - **Downloads are constrained.** HTTPS only (loopback excepted for tests), exact registry match,
    digest verified, size-capped even when the server understates `content-length`, and redirects
    refused by default.
- **Control coverage added:** DEP-01 (identity and pins), DEP-02 (install-script policy), CI-02
  (immutable execution inputs), and the execution half of AGT-02. DEP-03's updater and advisory
  freshness remain Step 09/16 work.
- **Limitations and unresolved findings:**
  - **The release-age delay is policy, not yet verified behaviour.** `policy/dependency-policy.yaml`
    sets `minimum_release_age_minutes: 10080` and validation refuses a normal install while the
    package manager's enforcement is unverified. **pnpm is not installed** (B14), so pnpm's
    `minimumReleaseAge` behaviour has not been selected, configured, or tested. Recorded as blocked;
    the code does not pretend otherwise.
  - **The install-script control is verified for our own toolchain, not for pnpm.** Our dependency
    set needs no install hook and builds with scripts disabled. That pnpm actually leaves an
    unapproved hook disabled is unverified (B14).
  - **Scanner identities are unverified and nothing has been downloaded** (B13). The digest-gated
    download path is tested against a local HTTP server, not against a real registry.
  - **Provisioning executes through an absolute manager path only.** There is no working end-to-end
    provisioning run, because that needs the manager and network permission.
  - `application_execution` records the operator-isolation requirement as policy; no recipe executes
    application code yet (Step 07+).
- **Owner decisions or external setup still needed:** B13 (registries), B14 (runtimes/pnpm).
- **Next step:** Step 07, blocked on B12/E3.

### Steps 07–10 — blocked

- **Step 07 (reference application):** `blocked` — requires Docker; absent (E3).
- **Step 08 (authorization and session verification):** `blocked` — depends on Step 07.
- **Step 09 (scanner adapters):** `blocked` — depends on Step 06 (met), but needs Step 08's app for
  the integrated profile and requires real positive detections with downloaded, pinned tools. Both
  the container runtime and the network permission are missing.
- **Step 10 (build and client-asset checks):** `blocked` — depends on Steps 08–09.

No workaround was attempted. Scaffolding an application or a scanner adapter that cannot run would
be exactly the "documentation standing in for behaviour" this project forbids.

---

## Batch A completion pass (2026-10-06)

An audit of Steps 00–05 against their stated acceptance criteria found several items the earlier
checkpoint treated as done that were not. They were fixed and tested. This pass stayed inside
Batch A; nothing from Steps 06+ was started.

### What was actually missing

| Defect | Why it mattered | Fix |
| --- | --- | --- |
| **Applicable manual-only controls were never planned or evaluated.** SEC-03, OPS-02, and OPS-03 were silently absent from every plan, at every stage. | A release could ignore required restore, response, and credential-lifecycle evidence entirely — an implied pass, which the blueprint forbids. | The planner now plans manual requirements; the evaluator satisfies them only from a current passing attestation with a matching recipe. Missing, expired, pending, or negative records leave the requirement unmet. |
| **Profile stage requirements were dominated by a hardcoded method list.** A union of `STAGE_METHODS` and the profiles meant the profiles could only add methods, never scope a stage. | The plan's intent that profiles define PR/release/operations requirements had no effect. | Profiles are authoritative; the constant is only a fallback for a profile that defines no stage. `manual_attestation` was added to the release stage of both profiles, so production release requires current operator evidence. |
| **`assessments.yaml` was never loaded or validated.** The file, schema, and template existed; `validate`/`plan`/`gate` ignored it. | A consumer's assessments could be malformed, reference a forged control, or be written against a stale definition version, and nothing noticed. | `loadConsumer` loads and validates it; duplicate controls are rejected; a version conflict against the catalogue is reported; the evaluator receives the records (status remains a claim, never proof). |
| **Record-freshness validation was unwired.** `checkIntervals` existed but nothing called it. | Malformed intervals (expiry before observation) were accepted as valid records. | `validate` rejects malformed intervals as errors and reports expired records as warnings, so an expired exception still lets a plan be derived and the finding shown. |
| **Evidence references were not confined.** Path confinement was only used by unit tests. | A record could reference `../../../etc/passwd`, and remote references were indistinguishable from local ones. | Local references are confined to the application root, including through symlinked ancestors, without requiring the evidence to exist yet. Remote URLs are treated as references and are never fetched. |
| **Two templates did not validate.** `assessments.template.yaml` records lacked the required `schema_version`; `manual-evidence.template.yaml` used `outcome: pending`, which the enum rejected; unquoted placeholders parsed as YAML flow maps. | The templates could not actually be used to create valid records — documentation standing in for working behaviour. | Fixed, `pending` added as an explicit manual-evidence outcome, placeholders quoted, and a test now validates every template after substitution. |
| **Dead code** (`toJson`, `escapeJsonString`, `countFiles`, `confineToRun`, `readRunRecord`, `displayPath`) | Unused exports invite drift and make the real surface harder to review. | Removed. |

### Behaviour changes the owner should know about

- **A pull-request plan now derives 33 checks rather than 45, and a release plan 55 (15 of them
  manual).** Pull requests require no manual evidence by design; production release requires current
  operator evidence for every applicable manual control. The reduction at PR is the profile method
  list taking effect for the first time; it is not lost coverage.
- **A release from a directory that is not a Git repository blocks on source identity.** This was
  already intended, but the integration fixture surfaced it: `resolveSourceIdentity` returns a zero
  commit and a dirty tree, so `release` evaluation blocks. Correct behaviour, now covered by a test.

### Checks actually run

- `npx tsc --noEmit` → exit 0. `npm run build` → exit 0. `npm run lint` → exit 0 (it caught a missing
  final newline introduced by the dead-code removal).
- `npx vitest run` → **280 tests, 12 files, all passing** (17 new consumer-record and template tests,
  plus the manual-requirement tests).
- `node dist/cli.js plan --stage pr` → 33 expected checks; `--stage release` → 55, including
  `OPS-02:manual_attestation:ops/restore-exercise:release`.
- `node dist/cli.js check` on the release plan → 40 results; no result is fabricated for a manual
  requirement.
- `node dist/cli.js gate` on that run → exit 1, blocked, with `manual.missing` and
  `policy.control_not_approved` among the reasons.
- A deliberately corrupted consumer (forged control ID, traversal reference, stale definition
  version) → `validate` exit 2 with `schema.invalid`, `path.outside_root`, and
  `semantic.version_conflict`.

### Remaining limitations after this pass

- Manual interval defaults are the policy-wide 30 days; per-control intervals and recipe-specific
  exercise windows are Step 14.
- Evidence-reference *existence* and digest checks are Step 14; only escape is rejected now.
- The `check` command still reports unimplemented recipes as `unsupported`. Scanner integration is
  Steps 06–11.
- All 35 controls remain `draft` with zero approvals, so release evaluation blocks on approvals in
  addition to the missing scanner coverage. That is intended.

---

## Batch A verification summary

| Check | Command | Result |
| --- | --- | --- |
| Install | `npm install --engine-strict=false --no-package-lock` | pass (pnpm acceptance **not** run — E1) |
| Type check | `npm run typecheck` | pass |
| Build | `npm run build` | pass |
| Hygiene lint | `npm run lint` | pass |
| Unit and domain tests | `npm test` | 280 tests, 12 files, pass (count grew during the completion pass) |
| Integration tests | `npm run test:integration` | pass, CLI run from outside the repository |
| Matrix generation | `npm run generate:matrix` | pass, byte-identical on rerun |
| CLI help/version | `node dist/cli.js help` / `version` | pass |
| CLI satisfied / blocked / invalid | `gate`, `report`, `validate` | exit 0 / 1 / 2 all demonstrated |
| Scanners | — | **none integrated; none run** |
| Application tests | — | **none exist** |
| Live / TLS / platform checks | — | **none exist** |
