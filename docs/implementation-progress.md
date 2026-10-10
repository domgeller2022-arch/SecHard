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
| E1 | ~~pnpm not installed~~ **RESOLVED 2026-10-06** | `pnpm --version` → 12.9.1 | — | pnpm installed under B14. `pnpm install --frozen-lockfile` verified; `pnpm-lock.yaml` committed |
| E2 | ~~Host runtime unsupported~~ **RESOLVED 2026-10-06** | `~/.local/opt/node-v24.21.0/bin/node --version` → v24.21.0 | — | Node 24.21.0 installed from the official tarball with a verified SHA-256. Full suite re-run on it; **all current results are on the supported runtime** |
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

### Step 06 — blocked sub-items resolved (owner granted runtimes + registries)

After the owner granted `agent_may_install_runtimes: true` and `network_access_to_registries: true`,
the blocked verification was completed. **This also resolves E1 and E2 from Batch A.**

- **State:** Step 06 is now `verified` in full. Scanner identity verification remains Step 09 work.
- **Files changed:** `pnpm-workspace.yaml` (new), `.npmrc` (rewritten), `package.json`,
  `pnpm-lock.yaml` (new), `policy/toolchain.yaml`, `docs/supported-versions.md`,
  `tests/execution/install-policy.test.ts`.
- **Actual checks run, with results:**
  - **Node 24.21.0 installed and verified.** Official `darwin-x64` tarball, SHA-256 checked against
    `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt` → `1462cb3b…e8097`, exact match. Extracted to
    `~/.local/opt/node-v24.21.0`. A version manager was not used because installing one means running
    an installer script; the tarball plus published digest is inspectable and verifiable.
  - **`pnpm install --frozen-lockfile` → exit 0, lockfile up to date.** It reports "Lockfile passes
    supply-chain policies". This is the Step 01 acceptance check that had been blocked since Batch A.
  - **`pnpm run build`, `pnpm run typecheck`, `pnpm run lint` → all pass on Node 24.21.0.**
  - **Full suite on Node 24.21.0: 338 unit tests + 8 integration tests, all passing.**
  - **Release-age policy verified against the real package manager.** `minimumReleaseAge: 10080`
    refused `nanoid@6.0.2` (published 18.5h earlier) with `ERR_PNPM_NO_MATURE_MATCHING_VERSION`,
    naming the publish time and cutoff, exit 1. An older package installed normally.
  - **Install-script default deny verified.** An unapproved hook **failed the install**
    (`ERR_PNPM_IGNORED_BUILDS`, exit 1) and did not run — verified with `core-js@3.37.1` and with a
    local tarball fixture carrying a postinstall script. `allowBuilds: { pkg: true }` ran the reviewed
    hook; `allowBuilds: { pkg: false }` recorded a denial without running it.
  - **`engineStrict` verified**: under Node 25 the install failed with
    `ERR_PNPM_UNSUPPORTED_ENGINE`; under Node 24.21.0 it succeeded.
  - **`strictPeerDependencies` verified**: the install failed with `ERR_PNPM_PEER_DEP_ISSUES` when
    `vitest`'s peer `vite` was undeclared.
- **Significant corrections found and applied:**
  1. **pnpm 12 does not read pnpm settings from `.npmrc`.** `minimumReleaseAge` in `.npmrc` (both
     `kebab-case` and `camelCase`) was silently ignored; `engine-strict` in `.npmrc` was ignored while
     `engineStrict` in `pnpm-workspace.yaml` was enforced. All pnpm settings now live in
     `pnpm-workspace.yaml`, and `.npmrc` is documented as npm-only.
  2. **`ignore-scripts=true` in `.npmrc` is ignored by pnpm.** It was previously described as the
     mechanism that blocks dependency hooks; that was untested and wrong. The real mechanism is
     `allowBuilds` default-deny, which is stronger: it fails the install rather than skipping quietly.
     `.npmrc`, `policy/toolchain.yaml`, and the tests were corrected.
  3. **The age policy immediately caught this repository's own dependencies.** `vitest@5.0.3` and
     `@types/node@26.6.4` were younger than 7 days, so the install was refused. Rather than take a
     package-wide age exemption — which the policy forbids — they were moved to the newest mature
     versions: `vitest@5.0.2` and `@types/node@24.19.0`. The latter also matches the Node 24 runtime
     better than the 26.x types originally chosen. `vite@8.3.1` was added as an explicit peer
     dependency because strict peer resolution requires it.
  4. **`minimumReleaseAge` accepts a range fallback.** With a caret range and no strict setting, pnpm
     silently resolved to the newest *mature* version (skipping an 18h-old release). Exact-version
     pinning plus `minimumReleaseAge` produces a hard refusal, which is what this repository relies on.
     The distinct effect of `minimumReleaseAgeStrict` was not isolated, so it is not set.
- **Limitations and unresolved findings:**
  - `minimumReleaseAgeExclude` is **package-wide, not version-specific**, so the exact-version
    exception in `policy/dependency-policy.yaml` cannot be expressed directly in pnpm. The
    compensating control is: pin the exact version in the manifest, add a temporary exclusion, and
    hold a policy exception with an expiry; the exclusion must be removed when the version matures or
    the exception expires. Recorded in the policy notes.
  - The live download path in `src/execution/download.ts` has still not been exercised against a real
    registry; it is tested against a local server. Step 09 exercises it for real when tools are
    downloaded.
- **Next step:** Step 09's scanner identity work is now unblocked; Steps 07–10 remain blocked on the
  container runtime.

### Step 09 — Implement the four scanner adapters

- **State:** `verified` for the adapter work; the app-integrated scan is `blocked` on Step 08.
- **Files changed:** `src/adapters/{types,gitleaks,zizmor,osv,opengrep,index}.ts`,
  `ci/configs/gitleaks.toml`, `ci/configs/opengrep-rules/hardening-core.yaml`,
  `tests/scanners/adapters.test.ts`, `tests/fixtures/scanners/**`, `policy/toolchain.yaml`,
  `policy/dependency-policy.yaml`, `tools/fetch-tools.mjs`, `src/execution/download.ts`.
- **Tools pinned with verified identities** (downloaded through the reviewed path: approved origin,
  approved redirect host, bounded size, SHA-256 verified):

  | Tool | Version | Provenance |
  | --- | --- | --- |
  | Gitleaks | 8.30.1 | Publisher checksums file **cross-checked** against the hosting API's release-asset digest |
  | OSV-Scanner | 2.6.0 | Publisher checksums file **cross-checked** against the release-asset digest |
  | Opengrep | 1.30.0 | Release-asset digest only (no checksums file published) |
  | zizmor | 1.30.1 | Release-asset digest only (no checksums file published) |

  Versions were confirmed by **running each binary**, not by reading a release page.
- **Actual checks run, with results:**
  - `npx vitest run tests/scanners` → **15 tests pass**, running the real binaries.
  - Gitleaks on the vulnerable fixture → 3 findings (`github-pat`, `slack-bot-token`,
    `private-key`); on the fixed fixture → 0.
  - zizmor on the vulnerable workflow → 4 findings (`dangerous-triggers`, `unpinned-uses`,
    `template-injection`, `artipacked`); on the fixed workflow → 0, exit 0.
  - OSV-Scanner on a lockfile pinning `lodash@4.17.15` → advisories found, one finding per advisory
    group with aliases collapsed and CVSS-derived severity.
  - Opengrep with the reviewed local rule pack → 3 findings on the vulnerable fixture
    (`no-eval` high, `child-process-exec-interpolation` high, `dom-innerhtml-assignment` medium);
    on the fixed fixture → 0.
  - **Master repository scanned for real**: Gitleaks over the repo with the product config → 0
    findings; Opengrep over `src` and `ci` (32 files) → 0 findings; zizmor → nothing to scan, because
    `.github/workflows` does not exist until Step 13. That gap is recorded rather than papered over.
  - Full suite: **357 unit + 8 integration tests, all passing** on Node 24.21.0 with pnpm.
- **Significant findings from running the tools, each fixed rather than worked around:**
  1. **The first real scan of this repository found 4 leaks** — 3 synthetic GitHub tokens in
     `tests/scanners/adapters.test.ts` and 1 in `tests/cli/cli.test.ts`. The synthetic values are now
     **composed at runtime** instead of committed as literals, so no secret-shaped string exists in
     the repository. Allowlisting the files was rejected: that would hide a future real leak in them.
     Re-scan: 0 findings.
  2. **The toolchain recorded the archive digest, not the executable digest.** The registry's own
     digest check caught it: gitleaks and zizmor are shipped as archives, and the extracted binary has
     a different SHA-256 from the tarball. The executable digest is now the pin, with the archive
     digest retained separately as provenance.
  3. **The adapter initially retained the raw report**, which meant an unredacted secret rode along
     inside the parsed outcome. Found by a test that serialises the outcome. The raw report is no
     longer held on the outcome at all; the runner hashes the report file instead.
  4. `ignore-scripts` was believed to be the install-script control; it is not (see the Step 06
     resolution above).
- **Coverage honesty, per tool:**
  - Gitleaks → **partial**. It reports bytes scanned and leak count, not the files examined, so a
    file-level coverage claim cannot be supported.
  - zizmor → complete when it names the audited files (it does).
  - Opengrep → complete when its reported scanned-file list matches the intended scope.
  - OSV-Scanner → **partial** unless the caller supplies the lockfile's package count, because
    "some packages checked" is not "the lockfile was covered".
  - **Initial history review run.** `gitleaks git .` over this repository's full history (13
    commits, ~918 KB) found **1 finding**: `generic-api-key` in `tests/cli/cli.test.ts`, in commit
    `5ac4a0b4`. The working tree is clean because the literal was removed in a later commit, but the
    history still contains it. **Assessment: the value was a synthetic, non-functional placeholder
    (`ghp_` followed by the sequential alphabet) that was never issued by any provider and never
    valid for any account.** There is nothing to rotate. It is left **visible and unresolved** rather
    than allowlisted, because allowlisting a token-shaped value in a scanner config is how a real
    leak gets missed later. Remediation options for the owner: rewrite the local history (not
    performed — it rewrites commit identities and was not authorised), or accept a narrow,
    documented allowlist for that exact value. Until one is chosen the master repository's own
    history scan will report this finding, which is the honest state.
- **Limitations and unresolved findings:**
  - **No app-integrated scan** (needs Step 08).
  - **No history scan yet.** Gitleaks' `git` mode over full history is a recipe for Step 13's CI and
    is not yet exercised; shallow clones would limit it, and that limitation must be recorded where it
    is used.
  - **Rules are syntactic.** Opengrep's local rules do not perform cross-file analysis, and the
    adapter says so. `--taint-intrafile` was not used.
  - **Opengrep's cosign `.sig`/`.cert` were not verified**; that needs cosign and is future work.
  - **No image or rule-pack digests beyond the local rule file**; the local pack is tracked in git, so
    its identity is the commit.
  - **Advisory data provenance is not yet recorded by the runner.** The adapter parses what it is
    given; `advisory_mode` and `advisory_provenance` are set by the runner when OSV is wired into a
    recipe. Until then, only the tests exercise them.
- **Next step:** Steps 07–08 for the application, or Step 10 once they exist. Both blocked on E3.

### Step 12 — Generate and protect agent guidance

- **State:** `verified`, with the tool-compatibility check `blocked` on an unfilled owner decision.
- **Files changed:** `agent-rules/core/rules.yaml`, `agent-rules/generated/{AGENTS.md,CLAUDE.md}`,
  `agent-rules/review-manifest.yaml`, `agent-rules/operator-requirements.md`,
  `src/agent/{generate,review-manifest,change-report}.ts`,
  `tools/{generate-agent-rules.ts,review-changes.mjs}`, `tests/agent/**`.
- **Actual checks run:**
  - `npx vitest run tests/agent` → **33 tests, 3 files, pass.**
  - `node tools/generate-agent-rules.ts` → generated both formats; re-running produced **byte-identical
    output** (no timestamp is embedded, so a diff means the source changed).
  - Merge protection exercised: a hand-written `AGENTS.md` was **refused** and left byte-identical,
    while a missing `CLAUDE.md` beside it was generated.
  - `node tools/review-changes.mjs 8ea01a0 c914316` over a real range → exit 1 and a report naming
    each sensitive-path change (scanner configs, policy, gate logic, lockfiles, tests).
  - Full suite: **390 unit + 8 integration tests, all passing** on Node 24.21.0.
- **Observed outcomes and evidence references:**
  - The rules source covers all seven required areas (authorized work, untrusted context,
    dependencies, secret boundaries, actual execution, preserved tests, unresolved findings) in 15
    rules, each `must` or `must_not` — there is deliberately no `should`, because an optional rule is
    an option the agent will take.
  - A test asserts the generated text contains **no permissive construction** (permission to skip or
    ignore, to simulate, "no need to run", "trust the tool", or any "optional"). A prohibition phrased
    as "never claim that a simulated check passed" passes; a permission would not.
  - Both formats state plainly that a prompt is not a permission boundary, and the operator document
    names filesystem, credential, network, and runtime restrictions with a **check** for each.
  - The review manifest validates: every entry names a real control (validation caught an invented
    `AGT-CTX-01` and it was corrected), states why review is required, and says what to check. A
    pattern matching everything is rejected, so the manifest cannot degrade into "review everything".
  - The change report detects a weakened test in a real temporary repository: removed case, added
    skip, removed assertion, added mock, and the sensitive-path change — and reports a docs-only
    change as clean. An unknown revision produces a limitation, not a clean result.
- **Limitations and unresolved findings:**
  - **Tool-compatibility verification is `blocked` on `coding_tool`.** The plan asks that generated
    files be checked against the selected tool's documented loading and precedence behaviour. That
    is unfilled in the owner decisions, so the generated headers say the behaviour is **not yet
    verified** and the expectation is stated as an expectation. No compatibility claim is made.
  - **The manifest is data, not enforcement.** It states what needs review; the platform enforces it.
    Wiring the manifest into required checks and CODEOWNERS is Step 13.
  - **The change report notices mechanics, not intent.** It cannot tell whether a removed assertion
    was wrong or inconvenient, and it says so in every report. Reformatting appears as removal plus
    addition.
  - **`review_status: draft`** on both the rules source and the manifest, pending owner review.
  - **Consumer files are protected from overwrite but not from drift**: the generator refuses a
    hand-edited file, so a consumer that hand-edits must merge deliberately rather than silently
    losing the generated rules.
- **Owner decisions or external setup still needed:** `coding_tool` (B15) to complete the
  compatibility check; owner review of the rules source.
- **Next step:** Step 11 remains blocked on the container runtime (ZAP needs Docker); Steps 13 and 14
  depend on it and on the GitHub test environment.

### Environment blocker E3 resolved — container runtime installed (2026-10-07)

- **State:** resolved and verified.
- **What was installed:** colima 0.10.3 (MIT) with lima 2.2.1 (Apache-2.0) and the docker CLI 29.8.2
  (Apache-2.0), via Homebrew, which verifies bottle checksums. **Docker Desktop was deliberately not
  used**: it is proprietary and carries a licence decision (paid subscription above a size threshold)
  that belongs to the owner. colima is a Docker-compatible runtime, so Supabase's Docker assumptions
  still hold.
- **Verification:** `colima start --cpu 2 --memory 4 --disk 20` completed; `docker info` reported
  server 29.5.2 with overlayfs and cgroup v2; `docker run --rm hello-world` ran a real container
  successfully.
- **Repair applied:** `~/.docker/config.json` contained `credsStore: "desktop"` left over from a
  removed Docker Desktop installation, which made every image pull fail with "executable not found".
  The key was removed after backing the file up beside it (`config.json.bak-20261008021956`);
  `auths` was empty, so no credential was affected. This repair is recorded because it is a change to
  a file outside this repository.
- **Recorded in:** `01-owner-decisions.md` (`docker_available: true`), `policy/toolchain.yaml`
  (`container_runtime`), `docs/supported-versions.md`.
- **Note for the operator:** colima was started manually for this session. `brew services start
  colima` makes it survive a reboot, at the owner's discretion.
- **Effect:** Steps 07, 08, 10, 11, and 14 are no longer blocked on the environment.

### Publication and session handoff (2026-10-08)

- **Published** at `https://github.com/domgeller2022-arch/SecHard` (commit `88df318`), on the owner's
  instruction. Public for the initial external audit, then private. Push permission recorded
  (`agent_may_push: true`).
- **Verified after pushing:** remote `main` and local `HEAD` are the same commit; 185 files; zero
  machine-output files; secret scan over committed content and history reports none; zizmor clean.
- **Two failed credential attempts preceded success, both instructive:** a token without the
  `workflow` scope (a PAT push creating `.github/workflows/**` requires it) and a fine-grained token
  without write access to the repository (a public repository is readable without being granted,
  which masks the missing permission until the push). The working credential is the owner's SSH key.

**For the next session — read in this order:** this file, then `docs/status.md` (generated from this
record; it replaced `docs/status-report.md` in Batch R), then `docs/checkpoints/batch-*.md`.

- **Batches A and B are complete. Batch C is complete except Step 13's platform half**, which needs
  the throwaway GitHub account the owner is creating at the end. **Batch D (Steps 15–16) has not
  started.**
- **An external audit by another tool is in progress.** Treat its findings as inputs to review, not
  as authority: this repository's rules on precedence and evidence still apply.
- **Next steps, in order:** Step 15 (independent consumer adoption), Step 16 (updater, scheduled
  checks, release notes, readiness summaries at 0.1.0), then Step 13's platform half when the test
  environment exists.
- **Open findings** are listed in `docs/status.md` (and the progress record); the ones that matter most are the binding
  finding (page 1), the six ZAP warnings on the example, and the unfilled owner decisions
  (`security_contact_email` in particular, which blocks OPS-03).

### Full audit (2026-10-08)

A verification pass over every claim in this record, run rather than remembered.

- **Repository:** 30 commits, tree clean, no uncommitted work.
- **Executable checks:** `typecheck` 0 errors; `build` succeeds; `lint` clean; **465 unit + 8
  integration tests pass**; scanner adapter suite 15 tests; live HTTP suite 17; client-asset suite 12;
  example application `next build` succeeds.
- **CLI:** `validate` passes on the consumer fixture (2 profiles, 35 controls, 2 assessments,
  1 exception); `approvals` reports 35 approved; a release gate **blocks** with 55 reasons —
  the behaviour is unchanged and correct.
- **Tool identities:** gitleaks, opengrep, osv-scanner, and zizmor all resolve with digests matching
  the binaries on disk; testssl is refused as unverified; ZAP is refused by the executable registry
  as `container_executed` (it is pinned as an image and run through the container runtime).
- **Generated artifacts:** `controls/matrix.md` and `agent-rules/generated/*` are current;
  regeneration produces no diff.
- **Self-scans:** zizmor over the workflows → 0 findings. Gitleaks in **git mode** (committed content
  and history) → **0 findings**.
- **Unfinished-work markers:** no TODO/FIXME/XXX/HACK in `src`, `controls`, `policy`, `profiles`,
  `schemas`, `agent-rules/core`, or `runbooks`.
- **Two findings from the audit itself, both fixed:**
  1. **The product secret scan was scoped by `dir`, so it scanned build output and local files.** A
     `dir` scan reported 14 findings: `examples/nextjs-supabase/.next/**` build artifacts,
     `.env.local` (gitignored, carrying the intended-publishable key), and **`tests/fixtures/build/`** —
     the fixture that deliberately contains a publishable key so the client-asset classifier can be
     shown to accept it. Those paths are not repository content, and findings nobody can act on are
     how a scanner stops being read. The product scan is now defined as **`gitleaks git`** (committed
     content and history), and the build fixture was added to the reviewed exclusion list alongside
     the scanner fixtures. Re-run: **0 findings**, while adapter verification still detects every
     fixture it is supposed to. The configuration now says which mode is the product scan and why.
  2. **`gitleaks dir` accepts a single path.** My first attempt passed several paths and silently
     scanned the whole tree instead, which is how the misleading counts appeared. Corrected usage
     verified: `dir src` → 0 findings.

### Step 14 — Manual evidence and operational recipes (2026-10-08)

- **State:** `verified` for the freshness rules, the exception rules, the local restore drill, and the
  runbooks. Hosted operational evidence remains `pending` by definition — it is a person's job to
  perform, and the records say so.
- **Files changed:** `src/domain/evaluator.ts`, `src/domain/types.ts`, `src/commands/run.ts`,
  `schemas/exception.schema.json`, `tests/failure-modes/failure-modes.test.ts`,
  `examples/nextjs-supabase/tests/operations/restore-exercise.sh`, `runbooks/**`.
- **Actual checks run:**
  - `npx vitest run tests/failure-modes` → **28 tests pass**, 8 of them new for this step.
  - `bash tests/operations/restore-exercise.sh` → **PASS**: backup, loss, restore, and verification
    of row count, per-owner distribution, and a run-specific marker row.
  - Full suite: **465 unit + 8 integration tests, all passing.**
- **Rules implemented, each with a test:**
  - **Per-control freshness.** The interval is the control's own where it declares one
    (`max_age_days` on its manual evidence requirement): 90 days for restore and response exercises
    and data review, 30 for access, credential, and configuration evidence. A 60-day-old restore
    drill is current for OPS-02 and **stale** for SEC-03 — asserted both ways. Policy defaults remain
    the fallback, with the longer exercise interval for restore/rollback recipes.
  - **Scope-bound reuse across source changes.** An operational fact survives an unrelated code
    change but not a storage migration. A record observed at a different source is reusable only when
    it also pins the configuration fingerprint; otherwise it is refused with
    `manual.reuse_without_scope`, rather than silently carried forward or demanding a fresh drill for
    every commit.
  - **Profile-permitted exceptions.** An exception for a control a profile marks `never` no longer
    applies — previously the profile's `permitted_exceptions` list was data nothing enforced. Now
    asserted, using AUTHZ-01 as the case.
  - **Definition-version invalidation.** An exception records the definition version it was granted
    against, and stops applying when the definition changes — the acceptance criteria it accepted are
    not the ones in force.
  - **Waivers are reported separately**, with the self-review flag preserved, never as a pass.
- **The restore drill found a real defect in my own procedure.** The first version loaded a data-only
  dump without replacing the target's rows and failed with a duplicate key: a data-only dump appended
  to existing data is an **append, not a restore**, and an operator following it would corrupt the
  database. The corrected procedure truncates first. The schema, grants, and policies are deliberately
  not in the backup: they come from versioned migrations, so a restore cannot silently reintroduce a
  drifted schema. The exercise also fails if the simulated loss did not actually remove the data,
  because a restore that proved nothing is worse than no exercise.
- **Runbooks written** for restore/rollback, credential rotation and revocation, incident response,
  and logging/alerting. Each names its controls, the steps, and the manual-evidence record to
  produce, and each states that a runbook is a procedure rather than evidence.
- **Limitations and unresolved findings:**
  - **Hosted operational evidence is `pending`**, as it must be: no deployment exists, and five
    controls (OPS-01, OPS-02, OPS-03, SEC-03, PRIV-01) cannot pass until a person performs and
    records the work.
  - **OPS-03 is blocked by an unfilled owner decision**: there is no security contact, so there is no
    report channel. Recorded rather than worked around.
  - The local recovery time (under a second) is meaningless as a recovery target; only the hosted
    measurement counts.
  - **Exception scope precision** still requires either a check, finding, rule, or a control plus an
    environment. That is unchanged and deliberate.

### Step 11 — Guarded live application recipes (2026-10-08)

- **State:** `verified` for the approved-target model, the HTTP recipe, and the passive ZAP baseline
  against a controlled local target. Deeper TLS assessment remains manual evidence, and the tool for
  it is deliberately not claimed.
- **Files added:** `schemas/live-targets.schema.json`, `examples/nextjs-supabase/.hardening/targets.yaml`,
  `src/adapters/http.ts`, `tools/run-live-checks.mjs`, `tests/live/http.test.ts`,
  `docs/live-checks.md`; the app's `next.config.ts` gained route-appropriate headers, and
  `app/auth/callback/route.ts` was changed to stop deriving redirects from the Host header.
- **Actual checks run:**
  - `npx vitest run tests/live` → **17 tests pass** against a local server made to break in each of
    the ways the recipe exists to catch.
  - `node tools/run-live-checks.mjs … local` against the running application → **3/3 routes observed,
    coverage complete**; the first run reported **2 findings**, both fixed or configured, and the
    final run reports **0**.
  - ZAP passive baseline against the controlled local target → **60 passes, 7 warnings, 0 failures**,
    report captured with SHA-256 `b35b5784a250e49a…` (ZAP 2.17.0, image digest
    `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`).
  - An integration assertion now requires a release plan to contain a TLS transport check and that
    check to be `unsupported`, so **production evaluation blocks while TLS evidence is missing**.
  - Full suite: **457 unit + 8 integration tests, all passing.**
- **Findings from running it, each handled rather than smoothed over:**
  1. **The first live run found a real design issue.** `/auth/callback` built its redirect from
     `new URL(request.url).origin` — the **Host header**. That is the classic host-header open
     redirect. The route now requires a configured `APP_ORIGIN` and returns 500 if it is unset. The
     inventory was **not** widened to make the finding disappear; the same-origin redirects that are
     genuinely expected were then named explicitly.
  2. **The app set no security headers at all.** The recipe would have reported them missing, so the
     application now sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and
     `Permissions-Policy`. HSTS is deliberately absent locally: claiming transport security from a
     plain-HTTP server would be a lie the check exists to prevent.
  3. **ZAP's image could not write its report.** The image runs as uid 1000 while `/zap/wrk` is owned
     by root, and the macOS bind-mount share refuses the container's writes. Writing into a Docker
     volume as root and copying the report out works; the working invocation and the reason are in
     `docs/live-checks.md`. Four attempts were required, and the detail is recorded so nobody repeats
     them.
  4. **ZAP found six real gaps in the application**, recorded as unresolved: missing CSP (4
     instances), absent anti-CSRF tokens, missing COEP/COOP/CORP headers, and `X-Powered-By`
     disclosing server information. A CSP for this application needs script nonces; adding a broken
     header to close a warning would be worse than the warning. The CSRF result reflects that
     mutations are Server Actions — a design fact to assess, not a defect to fix blindly.
- **Boundaries stated rather than implied:**
  - Requests are **anonymous**. An authenticated requirement cannot be met by this recipe.
  - TLS: a successful HTTPS request means Node validated the chain and expiry. Protocol versions,
    ciphers, and configuration depth are **not** assessed; `testssl.sh` is recorded as unverified and
    that work remains manual evidence. A production transport requirement cannot be satisfied by the
    local plain-HTTP target.
  - ZAP is **passive baseline only**: no active attacks, no authenticated crawling, no business-logic
    testing. Active scanning belongs in controlled staging and is an extension point, not something
    implemented here.
  - **Incomplete coverage is not a pass**: an unreachable route exits non-zero and reports `partial`;
    a run that observed nothing reports `unknown`.
- **Limitations and unresolved findings:** the ZAP warnings above are open; no active or authenticated
  scanning exists; `testssl.sh` is unpinned; the binding finding remains open; QUAL-01 thresholds
  remain unconfigured.

### Step 10 — Build verification and the client secret boundary (2026-10-07)

- **State:** `verified`.
- **Files added:** `src/build/client-assets.ts`, `tests/build/client-assets.test.ts`,
  `tests/fixtures/build/{clean,leaking}/**`, `tools/inspect-build.mjs`, root `package.json` script
  `inspect:build`; `.gitignore` entry for generated build evidence.
- **Actual checks run:**
  - `npx vitest run tests/build` → **12 tests pass.**
  - `node tools/inspect-build.mjs` against the real production build → **11 files, 575 574 bytes,
    inventory digest `8037be58…`, zero findings, zero source maps, coverage `complete`**, exit 0.
  - The application's build runs clean: `next build` succeeds, `tsc --noEmit` passes, and the
    browser bundle contains **no Supabase key of any kind**.
  - Full suite: **440 unit + 8 integration tests, all passing.**
- **What the inspection establishes, and how:**
  - **The fixture proves detection.** A clean fixture containing a publishable key passes and the key
    is *classified*, not flagged; a leaking fixture containing a synthetic privileged marker and a
    browser source map **fails** with a critical and a medium finding respectively. A check that
    cannot see its own fixture has never been shown to work.
  - **The real build is clean**: no privileged marker, no `sb_secret_`, no service-role literal, no
    private key, no source map.
  - **Stronger than expected:** the publishable key does not appear in the browser bundle at all,
    because every Supabase operation in this application is server-side. That is verified rather than
    assumed, and the classification path is still exercised by the clean fixture.
  - **Coverage is stated, never implied**: the report names the directory inspected and says in the
    same sentence that server output, deployment configuration, and other artifacts are outside the
    scan. A test asserts the scope statement contains both halves, and another asserts that no
    `server/` file appears in the inventory.
  - **Identity is connected**: `tools/inspect-build.mjs` records source commit and dirtiness, policy
    commit and catalogue digest, the artifact inventory digest, and the inspection result in one
    record; it **re-reads the source identity after inspection and fails the run if the source moved
    underneath it**, because evidence for a source that no longer exists is not evidence.
  - **Quality is reported separately from security**: file counts, total bytes, and the largest files
    are recorded as quality information with **no threshold applied**, because a bundle-size limit
    that fails a build is a policy decision nobody has made yet.
- **Limitations and unresolved findings:**
  - **QUAL-01's configured thresholds are still outstanding.** The plan's Step 10 asks for "configured
    quality thresholds"; none are configured. `next build` type-checks, root `lint` checks hygiene,
    and bundle size is reported without a limit. Recorded rather than implied.
  - **The inspection covers browser output only.** Server output, source maps in server builds,
    deployment configuration, and environment separation are not inspected here; Step 11's live
    recipes and Step 14's operational evidence cover the deployed side.
  - An **artifact digest exists for the inspected inventory only.** There is no packaged artifact for
    a source deployment, so no single digest is presented as covering the deployment.
  - The **binding finding** remains open.

### Step 08 — authorization matrix verified, with detection proven (2026-10-07)

- **State:** `verified` for the matrix, the provider-path cases, the inventory checks, and the
  mutation test. Recovery isolation and genuine session expiry remain outstanding (below).
- **Files added:** `examples/nextjs-supabase/tests/authorization/matrix.yaml`,
  `.../run-authorization.mjs`, `.../weakened-detection.sh`; example `package.json` scripts;
  example `README.md` section.
- **Actual checks run — all against the real stack, none mocked:**
  - `pnpm run test:authorization` → **14 cases executed, 0 failed**, plus **4 inventory checks**.
  - `pnpm run test:authorization:weakened` → **detection proven**: with one extra permissive SELECT
    policy the matrix reported failures; after `supabase db reset` the same matrix passed again.
  - Full suite unaffected: **428 unit + 8 integration tests**; lint green.
- **What the matrix covers** (machine-readable data, not code): anonymous, owner A, and unrelated
  user B; list, read, create, update, and delete; a manipulated identifier (reading and writing a row
  by another user's ID); owner-field injection on both create and update; and an invalid session.
  Positive cases are included — a policy that denies everybody would fail them.
- **Denials are verified against stored state**, read afterwards through a privileged `psql`
  channel: the stored title, owner, and existence of the target row are asserted unchanged or absent
  as appropriate. This is the plan's requirement that an HTTP denial alone is not evidence.
- **Findings from running it, recorded rather than smoothed over:**
  1. **Anonymous is refused at the grant layer, not given an empty result.** The request returns
     HTTP 401 with PostgREST code **42501 (insufficient_privilege)**, because the migration revokes
     all grants from `anon`. My first expectation was "0 rows"; the actual behaviour is stronger, and
     the matrix now records the verified behaviour with the reason.
  2. **An invalid token is refused with PGRST301**, distinct from anonymous — so a malformed session
     is not silently downgraded to unauthenticated.
  3. **Owner-field injection fails with 42501 on both create and update** — a client cannot write as
     another user, and cannot move an existing note to another owner.
  4. **The inventory check caught my own comparison bug**: `pg_class` booleans concatenate as
     `true/true`, not `t/t`. Fixed; the check now asserts RLS is both **enabled and forced**, exactly
     one policy exists, it targets `authenticated` only, and `anon` holds no table grant.
  5. A URL-encoding bug in my runner (`URL.pathname` percent-encodes spaces) was fixed to
     `fileURLToPath`.
- **Case counting is enforced:** the runner exits non-zero if the number of executed cases differs
  from the number declared, so a case that silently stops running is a failure rather than an
  absence of failure.
- **Limitations and unresolved findings:**
  - **Recovery isolation (AUTH-02) is not tested.** It needs the email flow; it belongs with the
    operational recipes in Step 14.
  - **Genuine session expiry is not tested** — only a malformed token. Expiry needs a short-lived
    token or a clock we control; the provider's revocation behaviour is also unverified.
  - **The app-path matrix is the Playwright suite**, which covers ownership, sign-out, and cross-user
    cache separation through the interface; the direct-API matrix covers the provider path. Role and
    tenancy cases do not apply: both features are disabled in the manifest, and AUTHZ-02 is recorded
    as such rather than marked satisfied.
  - **QUAL-01's configured thresholds remain outstanding** for the example.
  - The **binding finding** remains open; the stack was started only for these checks and is stopped.

### Step 07 — reference application built and verified end to end (2026-10-07)

- **State:** `verified` for the application and its functional behaviour, with the binding finding
  below still open on its own criterion.
- **Files added:** `examples/nextjs-supabase/app/**` (layout, landing page, notes page, Server
  Actions, auth callback route), `lib/supabase/{server,middleware}.ts`, `middleware.ts`,
  `next.config.ts`, `tsconfig.json`, `.env.example`, `e2e/notes.spec.ts`, `playwright.config.ts`,
  `tools/sync-example-env.mjs`; `package.json` completed.
- **Pinned versions:** Next 16.3.7, React and React DOM 19.3.0, `@supabase/ssr` 0.12.7,
  `@supabase/supabase-js` 2.117.2, Playwright 1.63.0 — all mature under the seven-day release-age
  policy, which applies to the example because it is a workspace package.
- **Actual checks run:**
  - `next build` → **success**, with routes `/`, `/notes`, `/auth/callback` and middleware.
  - `pnpm exec playwright test` → **7 tests, all passing in 15.4s**, against a production build
    (`next start`), with the real Supabase stack running. Playwright is configured with **one
    worker, no retries**, because a security assertion that passes on the second attempt is a flaky
    assertion.
  - Root suite after the change: **428 unit + 8 integration tests, all passing**; `pnpm run lint`
    green once Playwright's generated `test-results/` was ignored.
- **What the browser tests actually prove:**
  - **Anonymous** visiting `/notes` is redirected to the sign-in form, and **the private content is
    never sent** — asserted by absence, not by visibility.
  - **User A sees A's note and never B's**; **user B sees B's and never A's** — through the real
    interface, real cookies, real Server Actions, and real row-level security.
  - **Sign out, then sign in as the other user, does not leak the previous user's notes** — the
    cache/session-separation case.
  - **Owner positive flow**: create, rename, and delete all work. This matters because a policy that
    denies everybody would pass the negative tests and fail these.
  - The notes response is **not publicly cacheable** (`cache-control` carries no `public` and no
    positive `s-maxage`).
- **Security decisions recorded in the code:**
  - The server client acts **as the signed-in user** from the request cookies; the application never
    uses the secret key, so no request path reaches around row-level security. Seeding uses a
    privileged connection.
  - The middleware uses **`getUser()`, not `getSession()`** — the latter reads a cookie the client
    could have written. It is documented as a convenience for the interface, not the boundary.
  - The query for a user's notes has **no `owner_id` filter**, deliberately: the policy decides, and a
    second weaker filter in application code could drift from it and give false assurance.
  - The auth callback validates its `next` parameter against a fixed set of internal paths, because
    redirecting to an arbitrary query value is the classic open-redirect mistake.
  - `productionBrowserSourceMaps` is left off, which is what SEC-02's build check will inspect.
- **Limitations and unresolved findings:**
  - **No recovery-flow test yet.** AUTH-02's recovery isolation needs the email flow; local mail is
    captured by the stack's SMTP service and the flow is exercised in Step 14's operational work.
  - **No manipulated-ID or direct-API bypass test through the app yet** — those are Step 08's matrix;
    the database-level equivalents were verified with psql, and the app-level ones need the matrix.
  - **QUAL-01's configured thresholds are not in place.** `next build` type-checks the application,
    and the root `lint` checks hygiene, but no linter or duplication/complexity threshold is
    configured for the example. Recorded as outstanding rather than implied complete.
  - The **binding finding** above remains open; the stack was run only for these tests and is stopped.

### Standards and upstream resources incorporated (2026-10-07)

- **State:** `verified` for the records and the consistency tests.
- **What the blueprint says, and how that was applied.** Blueprint section 3 states plainly that its
  standards and tools tables are **research background, not tasks**, and the plan fixes a small v1
  toolchain ("Do not build a general security platform or adopt every available scanner"). So
  incorporation was done as: every standard and candidate tool recorded with a canonical URL,
  edition, licence, support status, and review date; every framework cited by a control mapping
  pinned to a recorded edition; and everything not adopted recorded **with a reason** rather than
  left absent.
- **Files changed:** `upstream/sources.yaml` (4 → 35 records), `controls/mappings/standards.yaml`
  (6 → 10 editions and a `not_referenced` list), `docs/standards.md` (new),
  `tests/domain/standards.test.ts` (new), `schemas/source.schema.json` (two integrity-method values
  added), `src/domain/definitions.ts`, `controls/matrix.md` (regenerated).
- **Actual checks run:**
  - Fetched and checked **20 standard and guidance URLs** on 2026-10-07: each returned HTTP 200 with
    a title confirming the edition (for example "OWASP Top 10:2025", "SP 800-218 … Version 1.1",
    "SLSA specification", "WSTG - v4.2", "RFC 9700: Best Current Practice for OAuth 2.0 Security").
  - Checked **15 repository licences via the GitHub API**, including CodeGuard's, whose `LICENSE.md`
    was fetched directly and confirms **CC-BY-4.0** exactly as the blueprint states.
  - `npx vitest run tests/domain` → **91 tests pass**, including the new standards suite which asserts
    that every cited framework has a recorded edition and source, that no mapping claims
    `verified_coverage`, that the out-of-scope standards carry a reason, and that only tools the
    toolchain actually invokes may claim `invoking` + `verified`.
  - Full suite: **428 unit + 8 integration tests, all passing.**
- **Findings recorded honestly rather than smoothed over:**
  - **ASVS uses a moving `latest` release tag** (published 2026-09-03), so the numbered edition from
    the blueprint (5.0.0) is recorded as *intended* and not re-verified against a tag. The entry says
    so, and the plan's rule — leave unreviewed mappings visibly unverified — is applied.
  - **AISVS has no published release**, so no stable edition can be pinned; it is recorded as
    `unsupported` for v1 because runtime AI is excluded.
  - **MCP Top 10 is non-commercial share-alike**; only a link is recorded and nothing is adapted, with
    the constraint stated in the entry.
  - **TruffleHog is AGPL-3.0**, which is materially different from invoking a permissive tool, so it
    is recorded as a candidate needing its own review rather than adopted.
  - **No mapping claims `verified_coverage`.** No application has been assessed against ASVS or any
    other standard, so the catalogue describes intended coverage only. This is asserted by a test.
- **Deliberately not adopted, with reasons in `controls/mappings/standards.yaml`:** SLSA 1.2,
  AISVS, LLM Top 10, Agentic Top 10, MCP Top 10, MASVS, Electron security. Candidate tools recorded
  as reviewed-but-not-adopted: TruffleHog, CodeQL, harden-runner, Scorecard, Syft, Grype, Checkov,
  Claude Code security review, and the comparison checklists.

### Firewall verification — the LAN finding is narrowed, not closed (2026-10-07)

The owner enabled the macOS application firewall. Verified state:

- `--getglobalstate` → **enabled**; `--getstealthmode` → **on**. Both applied successfully.
- `--getappblocked /usr/local/opt/lima/bin/limactl` → **"Incoming connection … is permitted"**: the
  explicit block rule did not take effect. `limactl` is only **ad-hoc signed** (`codesign` reports
  `flags=0x2(adhoc)`), so it is not covered by the "allow signed software" policy and relies on the
  firewall's default treatment.
- **Tested from a genuinely separate host**: the colima VM. With the stack running, a request from
  inside the VM to the host's forwarded port returned **200**, both via the host's LAN address and
  via the VM-network gateway. The macOS firewall does not filter traffic arriving over the VM's
  network interface.
- **Therefore:** the exposure is narrowed for traffic arriving on the physical interface (default
  block for an ad-hoc-signed listener), but it is **not verifiably contained**, and I cannot test the
  physical LAN without a second physical device. Step 07's "bind to appropriate local interfaces"
  criterion remains **not verifiably met**; it is recorded as such rather than marked fixed.
- **Corrected commands for the owner** (the third command needs the application added first):
  `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/opt/lima/bin/limactl` then
  `--blockapp /usr/local/opt/lima/bin/limactl`; verify with `--getappblocked`, which should report
  blocked. Even then, the VM-network path may remain unfiltered, which is why the practical operating
  rule is: **the stack runs only while developing and is stopped afterwards** (it is stopped now, and
  the ports are closed).
- **For the final report:** this remains an open finding with two honest options — contain it further
  (firewall rule plus possibly a pf rule) or record local-network trust as an explicit accepted risk.

### GitHub test environment deferred to the final step (2026-10-07)

The owner will create the throwaway account and repositories and provide them at the end. Both
`github_test_owner` and `github_test_repos` carry that instruction in `01-owner-decisions.md`.
Step 13's platform verification stays `awaiting_external_verification` until then. Exact setup steps
are recorded in `docs/ci-trust.md`.

### Step 07/08 — reference application: records and row-level security (2026-10-07)

- **State:** `in_progress`. The database layer of Steps 07 and 08 is implemented and **verified by
  execution against the real stack**. The Next.js application itself is not written.
- **Files added:** `examples/nextjs-supabase/.hardening/app.yaml`,
  `examples/nextjs-supabase/supabase/migrations/20261007000001_notes.sql`,
  `examples/nextjs-supabase/supabase/seed.sql`, `examples/nextjs-supabase/README.md`,
  `tools/relink-example.mjs`, `tests/global-setup.ts` (re-links the example before the suite).
- **Actual checks run — the first real authorization evidence in this repository:**
  - `supabase db reset` → migration applied, seed loaded, containers restarted.
  - **As user A** (`set local role authenticated` with A's JWT subject): visible notes = **1** (A's
    own), other users' notes visible = **0**.
  - **As user B**: visible = **1**, other users' notes = **0**.
  - **A attempting to update B's note** → `UPDATE 0`. The note's title was then read back with a
    privileged connection and is **unchanged** ("User B private note"). The denial is verified against
    stored state, not just against a status code.
  - **A attempting to insert a note with `owner_id` = B** → `ERROR: new row violates row-level
    security policy for table "notes"`. Client-supplied ownership cannot be injected.
  - **Anonymous** → `ERROR: permission denied for table notes`. Grants are revoked as well as
    policies applied, so anonymity fails at the grant layer.
  - Full suite after these changes: **418 unit + 8 integration tests, all passing.**
- **Design decisions recorded in the migration:**
  - `owner_id` defaults to `auth.uid()` and the policy's `WITH CHECK` enforces it, so ownership is set
    by the session and cannot be reassigned by a client.
  - `force row level security` is set as well as `enable`, so the table owner does not silently bypass
    the policy.
  - Grants and policies are stated separately: a policy cannot grant access that was never granted,
    and a grant without a policy would expose the table.
  - Seeding runs as a privileged role and is separate from the unprivileged clients used for
    assertions. The seeded password is a local-development value against the `.invalid` TLD.
- **Flakiness observed, recorded rather than hidden:** one run of the Opengrep scanner test failed at
  30.7s while the Supabase VM was compiling containers; the same test passed in 15.6s on an idle
  machine and the full suite is green. The cause is resource contention, not a logic change. Not
  retried automatically; noted here as the plan requires.
- **Open finding (unchanged):** the LAN binding finding above. The macOS application firewall is
  **disabled** on this machine and `sudo` requires a password, so the recommended containment cannot
  be applied by the agent. Exact commands are in `examples/nextjs-supabase/README.md`. The stack is
  **stopped**; the ports are closed.

### Owner decisions actioned — CODEOWNERS and the GitHub test environment (2026-10-07)

- `github_codeowners: domgeller2022-arch`, `github_owner: domgeller2022-arch` (inferred from the
  owner's statement that this single account has sole access), `repo_visibility: private`.
- `.github/CODEOWNERS` created. Every sensitive path from the review manifest is covered, the file
  protects itself via `/.github/`, and a trust test now asserts: it exists, contains no placeholder,
  every handle is a valid username shape, and the handles match `github_codeowners` exactly — so the
  file cannot silently name nobody while looking like protection.
- `docs/ci-trust.md` gained the exact GitHub test environment setup steps (separate owner, disposable
  repositories, fine-grained token scopes, short expiry, environment-only handling) and the two
  documented limits: a fine-grained token has one resource owner, and merge queues need an
  organisation.

### Step 07 — Secure local reference application (in progress; infrastructure proven)

- **State:** `in_progress`. The local stack runs; the application itself is not built yet. One
  verified security finding is open against this step's acceptance criteria.
- **Files changed so far:** `pnpm-workspace.yaml` (the example is a workspace package so the reviewed
  dependency policy applies to it), `examples/nextjs-supabase/package.json`,
  `examples/nextjs-supabase/supabase/config.toml`, `examples/nextjs-supabase/supabase/.gitignore`,
  `examples/nextjs-supabase/supabase/.temp/` (ignored).
- **Actual checks run:**
  - `supabase --version` → 2.118.0 (pinned devDependency, mature at 12 days).
  - `supabase init` → generated `supabase/config.toml`.
  - `supabase start` (first attempt) → the stack pulled and ran, then **tore itself down** because
    three optional containers reported unhealthy: `analytics`, `vector`, `realtime`.
  - Disabled `realtime` and `analytics` in the example's `config.toml` — the reference app does not
    use them — and removed the need for a CLI flag. `supabase start` then completed:
    **"Started supabase local development setup."** Postgres on `127.0.0.1:54322`, data API on
    `127.0.0.1:54321`, and the CLI reported the new-style `sb_publishable_…` and `sb_secret_…` keys.
  - Runtime is colima (installed earlier this session); `supabase stop` and `start` were exercised.
- **Verified security finding, open:**
  - **The local stack is reachable from the local network.** `lsof` shows the port forwarder
    (`limactl`, formerly `ssh`) listening on `*` for 54321–54324, and
    a request to the machine's LAN address on the forwarded port returned **200** — the same response as loopback. The address is withheld from this record because the repository is published; the finding and its evidence do not depend on it.
  - The Supabase CLI's own output warns: "All services bind to 0.0.0.0 (network-accessible, not just
    localhost)" and "API keys and JWT secrets are shared defaults."
  - **Step 07's acceptance criteria require disposable development services to be bound to
    appropriate local interfaces. This is not satisfied**, so Step 07 cannot be called verified while
    it holds.
  - Attempted mitigation: restarting colima with `--port-forwarder grpc` did not change the bind —
    `limactl` still listens on `*`. Neither colima 0.10.3 nor Supabase CLI 2.118.0 exposes a
    loopback-only switch in the tested versions; the `host` field that config.toml documents for some
    other sections has no counterpart for the API or database services.
  - Mitigations available to the owner (in order of preference): enable the macOS application
    firewall and block incoming connections for the forwarder; run the local stack only while
    developing and never on an untrusted network; or treat the developer machine's network as part of
    the trust boundary for local development. **The third option is not a security control and is
    recorded only so the choice is explicit.**
  - Consequence for later steps: Step 11's live checks must not assume a loopback-only development
    environment, and `DEPLOY-01` evidence must record what was actually bound.
- **Limitations and unresolved findings:**
  - The application (Next.js), its manifest, migrations, RLS policies, and functional tests are not
    written yet.
  - The stack is running with syntactically default credentials, which the CLI itself flags as
    unsuitable for anything but local development. They are not secrets of value; they are recorded
    here because they exist.
- **Next step:** resolve or accept the binding finding, then build the application and migrations.

### Owner decisions actioned (2026-10-07)

- **`coding_tool`: opencode (primary), Claude Code and Codex available.** Step 12's compatibility
  check is now **verified for the primary tool**. Fetched `https://opencode.ai/docs/rules/` on
  2026-10-07. The documented behaviour that matters: opencode reads local rule files by traversing up
  from the working directory and **uses the first match in each category, preferring `AGENTS.md` over
  `CLAUDE.md`**. The generated notes now state this as verified fact with the source and date, and a
  test prevents the claim from regressing. Implication recorded: for opencode, `AGENTS.md` is the file
  that takes effect; `CLAUDE.md` exists for Claude Code, and both are generated from the same source
  so they cannot diverge.
- **All 35 control definitions approved by the owner.** `controls/approvals.yaml` now holds 35
  records naming each definition's reviewed-content digest; `review_status` in the definitions is
  `owner_reviewed` with `reviewed_by: "owner"` and the date. `kind: owner` records **self-review**
  (sole maintainer); `owner_legal_name` is still unfilled, so the reviewer field names the role
  rather than a person, and that is stated in each record's notes.
  - Verified: `hardening approvals --policy .` shows 35 approved; a release gate now produces **0**
    `policy.control_not_approved` reasons (it previously produced one per applicable control) and
    still blocks on the real remaining gaps.
  - The generated matrix and review sheet were updated; the review sheet now reports
    "0 draft, 35 owner-reviewed" from the live catalogue rather than asserting a fixed state.
- **Git history rewritten to purge synthetic credential-shaped literals.** The owner chose a rewrite.
  `git filter-branch` replaced both committed literals (the GitHub-token placeholder and a synthetic
  JWT) with explicit `REMOVED_FROM_HISTORY` markers across every commit, then the original refs and
  unreachable objects were expired and pruned. **Verification: `gitleaks git .` over the full history
  reports 0 findings**, down from 1. A full `.git` backup was taken outside the repository before the
  rewrite (`.../T/opencode/git-backup-prehistory-20261008024854`, 1.8 MB); the owner may delete it.
  - Consequence recorded: **commit SHAs referenced in earlier checkpoint and progress entries refer
    to pre-rewrite commits** and no longer resolve. The records are historical and were not rewritten;
    this note is the pointer.
  - All 414 unit + 8 integration tests pass after the rewrite.
- **`docker_available: true`** — colima runtime installed and verified (see the E3 entry above).
- **`github_codeowners` remains unfilled**, at the owner's request for an explanation; CODEOWNERS
  stays absent and the template is in place. Explained in the checkpoint.

### Step 13 — GitHub workflows and the trusted final gate (local half)

- **State:** `awaiting_external_verification`. The workflows, trust tests, and documentation are
  implemented and locally verified; **no platform behaviour has been observed**, because the GitHub
  test environment is unfilled (`github_test_owner`, `github_test_repos` are `TODO`) and no token is
  available.
- **Files changed:** `.github/workflows/{repo-checks,hardening-pr,hardening-release}.yaml`,
  `templates/{consumer-workflow.template.yaml,CODEOWNERS.template}`, `docs/ci-trust.md`,
  `tests/workflows/trust.test.ts`.
- **Actual checks run:**
  - `npx vitest run tests/workflows` → **23 tests pass**, including a real zizmor run.
  - **zizmor over `.github/workflows` initially reported 3 high-severity `template-injection`
    findings in my own workflows** — `${{ }}` interpolated directly into `run:` scripts. All three
    were fixed by passing values through `env:`; a re-scan reports **0 findings**.
  - Action pins are real commit SHAs resolved from the GitHub API, with the release version named in
    a comment next to each pin.
  - Full suite: **413 unit + 8 integration tests, all passing**.
- **Observed outcomes and evidence references:**
  - Every action is pinned to a full SHA; no workflow grants a write permission; `pull_request_target`
    is not used; every checkout disables credential persistence; every `run:` script is free of
    template interpolation.
  - Both callable workflows require a `hardening_ref` input, and the consumer template pins both the
    called workflow and the policy ref to the same commit placeholder. The CLI refuses to plan when
    the policy lock and the supplied policy root disagree, so a caller cannot evaluate against a
    different policy than the one that was reviewed.
  - The final `hardening-gate` job depends on every other job and runs `if: always()`, then fails when
    any dependency result is not `success` — because GitHub reports a skipped job as successful.
  - `.github/CODEOWNERS` is deliberately **absent** while `github_codeowners` is unfilled, with a
    template instead. A file naming a display name matches nobody, and GitHub skips invalid lines, so
    a fabricated file would look like protection while providing none. A test enforces both halves.
- **Limitations and unresolved findings:**
  - **No platform verification.** Required checks, review rules, CODEOWNERS resolution, bypass
    identities, fork behaviour, and merge-queue behaviour are all unverified. `docs/ci-trust.md`
    states this and lists the settings the owner must configure.
  - **The trust limit is inherent**: a maintainer who can replace workflows or policy, or who can
    bypass checks, can defeat the gate. It is documented rather than papered over.
  - **Merge queues are outside the supported set** for a disposable personal-account test repository,
    because GitHub does not offer queues there.
  - The workflows assume a `linux` runner and the pinned Node 24.21.0; they have not been run on
    GitHub's runners.
- **Owner decisions or external setup still needed:** `github_test_owner`, `github_test_repos`,
  `github_codeowners`, `github_owner`; the token from `github_test_token_env_var` when Batch C/D
  platform testing is authorised.
- **Next step:** Step 11 and Step 14 remain blocked on the container runtime and on the application.

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

---

## Batch R — Repair (remediation plan, 2026-10-08)

**Authorisation.** `authorised_batch: R` in `01-owner-decisions.md`, set on the owner's instruction
to work the remediation plan. The owner's clarified goals (audit-report section 0) were recorded in
the owner decisions before R started. The remediation plan's audit-mode batch is called **U** here,
renamed from the plan's "A" to avoid colliding with the original Batch A.

**Scope.** `docs/audit/2026-10-08-remediation-plan.md` Batch R: R1 toolchain, R2 CI, R3 fail-closed
workflows, R4 exceptions, R5 report safety, R6 documentation truth, R7 owner hygiene. The gap
analysis in `docs/audit/2026-10-08-remediation-gap-analysis.md` identified items the plan missed;
the batch-R ones were implemented here (M5 filtered installs, C1/C3 dead policy data, C2/C3
evaluator aggregation, C5 console redaction, E1 plan/results artefacts).

- **State:** `verified` for R1–R6, with R3's GitHub-side acceptance and all R7 owner items pending.
  Batch R was committed (`bc0da96`) and pushed to `origin/main` over the owner's SSH key. A GitHub
  Actions run cannot be observed from this machine: the repository has been made **private** (as the
  owner planned after the public audit), and the unauthenticated Actions API returns 404. No token
  under `github_test_token_env_var` exists, so "repo-checks green on GitHub" remains
  `awaiting_external_verification` rather than claimed. The owner can see the run in the repository's
  Actions tab; the acceptance is a green `repo-checks` on this commit.
- **Files changed:** `policy/toolchain.yaml` (per-platform records), `tools/fetch-tools.mjs`
  (platform-aware, reviewed-digest-first, token-aware), `src/execution/registry.ts`
  (platform resolution, `unsupported_platform`), `src/commands/io.ts`,
  `src/agent/review-manifest.ts` (git candidates); `src/commands/run.ts` (check exit codes,
  console/report safety, waived section), `src/commands/check.ts` (title redaction),
  `src/domain/evaluator.ts` (H1–H3, per-control aggregation), `src/domain/types.ts`,
  `policy/gate-policy.yaml` (exceptions block), `schemas/exception.schema.json`;
  `.github/workflows/repo-checks.yaml`, `hardening-pr.yaml`, `hardening-release.yaml`;
  `tsconfig.json`, `tsconfig.tools.json`, `package.json`;
  `tools/relink-example.mjs`, `tools/generate-status.mjs`,
  `examples/nextjs-supabase/.hardening/app.template.yaml`, `.gitignore`;
  `README.md`, `docs/ci-trust.md`, `docs/status.md`, `docs/audit/**`;
  tests: `tests/gate/exceptions.test.ts`, `tests/cli/report-safety.test.ts`,
  `tests/cli/readme.test.ts`, `tests/scanners/workflow-analysis.test.ts`,
  `tests/example/real-build.test.ts`, and updates across the existing suites.
- **Actual checks run (all on Node 24.21.0):**
  - `pnpm run typecheck` → 0 errors; `pnpm run typecheck:tools` → 0 errors (after build).
  - `pnpm test` → **468 tests, 27 files, all passing** with no fetched tools and no example build.
  - The README replay test found a real CLI defect: `process.exit()` dropped buffered pipe output, so
    `src/cli.ts` now writes synchronously before exiting.
  - `pnpm run test:integration` → **8 passing**.
  - `pnpm run test:scanners` → **15 passing** against the real pinned tools at the new per-platform
    paths.
  - `pnpm run fetch:tools` on darwin-x64 → 4 tools verified against the reviewed pins, 0 failures;
    `--platform plan9-x64` → exit 2, `unsupported_platform` for every tool.
  - `git status` after `pnpm test` shows no generated-file noise (the example manifest is now
    generated from a template into a gitignored path).
  - `pnpm install --frozen-lockfile --filter sechard` → installs only this package.
- **R1 (C3, M6).** `policy/toolchain.yaml` records 16 pinned assets (4 tools × 4 platforms) with
  archive and executable digests; no absolute machine path remains anywhere in `executables`. The
  native-platform versions were observed by running the binaries; other platforms carry the release
  tag's version and are verified by `runTool` on their first CI run, stated per entry. Digests were
  bootstrapped through the reviewed download path (approved origin, redirect host, size cap,
  SHA-256) with a one-off script whose output was pasted into policy deliberately; subsequent runs
  verify against the reviewed pin first.
- **R2 (C4, M4, M5).** `build` now precedes `typecheck:tools`; `tools/**` is typechecked by
  `tsconfig.tools.json` against built `dist/`; the suites are split (`test`, `test:scanners`,
  `test:example`, `test:integration`); every workflow install is filtered to `sechard`, so consumer
  jobs no longer install Next.js, Playwright, and the Supabase CLI. The example manifest is generated
  from `.hardening/app.template.yaml` and gitignored, so `pnpm test` no longer dirties the tree.
- **R3 (C2, M2, E1).** `check` exits 1 when a required check is `unsupported`, `skipped`, or
  `pending`, and 2 on `error`, while still writing its results first. Both consumer workflows have no
  `|| echo` and no `continue-on-error`; report and gate always run; the final job downloads
  `plan.json` + `results.json` + reports and re-runs the gate against the recomputed plan, failing on
  a missing artefact. The audit's shell reproduction is a test: the gate step's own script is
  executed with a failing `pnpm` stub and must exit nonzero.
- **R4 (H1, H2, H3, plus dead policy data C1/C3).** The `never` policy is resolved from the finding's
  or check's control, unioned with the gate-policy `never_exceptable` floor; a `rule_id`-only scope
  is rejected by the schema and the evaluator; a check-scoped or control-scoped exception must match
  the item it is applied to; waivers apply only to `pass`/`fail` outcomes. **H2 decision, recorded in
  `policy/gate-policy.yaml`:** a valid waiver on a permitted control lets the gate pass while the
  finding remains visible in a new "Waived" report section; critical findings are never waivable; a
  high finding waived at release requires `self_review: false`.
- **R5 (M1, M7).** Every untrusted string reaching Markdown goes through `redactSecrets` then
  `escapeMarkdown`; console output is redacted and newline-flattened; finding titles are redacted at
  result creation. `control_outcomes` is now one row per control (worst check outcome, union of
  reasons), with `required_checks`/`satisfied_checks` populated, so the summary counts controls, not
  checks.
- **R6 (M3, D4).** README rewritten to state what works and what does not; `docs/status.md` is
  generated from this record by `tools/generate-status.mjs`; `docs/status-report.md` removed; the
  audit, remediation plan, and gap analysis now live in `docs/audit/`; `docs/ci-trust.md` documents
  the H4 gap and the new fail-closed behaviour; a test replays the README's CLI block against a
  scratch consumer.
- **R7 (H6).** The generated control review sheet now carries a "pending re-approval" banner; owner
  hygiene items (`LICENSE`, `NOTICE`, `SECURITY.md` contact, the history-rewrite backup removal) are
  recorded below as owner actions. The history-rewrite backup in the temp directory was removed.
- **Limitations and unresolved findings:**
  - **Repository-side CI is unverified.** The rewrites are locally tested (including the shell
    harness), but no GitHub Actions run has been observed for this commit.
  - **R3's scripts re-run the gate against a PR-head manifest** until Batch W3; the H4 gap is
    documented in `docs/ci-trust.md`, not closed.
  - **`check` still runs no scanner**: required checks are `unsupported`, so the CLI exits 1 on the
    example and every consumer. Batch W wires the adapters.
  - **Gap-analysis items not in Batch R remain open:** audit-mode execution isolation and `--url`
    SSRF rules (Batch U), SARIF redaction (Batch U), AUTH-02 recovery/session tests, the LAN binding
    finding, control-catalogue versioning for new QUAL/AI IDs, and step-13 residual clauses.
- **Owner decisions or external setup still needed:** `code_licence`, `docs_licence`,
  `owner_legal_name`, `security_contact_email` (public-repository exposure continues until either the
  contact exists or the repository is made private); the throwaway GitHub test environment for
  platform verification; the R4 H2 decision is recorded and awaits owner review.
- **Next step:** Batch W (wire Steps 09–11 into `check`; finish Step 13's PR trust), after the owner
  reviews the Batch R checkpoint at `docs/checkpoints/batch-r.md`.

---

## Remediation close-out and owner decisions (2026-10-09)

- **State:** `verified`. Batch R is closed with the platform acceptance observed, and the owner
  answered the licensing/visibility questions.

### Batch R platform acceptance, observed on GitHub

The pushed commit `6e5cec4` ran `repo-checks` and **all required jobs passed**:

| Job | Result |
| --- | --- |
| build and test | successful (44s) |
| scanner self-scan | successful (38s) |
| workflow analysis | successful (23s) |
| hardening-gate | successful (3s) |
| security-test and sensitive-path change report | skipped (push event; the job is pull-request-only by design) |

This closes the Batch R acceptance that `repo-checks` passes on GitHub, and confirms the R1
Linux-x64 toolchain assets and the R2 ordering on a real runner. The owner reported the run;
the repository is private, so the local record cannot query the Actions API without a token.

### Owner decisions (2026-10-09)

- **R4 H2 review: accepted.** The owner reviewed the two rules in `policy/gate-policy.yaml`
  (`critical_findings_never_waivable`, `high_findings_require_non_self_approver_at_release`) and the
  never-exceptable floor, and directed Batch W to proceed. The rules remain as implemented; the
  regression tests in `tests/gate/exceptions.test.ts` pin the behaviour.
- **Licensing: none, deliberately.** `release_scope: private-sole-maintainer` recorded. The
  repository is private, maintained and used by the owner alone, and not distributed, so no
  `LICENSE` exists and the package stays `private`/`UNLICENSED`. The R7 "no licence" item is
  therefore a decision, not a blocker.
- **Security contact: not applicable while private.** `security_contact_email:
  not-applicable-private`. OPS-03's release obligation remains unmet and release evaluation blocks,
  which is correct while no release is planned.
- **Visibility: private.** Set to public only during the external audit, now private again; may be
  set public temporarily for testing, then private again.
- **History-rewrite backup:** deleted from the temporary directory in Batch R.
- `authorised_batch` set to `W`.

### Next step

Batch W — wire Steps 09–11 into `check` (C1), extend the client-secret markers (H5), evaluate pull
requests against the base branch's records (H4), and fold the live checks into a recipe.

---

## Batch W — Wire (remediation plan, 2026-10-08)

**Scope.** `docs/audit/2026-10-08-remediation-plan.md` Batch W: W1 recipe dispatch (audit C1), W2
client-secret coverage (H5), W3 pull-request trust (H4), W4 live-check recipe completion.

- **State:** `verified` for W1–W4 in this environment. The PR workflow change is locally tested but
  its platform half is unverified until a pull request runs against the private repository.
- **Files changed:** `src/execution/recipes.ts` (new), `src/execution/registry.ts` (explicit child
  env), `src/commands/run.ts` (async `check`, bounded pool, recipe dispatch), `src/commands/check.ts`
  (result tool/report/route fields), `src/domain/evaluator.ts` (coverage judged against the check's
  required coverage), `src/adapters/gitleaks.ts` (scope inventory semantics), `src/cli.ts` (await),
  `src/build/client-assets.ts` (extended markers + JWT role decoding), `controls/controls.yaml`
  (SEC-01 v2, recipes reclassified `mixed`), `.github/workflows/hardening-pr.yaml` (base records),
  `docs/ci-trust.md`, `README.md`; tests: `tests/scanners/recipes-cli.test.ts` (new),
  `tests/build/client-assets.test.ts`, `tests/workflows/trust.test.ts`, `tests/gate/gate.test.ts`,
  `tests/cli/cli.test.ts`, `tests/domain/catalogue.test.ts`.
- **Actual checks run, on Node 24.21.0:**
  - `pnpm test` → **474 tests, 27 files, all passing.**
  - `pnpm run test:integration` → **8 passing**; `pnpm run test:example` → **5 passing**;
    `pnpm run test:scanners` → **18 passing** (including the new CLI-level recipe test).
  - `pnpm run typecheck`, `typecheck:tools`, `lint` → clean.
  - `hardening check` on a scratch application containing the vulnerable fixtures: real findings
    from gitleaks (repository and history), opengrep, zizmor, and osv-scanner through the compiled
    CLI; raw reports under `<run>/raw/` with SHA-256 digests in the results.
- **W1 (C1).** Seven recipe handlers are wired: five scanner recipes, the client-asset classifier,
  and the live HTTP checks (folded in from `tools/run-live-checks.mjs`). Recipes that do not apply
  report `unsupported` with the specific reason (no git worktree, no lockfile, no workflows, no
  build output); a missing tool reports `error` with the registry's reason. Independent recipes run
  concurrently with a bounded pool.
- **Coverage correction.** `evaluateCheck` judged every pass by `coverage === 'complete'`, so a
  `mixed` method could never pass even when the stage only required partial. It now compares the
  result's coverage against the check's `required_coverage`. SEC-01's gitleaks recipes are
  reclassified `mixed` with a stated limitation (gitleaks reports bytes, not files); the tracked-file
  inventory is the compensating scope. Definition version 2 invalidates SEC-01's 2026-10-07
  approval by design; 34 of 35 approvals still resolve, and Batch D re-approves the sheet.
- **W2 (H5).** Markers now cover OpenAI, Anthropic, Stripe live, Google API, GitHub, Slack, Twilio,
  SendGrid, Resend, Firebase service-account JSON, and PEM blocks; JWT-shaped values are decoded and
  judged by their `role` claim (`service_role` or undecodable → privileged; `anon`/`publishable` →
  classified public). Tests prove the audit's probe values are detected and an anon JWT is not
  flagged.
- **W3 (H4).** `hardening-pr.yaml` checks out the base commit's records, evaluates against them, and
  fails as review-required when the PR changes the record set (the diff is printed; the evaluation
  still uses the base records). The first-adoption bootstrap is allowed and documented. A test
  executes the record step against unchanged, changed, and missing base records.
- **W4.** Live HTTP is a recipe (`web/http-requirements`) that reloads the approved-target inventory
  from the application, filters by environment, and refuses to pass on partial coverage. The X3
  exposure probes (`.env`, `.git`, source maps, debug routes) remain deferred to Batch X by the plan.
- **Limitations and unresolved findings:**
  - **ZAP is not a control recipe.** No control declares one; the Step 11 ZAP baseline remains a
    standalone tool run, recorded as such in the checkpoint.
  - **TLS remains `unsupported`** (testssl unpinned, Batch X), so a release still blocks on TLS
    evidence.
  - **The authorization, functional, dependency-policy, agent, and release recipes are not wired**;
    `check` exits 1 on them by design.
  - **Platform verification of the PR workflow** awaits a real pull request on the private
    repository.
  - `web/http-requirements` runs only where the profile plans it and a target inventory exists; a
    stopped local server yields partial coverage, which cannot pass.
- **Owner decisions or external setup still needed:** none new. `authorised_batch` stays `W`; Batch U
  (audit mode) is the proposed next batch and needs the owner's authorisation.
- **Next step:** owner review of `docs/checkpoints/batch-w.md`, then Batch U or the owner's chosen
  batch.

---

## Batch U — Audit mode (2026-10-09)

**Authorisation.** `authorised_batch: U` in `01-owner-decisions.md`, set on the owner's explicit
instruction ("continue with the next phase and building") after the Batch W checkpoint was
reviewed. Scope: remediation-plan Batch A (renamed U by the gap analysis D11) — A1 the audit
command, A2 stack and feature detection, A3 the report, A4 composable profiles — plus the
before-A gap items D1, D2, D5, D6, D8, and D9.

- **State:** `verified` in this environment. Platform behaviour is unchanged (no workflow ran);
  the audit live path is proven against a local TLS server, not a deployed internet target.
- **Files changed:** `src/audit/detect.ts`, `src/audit/url-guard.ts`, `src/audit/explanations.ts`,
  `src/audit/report.ts` (new); `src/commands/audit.ts` (new); `src/cli.ts` (audit wiring,
  usage); `src/commands/io.ts` (`recordsRoot`, profiles loaded by directory); `src/commands/run.ts`
  (`skipRecipes`/`skipReason`, `recordsRoot` into recipe context); `src/execution/recipes.ts`
  (`recordsRoot` for the live recipe); `src/adapters/http.ts` (fetch `cause` chain in TLS
  classification); `src/domain/matrix.ts` (all-mixed classification; profiles from the directory);
  `profiles/{nextjs,react-spa,node-api,python-web,supabase,payments}.yaml` (new composable set);
  `schemas/sarif-2.1.0.schema.json` (vendored, provenance in `upstream/sources.yaml`);
  `docs/audit-mode.md` (new), `README.md`, `tests/fixtures/audit/**` (new fixture apps),
  `tests/audit/**` and `tests/scanners/audit-cli.test.ts` (new), `tests/live/http.test.ts`,
  `tests/domain/catalogue.test.ts`, `controls/matrix.md` and
  `docs/checkpoints/control-review-sheet.md` (regenerated).
- **Actual checks run, on Node 24.21.0:**
  - `pnpm test` → **510 tests, 31 files, all passing** (34 new audit unit tests, 1 matrix
    classification regression test, 1 live-adapter cause-chain regression test).
  - `pnpm run test:scanners` → **27 passing** (18 previous + 9 audit CLI acceptance tests:
    three sample applications, the reference application, depth semantics, `--out` refusal,
    `--url` refusals, and the production live-check path).
  - `pnpm run test:integration` → **8 passing**; `pnpm run test:example` → **5 passing**.
  - `pnpm run typecheck`, `typecheck:tools`, `lint` → clean. `generate:matrix` regenerated.
  - Real audits through the compiled CLI: a Vite+Supabase+Stripe app (findings from gitleaks
    repository **and** history, opengrep, zizmor, osv-scanner), a Python FastAPI app (PYSEC
    advisories for the pinned `requests==2.19.1` and `fastapi==0.95.2`), an Expo app (gap banner +
    real lockfile advisories), and the reference application (zero committed secrets, stack
    composed as core + nextjs + supabase). The audited trees' SHA-256 content digests were
    identical before and after each audit.
- **U1 — the command.** `hardening audit PATH [--url ORIGIN] [--out DIR] [--depth quick|standard|
  deep] [--allow-local]`. It generates an ephemeral manifest into `<out>/records/` (validated
  against the consumer schema before anything runs), then uses the real `planCommand`,
  `checkCommand`, and `gateCommand` with a `recordsRoot` override — the audited tree is never
  written to, and the `--out` directory must live outside it (exit 2 otherwise). Detection is a
  bounded read-only walk; every detection records its evidence; undetectable features stay
  `unknown`, never `disabled`.
- **D1 — no untrusted code execution.** No recipe executes application code; `quick` is the fast
  static set, `standard` adds history/client-bundle/live checks, and `deep` states in the report
  that it adds nothing in this build because deeper work needs the isolation model (D8's semantics
  defined and tested; the isolation model itself is deliberately not built).
- **D2 — the Git-URL claim is dropped, not faked.** Audit takes a local folder; the trust rules for
  cloning an untrusted repository are recorded as not built. `--policy` defaults to the shipped
  policy root.
- **D6 — the `--url` guard.** Private, loopback, link-local (including cloud metadata), RFC1918,
  unique-local and mapped-IPv6 targets, credential URLs, non-HTTP(S) schemes, and deep paths are
  refused (exit 2, no request made); hostnames are resolved and every resolved address is checked
  and recorded; `--allow-local` is the explicit opt-in. The generated inventory is validated by
  the recipe's own loader.
- **D5 — SARIF.** `report.sarif` validates against the vendored OASIS SARIF 2.1.0 schema
  (provenance and the OASIS-licence review note are in `upstream/sources.yaml`), is redacted,
  carries no snippets, and uses relative or remote URIs only. The report also ships `report.md`
  (prioritised, plain-English findings with effort, confidence, standards references, and a
  ready-to-paste AI prompt), a self-contained `report.html`, and `report.json`; all four come from
  one evaluation.
- **D9 — the tree-digest test.** "Never writes" is defined (no creation, modification, or deletion
  inside the target, including caches; outputs to `--out` only) and enforced by checksumming the
  target tree before and after each acceptance audit.
- **U4 — composable profiles.** `nextjs`, `react-spa`, `node-api`, `python-web` (stacks), `supabase`
  and `payments` (features), all `draft`, all loaded from `profiles/` by directory rather than a
  hardcoded list (a shipped-but-unloaded profile is dead policy). Deliberate omissions, recorded:
  the `quality` profile arrives with Batch Q when QUAL-02+ controls exist; `firebase-detect`,
  `uploads`, `runtime-ai`, and `multi-tenant` have no catalogue controls or recipes to select in
  this build (detection reports the features and the report states the gaps); `nextjs-supabase`
  is **kept, not replaced**, so the example's records keep resolving — the plan's "replace" would
  have been churn with no behavioural gain.
- **Defects found and fixed while building this batch:**
  1. **The control matrix misclassified every control that has only `mixed` and manual methods as
     `manual_only`** — whose own definition says "a scan result can never satisfy these", which
     was false after Batch W's `required_coverage` change. Eight controls (SEC-01, GOV-01, AGT-01,
     AGT-02, CI-01, CI-02, WEB-01, DEPLOY-01) were listed wrong. Batch W had also edited SEC-01
     to version 2 without regenerating the matrix, so the drift was invisible until this batch
     regenerated it. The classifier now counts `mixed` towards `mixed`; a regression test pins
     SEC-01 as `mixed`; the matrix and review sheet are regenerated.
  2. **The live HTTP adapter classified an unverified TLS connection as a generic unreachable
     route.** Node's fetch reports certificate failures as "fetch failed" with the socket error on
     `error.cause`; the adapter read only the outer message. Found by the audit live-target
     acceptance test (the manual reproduction showed `route-unreachable` where `tls-invalid` was
     due); fixed by reading the cause chain, with a regression test in `tests/live/http.test.ts`.
  3. **The first version of the live acceptance test hosted its HTTPS server in the test process**
     while the CLI helper blocked that process's event loop synchronously, so the TLS handshake
     never completed and the test saw a 10-second timeout misread as an unreachable route. The
     server now runs as an independent child process. Recorded here because "the test was wrong,
     not the code" is exactly the kind of finding this repository exists to make visible.
- **Limitations and unresolved findings:**
  - **Local folder only; `deep` equals `standard`** in this build; both stated in the report and
    `docs/audit-mode.md`.
  - **Python static analysis does not run** — the reviewed rule pack is JS/TS only; the
    `python-web` profile does not require the method rather than fabricate coverage.
  - **The audit live path is proven against `--allow-local` https targets** (self-signed local
    server, honest `tls-invalid` finding). A real deployed-origin audit with valid TLS was not
    performed; the machinery is identical.
  - **The fastapi acceptance audit costs ~5 minutes** because osv-scanner resolves Python
    dependencies online; recorded as the price of the real-advisory acceptance rather than
    hidden with a fixture.
  - **The SARIF schema is OASIS material** (RF-on-RAND IPR mode, no SPDX id). Vendored for
    validation of our own output; redistribution beyond this private repository needs the licence
    review recorded in `upstream/sources.yaml` — an owner action for Batch D.
  - Unchanged from W: authorization/functional/dependency-policy/agent/release recipes unwired;
    TLS manual; LAN binding and AUTH-02 recovery/session still unowned by a batch.
- **Owner decisions or external setup still needed:** none blocking. For review: the six new
  profiles' control selections and method sets (`profiles/*.yaml`), and the audit contract
  (`docs/audit-mode.md`). `authorised_batch` stays `U`; Batch Q (quality) or S (standards) is
  proposed next, per the remediation plan's order.
- **Next step:** owner review of `docs/checkpoints/batch-u.md`, then Batch Q or S on
  authorisation.

---

## Batch Q — Quality: "engineered, not vibe-coded" (2026-10-10)

**Authorisation.** `authorised_batch: U` covered the batch map's next slot ambiguously (the plan's
Q can run after U); the owner's explicit instruction ("lets start with batch Q") authorises Batch Q.
Scope: remediation-plan Q1 (quality controls), Q4 (the SecHard-owned tells analyser), Q6 (the
calibration corpus), gap A2 (apply the reference-app M8 findings or record them), and gap D3 (the
catalogue-versioning story for new control IDs). Q2/Q3 (external analyser provisioning), Q5
(advisory AI review), and the external calibration targets (Juice Shop, NodeGoat) are staged.

- **State:** `verified` for everything wired, with the staged work named below.
- **Files changed:** `controls/controls.yaml` (catalogue v2: QUAL-02…13 added, migration note),
  `controls/control.schema.json` (`quality_scan` method), `schemas/control-catalogue.schema.json`
  (`migration`), `schemas/quality-thresholds.schema.json` + `policy/quality-thresholds.yaml` (new),
  `profiles/quality.yaml` (new), `src/quality/{thresholds,common,tells,correctness,hygiene}.ts`
  (new), `ci/configs/opengrep-rules/quality-errors.yaml` (new),
  `src/execution/recipes.ts` (six quality recipes + rule-id normalisation),
  `src/adapters/opengrep.ts` (pack-prefixed rule ids normalised), `src/audit/detect.ts` (quality
  always composes), `src/audit/report.ts` (security/quality split), `src/audit/explanations.ts`
  (quality explanations), `src/adapters/http.ts` unchanged; reference app: `app/notes/actions.ts`,
  `app/notes/page.tsx`, `next.config.ts` (M8 fixes); `tests/quality/{corpus,self-audit}.test.ts`,
  `tests/corpus/**` (new), `tests/scanners/quality-opengrep.test.ts` (new),
  `tests/agent/change-report.test.ts` (fixture composed at runtime),
  `agent-rules/review-manifest.yaml`, `README.md`, `docs/audit-mode.md`, `controls/matrix.md` and
  `docs/checkpoints/control-review-sheet.md` (regenerated).
- **Actual checks run, on Node 24.21.0:**
  - `pnpm test` → **522 tests, 33 files, all passing** (calibration, self-audit, catalogue
    migration, and the adjusted profile-composition assertions).
  - `pnpm run test:scanners` → **31 passing** (27 previous + 4 opengrep quality-pack tests with the
    real binary: every rule fires on the vibe-app seeds, the clean twin stays silent).
  - `pnpm run test:integration` → **8 passing**; `pnpm run test:example` → **5 passing** (rebuilt
    example); `typecheck`, `typecheck:tools`, `lint` clean; `generate:matrix` regenerated.
  - **Calibration measured (Q6):** recall **1.0** over 18 seeded issues, precision **1.0** (20
    findings, all matched to seeds), clean twin **0 findings** — floors 0.8/0.6/0 cleared.
  - **Self-audit (the checkpoint's "SecHard passes its own quality audit"):** zero high/critical
    findings, and exactly one accepted LOW finding — the deliberately absent licence (a recorded
    owner decision the hygiene check reports because an unrecorded absence is indistinguishable
    from an oversight).
  - **Reference app (A2/M8):** `updateNote` writes the body (it silently dropped it), every
    insert/update/delete inspects and surfaces its error, `X-Powered-By` is off, and CSP +
    COOP + CORP headers are set — **verified live against the running production build with
    curl**: X-Powered-By absent, all seven security headers present.
- **D3 (catalogue versioning).** Catalogue v2 carries a `migration` note that names exactly what
  was added; the catalogue test asserts the note and the deliberate 47-ID set, keeps the 35 v1
  definitions' owner-review assertions scoped to v1, and expects the 12 new drafts unresolved for
  approvals (release evaluation blocks on them until the owner approves — the same rule as every
  other control). A schema field allows new ID sets only with a migration note.
- **Q4 (tells analyser).** Rules: narration (a comment restating the next line's mechanics — judged
  against the next line only, with rationale markers and wrapped-prose guards, because the
  three-line window misread this repository's own policy comments), step narration, marketing
  adjectives, banners, emoji, placeholder comments/values, hardcoded local URLs (scheme required;
  comparisons and config/tool/e2e files are mentions, not assumptions), debugger statements,
  commented-out code, and comment dominance. Deliberate omissions recorded: near-duplicate
  helpers, several utility files, mixed paradigms (need cross-file analysis), hallucinated imports
  (need registry access, Batch X). Every finding is a signal with an explanation — never proof of
  authorship.
- **Reference-app defect found by the analysers during calibration:** `tests/agent/
  change-report.test.ts` contained a literal `.skip` inside its detection fixture — composed at
  runtime now, per the repository's established technique. The instrument found a real instance of
  the thing it measures, in the repository that built it.
- **Toolchain defect found while wiring the quality pack:** the pinned opengrep (1.30.0) reads
  local config files with a locale-dependent codec and crashes on non-ASCII content under the
  minimal recipe environment (`'ascii' codec can't decode…` in `config_resolver.py`); the security
  pack was pure ASCII by luck. The reviewed rule packs are now ASCII-only by rule, and the pack
  header records why. Separately: semgrep-style tools prefix a local config path onto every rule
  id — the adapter now normalises to the reviewed pack namespace, which the earlier suffix-tolerant
  tests already anticipated.
- **Staged, recorded rather than implied:** jscpd (QUAL-03), Lizard (QUAL-04), Knip/Vulture
  (QUAL-05), dependency-cruiser (QUAL-06), formatters (QUAL-10), axe-core/Lighthouse (QUAL-13),
  and QUAL-01's own-scripts recipes (D1: executing application code needs the isolation model) —
  each recipe reports `unsupported` with the tool's name as the reason. Q5 (advisory AI review)
  needs the owner's explicit opt-in and a provider decision. The external calibration targets are
  security corpora first (Batch X).
- **Limitations and unresolved findings:** registry-based dependency health (deprecation, major
  drift) is not measured; the tells analyser's precision was tuned against this repository and the
  corpus, and recalibration is a reviewed change to `policy/quality-thresholds.yaml`; the
  opengrep locale defect is an upstream bug recorded here (ASCII-only configs are our defence,
  not a fix).
- **Owner decisions or external setup still needed:** review the twelve new control definitions
  (all `draft`; release evaluation blocks on them until approved, by design), the quality
  profile's exception policies, and the thresholds policy. `authorised_batch` stays `U`; Batch S
  (standards) is the remaining plan batch that can proceed.
- **Next step:** owner review of `docs/checkpoints/batch-q.md`, then Batch S or X on
  authorisation.

---

## Batch S — Standards at requirement level (2026-10-10)

**Authorisation.** Batch S on the owner's explicit instruction ("lets start with S"). Scope:
remediation-plan S1 (the mapping data model and coverage matrices), S2 (per-standard work), S4
(comparison-project records), and gap D7's Scorecard-pinning statement. S3 (agent-guidance
curation) and the release-side SLSA row are staged with recorded reasons.

- **State:** `verified` for everything delivered; the staged work is named below.
- **Files changed:** `controls/mappings/{asvs,owasp-top-10,owasp-api-top-10,nist-ssdf,osps,mvsp,
  asd-sbd,mcp-top-10}.yaml` (new, 518 requirement entries), `controls/mappings/data/
  asvs-5.0.0-en.csv` (vendored official data, licence notice in `upstream/sources.yaml`),
  `controls/coverage/**` (new, generated), `schemas/standard-mapping.schema.json`,
  `src/domain/standards-coverage.ts`, `tools/generate-coverage.ts`,
  `ci/configs/opengrep-rules/hardening-core.yaml` (six new rules: SSRF, unsafe consumption,
  implicit grant, three Electron rules), `tests/fixtures/scanners/{api,oauth,electron}/**`
  (vulnerable/fixed pairs), `controls/controls.yaml` (catalogue **v3**: AUTH-03; WSTG citations and
  cheat-sheet references on every test recipe; corrected QUAL-07 Top-10 note),
  `controls/control.schema.json` (wstg/cheat_sheet), `schemas/control-catalogue.schema.json`
  (migration history), all six auth-bearing profiles (AUTH-03, never exceptable),
  `src/audit/report.ts` + `src/commands/audit.ts` (per-application standards-coverage statement),
  `src/adapters/opengrep.ts` (unchanged this batch), `upstream/sources.yaml` (ASVS vendoring;
  Top-10 2025 names; gorrion split out per S4; QUAL-07 note), `agent-rules/review-manifest.yaml`
  (mappings are review-required), `tests/domain/standards-coverage.test.ts` (new),
  `tests/scanners/adapters.test.ts` (new-rule fixtures), tests updated deliberately for the
  catalogue change; `README.md`, `docs/audit-mode.md`, matrices regenerated.
- **Actual checks run, on Node 24.21.0:**
  - `pnpm test` → **535 tests, 34 files, all passing**, including the new Batch S acceptance:
    no unmapped ASVS id, no invalid chapter, levels checked against the vendored CSV, exact
    2025 Top-10 names, API1–API10 present, SSDF's 42 active tasks + 5 recorded consolidations,
    MCP link-only, every gap carrying a reason, every mapped control and recipe id existing.
  - `pnpm run test:scanners` → **31 passing**; the six new opengrep rules verified against their
    vulnerable fixtures and clean twins with the real pinned binary.
  - `pnpm run test:integration` → **8 passing**; `pnpm run test:example` → **5 passing**;
    `typecheck`, `typecheck:tools`, `lint` clean.
- **S1 (data model).** `schemas/standard-mapping.schema.json` + `src/domain/standards-coverage.ts`
  + `tools/generate-coverage.ts`: eight mapping files, eight generated matrices under
  `controls/coverage/` with an index, and a per-application standards-coverage statement in every
  audit report (which requirements the composed profiles could actually check for THIS app).
- **S2 (per-standard).**
  - **ASVS 5.0.0: all 345 requirements mapped** (70 L1: 12 automated, 20 manual, 38 gap; L2/L3
    recorded with methods and reasons; V17 WebRTC not_applicable). The official CSV is vendored
    (SHA-256 in sources; CC BY-SA review-before-distribution note), and a test enforces that no
    summary reproduces the standard's phrasing. The plan's expected areas all have named controls
    or recorded gaps: V7 (AUTH-01, unwired - the recorded session finding), V10 (AUTH-03),
    V3/V5/V11/V14/V15 (gaps with reasons or manual mappings).
  - **AUTH-03 (RFC 9700)** added at catalogue v3: OAuth/OIDC flow security - implicit-grant
    prohibition enforced by the wired `hardening.oauth-implicit-grant` rule (fixture detected,
    clean twin silent), PKCE/state/nonce/redirect handling by the declared
    `auth/oauth-flows` manual recipe. Never exceptable in every profile that selects it.
  - **Top 10 2025**: names fetched from the published edition (A01 Broken Access Control …
    A10 Mishandling of Exceptional Conditions) and pinned by test; the chapter-level mappings in
    `standards.yaml` updated to the 2025 letters, including correcting this repository's own
    Batch Q note (A10 is exceptional conditions, not integrity).
  - **API Top 10 2023**: API1–API10 mapped; API7 SSRF and API10 unsafe consumption have wired
    static rules with fixtures; the SSRF rule's syntactic limitation (indirect routing through a
    variable) is recorded in the fixture itself.
  - **WSTG 4.2**: every `authorization_test`/`functional_test` recipe cites WSTG test ids
    (WSTG-ATHZ-02/04 for IDOR, SESS for session, INPV for inputs, BUSL for flows) or records why
    no WSTG test exists (WSTG excludes DoS; supply-chain hooks and release drills are out of
    scope for it), plus the cheat sheet each follows. Enforced by test.
  - **SSDF 1.1**: task ids extracted from the official SP 800-218 PDF (public domain); 42 active
    tasks mapped (PW/RV to controls, PO/PS to governance and manual evidence), 5 v1.1
    consolidations recorded as such. The plan's "42" matches the active count exactly.
  - **OSPS v2026.08.28**: all 64 active requirements fetched and mapped (the plan's 67 was an
    estimate; the published edition has 64 active plus one retired id, which stays visible).
    **Level 1 applied to SecHard itself** - see the checkpoint for the met/owner-blocked table.
    **D7 recorded**: when Scorecard is run, it must be SHA-pinned like every external action (the
    Trivy/KICS lesson); stated in the checkpoint's owner list.
  - **MVSP**: all 25 controls mapped (CC0 source, structure fetched).
  - **ASD SBD**: the current six-foundation edition fetched and mapped to CTX/GOV/OPS.
  - **MCP Top 10**: link-only as the plan requires (CC-BY-NC-SA); ids and category names with
    canonical links, zero adapted text, licence note enforced by test.
  - **SLSA 1.2**: staged - no release exists, so "releases get Build L2" has nothing to attach
    to; it is a Batch D release-pipeline item, recorded rather than faked.
- **S4**: the gorrion production-readiness-checklist now has its own source record with its MIT
  licence, separate from the representative checklist entry; the astoj IaC project could not be
  identified from a URL in the plan and is recorded as a gap rather than guessed at.
- **S3 staged, not skipped**: CodeGuard, the OpenSSF AI-instructions guide, and the OWASP Secure
  Coding with AI cheat sheet are already recorded as sources with verified licences; adapting
  them into `agent-rules/core/` regenerates AGENTS.md/CLAUDE.md and needs owner review of the
  generated guidance - doing that in the same session as 518 mapping entries risks rushing
  unreviewable instruction text. Recorded as the first item of the next batch or a standalone
  owner-reviewed task.
- **Approval invalidations (deliberate):** WSTG citations edited fourteen v1 definitions and the
  catalogue gained AUTH-03, so 14 approvals no longer resolve and 20 of 35 still do; the
  catalogue test pins the full unresolved list. Batch D re-approves the sheet.
- **Limitations and unresolved findings:** the audit-level standards statement is kit-level plus
  composition - it says what could run for the app, not what a human assessor verified
  (ASVS-style full verification is a service, not a scan, and the report says so); the
  true-positive-checklists entry keeps a representative canonical URL because the projects it
  stands for have no single one.
- **Owner decisions or external setup still needed:** review ASVS L1 and Top 10 2025 **line by
  line** (the checkpoint's review list points at the matrices), then approve or amend; the
  fourteen WSTG-invalidated definitions need re-approval whenever the owner chooses; Scorecard,
  if adopted, must be SHA-pinned.
- **Next step:** owner review of `docs/checkpoints/batch-s.md`, then Batch X (expansion) or D
  (adoption) on authorisation.


---

## Revision: the red CI run found by pushing Batch S (2026-10-10)

The owner instructed that all updated work be pushed before the next batch. The push of Batch S
(`08cc1c8`) triggered `repo-checks`, and watching it exposed that **the Batch W push
(`70382b1`) had failed CI on 2026-10-08 and the failure had never been recorded** — the last
verified green run was Batch R's `6e5cec4`. The batch-w checkpoint's platform section described
the pull-request workflow as unverified but did not state that the push run itself was red.
Recorded here as a process defect: a run nobody watched is a claim nobody checked.

- **State:** `verified`. **`repo-checks` green on GitHub for `8ff7cc6` (run `38059518124`,
  2026-10-10)**: build and test, scanner self-scan, workflow analysis, and hardening-gate all
  successful; the PR-only change report skipped by design. Reaching green took three pushes; the
  third failed on a typecheck error in the new test code that was committed without running
  `typecheck` first — recorded here because the repository's own rules say to run it, and CI was
  the place that caught it.
- **Root cause 1:** two unit tests (`tests/cli/cli.test.ts`, `tests/cli/readme.test.ts`) silently
  required fetched scanner tools — Batch W's wiring made `check`'s exit code environment-dependent
  (unsupported → exit 1 with tools; missing-tool errors → exit 2 without). The local machine
  always had tools, so the unit CI branch never executed locally. Fixed: both tests now branch on
  `resolveTool('gitleaks').available` and assert the named contract for the environment they are
  in; the no-tools branch additionally asserts the missing-tool error diagnostic, which had no
  direct test before.
- **Root cause 2:** the audit SARIF writer kept absolute local paths inside the audited target
  (contradicting gap D5's own wording). GitHub's `/tmp` runner directories tripped the
  `audit-cli` test that the macOS `/var/folders` temp dir had satisfied locally. Fixed: absolute
  locations inside the target are relativized against the audit root (`uriBaseId: AUDITROOT`);
  the unit test now uses a location inside the fixture target.
- **Checks run locally:** full unit suite (535) and the scanners suite including the audit CLI
  acceptance (32) pass with tools present; the CI run exercises the no-tools branches.
