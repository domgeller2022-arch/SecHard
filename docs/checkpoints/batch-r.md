# Batch R checkpoint

Batch R of `docs/audit/2026-10-08-remediation-plan.md`, worked against
`docs/audit/2026-10-08-external-audit.md` (commit `331078e`) and the gap analysis in
`docs/audit/2026-10-08-remediation-gap-analysis.md`.

## Status

- **R1 — Platform-aware, relocatable toolchain (C3, M6): verified locally.** Four tools × four
  platforms pinned with archive and executable digests; no machine path remains; an unlisted
  platform is refused as `unsupported_platform`. Non-native platform versions are release-declared
  and verified by `runTool` on their first CI run, stated per entry.
- **R2 — CI ordering and suite split (C4, M4, M5): verified locally; GitHub run
  `awaiting_external_verification`.** Build precedes `dist/` consumers; suites split; installs
  filtered; `pnpm test` no longer dirties the tree. The commit is pushed; the repository is private,
  so the run is visible to the owner in the Actions tab but not over the unauthenticated API.
- **R3 — Fail-closed workflows (C2, M2, E1): local half verified; platform half
  `awaiting_external_verification`.** `check` exits nonzero on unmet required work; workflows have no
  fail-open construct; the final job re-runs the gate against the uploaded plan and results; the
  audit's shell reproduction is a passing regression test.
- **R4 — Exception handling (H1–H3): verified.** Never-policy resolves from the finding's control;
  `rule_id`-only scopes are rejected; waivers cannot apply over errors or unsupported results;
  critical findings are never waivable; high findings at release need a non-self approver.
- **R5 — Report safety (M1, M7): verified.** Redaction then Markdown escaping on every untrusted
  string; console output redacted and newline-flattened; one outcome per control, not per check.
- **R6 — Documentation truth (M3, D4): verified.** README rewritten; `docs/status.md` generated from
  the progress record; review sheet marked pending re-approval; audit documents in `docs/audit/`;
  README commands replayed by a test.
- **R7 — Owner hygiene: partially done, owner items pending.** Review sheet marked; history-rewrite
  backup removed. `LICENSE`, `NOTICE`, and the security contact need owner decisions.

## Post-checkpoint update (2026-10-09)

- `repo-checks` on `6e5cec4` passed: build and test, scanner self-scan, workflow analysis, and
  hardening-gate all successful; the pull-request-only review job skipped as designed. R2/R3 platform
  acceptance is closed.
- The owner accepted the R4 H2 rules and the never-exceptable floor.
- Owner decisions: no licence (`release_scope: private-sole-maintainer`), no security contact while
  private, repository private. R7's owner items are decisions rather than blockers.

## What now works

Exact commands, all run on Node 24.21.0:

- `pnpm install --frozen-lockfile --filter sechard` — installs only this package.
- `pnpm run fetch:tools` — verifies the current platform's pinned assets against the reviewed
  digests; `--platform plan9-x64` exits 2 with `unsupported_platform`.
- `pnpm run build && pnpm run typecheck && pnpm run typecheck:tools && pnpm run lint`.
- `pnpm test` (468 tests, no external preconditions), `pnpm run test:scanners` (16, needs fetched
  tools), `pnpm run test:example` (5, needs the example build), `pnpm run test:integration` (8).
- `pnpm run generate:status` — regenerates `docs/status.md`; `--check` fails if it is out of date.
- `hardening check` now exits 1 when a required check did not run, and the consumer workflows fail
  closed on that.

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` | 468 passed, 27 files |
| `pnpm run test:integration` | 8 passed |
| `pnpm run test:scanners` | 16 passed against real pinned tools |
| `pnpm run test:example` | 5 passed against the real `.next` build |
| `pnpm run fetch:tools` (darwin-x64) | 4 verified, 0 failures |
| `node tools/fetch-tools.mjs --platform plan9-x64` | exit 2, `unsupported_platform` |
| `pnpm install --frozen-lockfile --filter sechard` | root package only |
| `git status` after `pnpm test` | only intentional changes |
| `pnpm run typecheck` / `typecheck:tools` / `lint` | 0 errors |
| Outputs stored | Terminal only; raw evidence is not committed |

## Controls

Catalogue unchanged: 35 controls, all `owner_reviewed` with historical approvals. R7 marks the
review sheet pending re-approval; every remediation batch changes definitions, so Batch D re-approves
against the final sheet. No control's acceptance criteria changed in R.

## Deviations from the plan

1. Audit mode is called **Batch U**, not "A", to avoid colliding with original Batch A.
2. The H2 decision was implemented as the plan recommended (waiver lets the gate pass; critical never
   waivable; high at release needs a non-self approver) rather than deferred.
3. R1's acceptance says "fetch succeeds on Ubuntu and macOS"; only the macOS half has been observed
   here. The Ubuntu half runs in CI and is not claimed until a run is seen.
4. The per-platform digests were bootstrapped with a one-off fetch whose output was pasted into
   `policy/toolchain.yaml` deliberately; the reviewed-pin-first mechanism now applies to every later
   run. Recorded because first-run bootstrap is inherently trust-on-first-use.
5. R3's final job re-runs the gate against the PR head's manifest (the H4 gap) until Batch W3.

## Blockers and owner actions needed

1. **GitHub platform verification** (`github_test_owner`, `github_test_repos`, token): needed to
   observe `repo-checks` and to close Step 13.
2. **`security_contact_email`, `code_licence`, `docs_licence`, `owner_legal_name`:** the repository is
   public with no licence and no report channel. Either fill these or move the repository private
   until Batch W is merged.
3. **R4 review:** confirm the H2 decision and the high-severity release rule in
   `policy/gate-policy.yaml`.
4. **LAN binding finding:** no batch owns it; decide containment or record the accepted risk.

## Owner review list

- `policy/gate-policy.yaml` `exceptions:` — the H2 decision and severity ceilings.
- `src/domain/evaluator.ts` `findException`/`aggregateControlOutcomes` — the H1 and M7 fixes.
- `.github/workflows/hardening-pr.yaml` — the fail-closed step order and the final gate job.
- `tests/gate/exceptions.test.ts` and `tests/workflows/trust.test.ts` — the H1–H3 probes and the
  executed shell reproduction.
- `policy/toolchain.yaml` `executables:` — per-platform digests and version provenance.
- `README.md` and `docs/status.md` — what is claimed versus what is not.

## Known limitations and risks

- No GitHub Actions run has been observed for this commit; CI acceptance is unverified.
- `check` still runs no scanner (Batch W); every consumer currently blocks by design.
- Audit-mode execution isolation, `--url` SSRF rules, and SARIF handling are recorded gaps.
- AUTH-02 recovery isolation and genuine session expiry remain untested.

## Proposed next batch

**Batch W** — wire `gitleaks`, `osv/lockfile`, `opengrep`, `zizmor`, client assets, and live HTTP
into `check` through a recipe registry; extend the client-secret markers; evaluate PRs against the
base branch's `.hardening/` records (H4). Owner preparation: review this checkpoint; decide the R4
questions; provide the GitHub test environment when available.
