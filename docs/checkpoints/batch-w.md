# Batch W checkpoint

Batch W of `docs/audit/2026-10-08-remediation-plan.md`, worked after Batch R against the
2026-10-08 external audit and the gap analysis.

## Status

- **W1 — Recipe dispatch (C1): verified locally.** Seven handlers wired; `check` runs them
  concurrently; raw reports stored with digests; real detections proven through the compiled CLI.
- **W2 — Client-secret coverage (H5): verified.** Extended markers plus JWT role decoding; the
  audit's probe values are caught.
- **W3 — Pull-request trust (H4): local half verified; platform half awaiting a real PR.** The PR
  workflow evaluates the base branch's records and fails review-required when they change. The
  repository is private, so no pull request has exercised it yet.
- **W4 — Live-check recipe completion: verified for the recipe.** `web/http-requirements` reloads
  the approved-target inventory and filters by environment. The X3 exposure probes stay deferred to
  Batch X by the plan.

## What now works

Commands, all run on Node 24.21.0:

- `hardening check` runs gitleaks (repository and history), osv-scanner, opengrep, zizmor, the
  client-asset classifier, and live HTTP when an approved target applies. Raw reports are written to
  `<run>/raw/` with SHA-256 digests recorded in `results.json`.
- Recipes that do not apply report `unsupported` with the specific reason; a missing tool reports
  `error` with the registry's reason; neither is ever a pass.
- `pnpm test` (474), `pnpm run test:scanners` (18, needs `pnpm run fetch:tools`),
  `pnpm run test:example` (5, needs the example build), `pnpm run test:integration` (8).

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` | 474 passed, 27 files |
| `pnpm run test:scanners` | 18 passed, including a CLI-level detection test |
| `pnpm run test:integration` / `test:example` | 8 / 5 passed |
| `pnpm run typecheck` / `typecheck:tools` / `lint` | clean |
| Real CLI run on a vulnerable scratch app | gitleaks ×2, opengrep, zizmor, osv all reported findings |
| Trust tests | record step executed against unchanged / changed / missing base records |

## Controls

The catalogue still holds 35 controls. **SEC-01 changed**: gitleaks recipes reclassified `mixed`
(definition version 2) because gitleaks cannot attest per-file coverage; the limitation is stated on
the control. That deliberately invalidates SEC-01's 2026-10-07 approval — 34 of 35 approvals still
resolve — and Batch D re-approves the whole sheet against the final review-sheet digests. No control
was added, removed, or merged.

## Deviations from the plan

1. The evaluator's coverage rule was corrected (judged against `required_coverage`, not always
   `complete`); without it, no `mixed`-method control could ever pass.
2. The live HTTP recipe was implemented in this batch (the plan allowed deferral to X3), while the
   X3 exposure probes were left deferred.
3. ZAP is not wired as a recipe because no control declares one; it remains a standalone Step 11
   tool. Recorded rather than implied.
4. `SEC-01`'s definition changed and its approval was invalidated; the plan's H6 re-approval at
   Batch D already anticipated definition churn.

## Blockers and owner actions needed

1. **A real pull request** to exercise the PR workflow's base-records behaviour on GitHub.
2. **Batch authorisation** for the next batch (the plan's Batch U, audit mode, is proposed).
3. Unchanged from R: `github_test_owner`/`github_test_repos` remain unfilled; licence and security
   contact are deliberate non-applicable decisions while the repository is private and undistributed.

## Owner review list

- `src/execution/recipes.ts` — what each recipe runs, its flags, and its honest failure modes.
- `tests/scanners/recipes-cli.test.ts` — the audit's C1 acceptance, executed through the CLI.
- `controls/controls.yaml` — SEC-01 version 2 and why its recipes are `mixed`.
- `src/domain/evaluator.ts` — coverage versus `required_coverage`.
- `.github/workflows/hardening-pr.yaml` — base-records checkout, review-required record change, and
  the bootstrap path; `docs/ci-trust.md` states the boundary.

## Known limitations and risks

- Most catalogue recipes remain unimplemented, so a clean application still cannot pass every
  control; the gate blocks honestly.
- TLS is manual (testssl unpinned, Batch X); ZAP is not a recipe.
- Recipes scan the git worktree root for repository-scoped artefacts (lockfiles, workflows), which
  for a nested example is the parent repository. That is the app's repository in normal use and is
  recorded in each result's scope.
- The PR workflow's base-records behaviour is unverified on the platform until a PR runs.

## Proposed next batch

**Batch U — audit mode**: `hardening audit PATH [--url]` with stack detection, an ephemeral
manifest, a prioritised report with fix suggestions and AI-ready prompts, and the isolation rules
from the gap analysis (untrusted application code execution, `--url` SSRF refusal). Owner
preparation: authorise the batch and review this checkpoint.
