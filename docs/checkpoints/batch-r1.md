# Checkpoint — Batch R1: protect the operator and the audited tree (full-audit remediation)

**State: implemented and locally verified.** Authority: `authorised_batch` updated to R1 on the
owner's go-ahead ("go ahead", 2026-10-14). Source: the full audit
(`full-audit/2026-10-13-SecHard-full-audit.md`) and the plan review's PR-01..PR-05 corrections,
applied to `2026-10-13-full-audit-remediation-plan.md` (v2).

## Counterexample-first, per the plan's ground rules

- **A-01**: the hostile-fixture test first proves the counterexample is real on this platform —
  an unhardened patch diff executes a repository-configured `diff.external` helper (marker file
  written) — then proves the hardened change report executes nothing and still reports the
  modified assertion line. `tests/agent/git-hardening.test.ts` (3 tests). Platform note recorded
  in the fixture: Git 2.55 rejects `core.fsmonitor=<path>` at parse time, so the live marker
  vector is the diff helper; the runner still disables fsmonitor and hooks for older parsers.
- **A-02**: `tests/commands/confinement.test.ts` (5 tests) — output symlink into the target
  refused (and a symlink resolving nowhere refused fail-closed), inside-target output refused,
  normal outside output proceeds, the detection walk never follows a symlink out of the tree and
  records the skip.
- **A-03**: unit redaction test for the previously unpersisted-then-leaked provider values
  (Stripe, OpenAI/Anthropic, database URLs, Google keys — including values not assigned to a
  variable named `secret`), plus a scanner-suite end-to-end assertion that the persisted
  report.md/report.json/report.sarif/evidence.json contain none of the fixture's secret values
  and that `raw/` is not retained.
- **A-27**: the restore drill rewritten to the PR-05 contract: dedicated disposable target
  identified by exact container name and Postgres image (no flag can redirect it), dump verified
  (non-empty, marker present) **and** restored into a separate disposable verification database
  before any destructive step, backup preserved with printed recovery instructions on every
  failure after destructive work begins, cleanup only after verified recovery. `bash -n` verified;
  a live run needs the local stack (operator step).
- **Workstream M**: `tests/corpus/independent-nextjs/EXPECTED.yaml` — the per-seed manifest at the
  original denominators (31 security / 30 quality), with baseline numbers from the pre-R1
  measurement (b71a073), misses disclosed by status (`fires` / `pending-A16` / `pending-cap` /
  `pending-F08` / `pending-tool`). Established before any detection tuning, per the review.

## Files changed

`src/execution/git-hardening.ts` (new: hardened `-c` args, diff-safety flags, child-process env),
`src/commands/io.ts` + `src/agent/review-manifest.ts` (both Git runners hardened),
`src/agent/change-report.ts` (`--no-ext-diff --no-textconv` on both diffs),
`src/execution/recipes.ts` (gitOutput hardened; gitleaks recipes inject the hardened Git config
environment for their child processes), `src/audit/detect.ts` (walk: lstat, no symlink following,
skips recorded as detection gaps), `src/security/migrations.ts` (readdir: no symlink following),
`src/commands/audit.ts` (real-path output confinement with dangling-symlink refusal; persistence-
boundary scrub of all four report formats and evidence.json; raw scanner output no longer
retained in audit mode), `src/evidence/redaction.ts` (the missing provider patterns),
`src/adapters/opengrep.ts` (matched line replaced by its digest — the source line is never
persisted), `examples/nextjs-supabase/tests/operations/restore-exercise.sh` (rewritten),
`tests/corpus/independent-nextjs/EXPECTED.yaml` (new manifest), tests (`git-hardening`,
`confinement`, audit-cli A-03 assertion), this record, `CHANGELOG.md`, `docs/status.md`.

## Checks run

Unit **569/569**, typecheck (both configs) and lint clean; the scanners suite (with fetched
tools) runs in this push and must be green before this checkpoint is recorded complete.
`bash -n` on the rewritten restore script; the live drill run remains an operator step (it needs
the local Supabase stack and is destructive by design on a disposable database).

## What R1 does not claim

- The A-25 acknowledgement design, A-29's download/process hardening beyond what R1 needed, and
  every R2–R5 item remain open (the plan's batch order stands).
- The gitleaks child-Git hardening is enforced via the environment channel and asserted at the
  unit level; the scanner-suite marker test asserts no helper executed during a full audit of a
  hostile-configured repository.
