# P3.1 evidence — mandatory packs, parser failures and independent scope (observed 2026-10-15)

A-09/A-10. The opengrep recipes can no longer produce a clean, complete result from a failed or
missing pack, a parser failure, an ignored file, or an unreviewed target suppression.

## What changed

1. **Independent inventory before the scan** (`src/execution/inventory.ts`): a bounded,
   symlink-safe walk over the packs' language extensions minus the reviewed directory exclusions.
   It records intended paths, a truncation flag, and skipped entries with reasons. `*.d.ts` files
   are excluded by reviewed convention (no runtime behaviour; the tool does not scan them; secret
   material in any file remains covered by the gitleaks recipes).
2. **Coverage verified against the inventory** (`src/adapters/opengrep.ts`): unexamined inventoried
   files, scanner-reported failures, and malformed report entries each keep the scan from claiming
   complete; the result scope carries `unexamined`/`failed` counts and names the first unexamined
   files. Expected scope is never defined as whatever the scanner happened to report.
3. **Strict pack aggregation** (`src/execution/recipes.ts`): one shared inventory and one shared
   suppression inventory feed both packs; a missing pack, invalid rules (scanner exit 7), a timeout
   (null exit code), a parser failure, an unexamined file, or an inventory gap makes the result an
   explicit **error carrying the findings** — findings survive to the report while the check fails
   (the check-result schema forbids a pass without complete coverage, so error is the structural
   representation). A successful sibling never masks a failed one. The same rules apply to the
   quality-error pack.
4. **Target-controlled suppressions cannot shrink the scope**: the recipe pins
   `--semgrepignore-filename` to a reviewed, empty policy file
   (`ci/configs/opengrep-semgrepignore`), replacing both the tool's built-in default ignore (which
   silently skipped whole source trees such as `tests/`) and any `.semgrepignore` the target
   ships; presence is still inventoried and recorded (`scope.suppressions`, named in the
   diagnostic). Inline `nosemgrep` annotations force explicit incomplete coverage. Gitignore
   semantics are preserved: `runTool` children start with an empty environment, so the child PATH
   now carries a reviewed git executable and the hardened git configuration (R1-01).
5. **Result schema** carries the buckets: `scope.unexamined`, `scope.failed`, `scope.suppressions`
   (`src/domain/types.ts`, `src/commands/check.ts`, `schemas/check-result.schema.json`).
6. **The tool is never pointed at an empty relevant scope**: with the pinned experimental target
   selection, opengrep hangs on a target with no inventoried relevant files (observed on a
   Python-only tree through the quality-error pack, which is composed for every stack). The recipe
   returns `unsupported` from the inventory alone — and an explicit error when the inventory itself
   could not be established (unreadable entries, the walk cap), since "no relevant files" is a
   claim an incomplete inventory cannot support.

## Repairs the honesty rules exposed in the reference application

- `e2e/notes.spec.ts` used an inline `import('@playwright/test').Page` type; opengrep reported a
  PartialParsing failure and withheld the file from its examined list — replaced with a top-level
  type import.
- The tool's built-in default ignore silently skipped `tests/` (the authorization runner
  `tests/authorization/run-authorization.mjs` was never scanned) — replaced by the reviewed ignore
  policy above.

## Observed

- `tests/scanners/pack-failures.test.ts` (new; the real pinned scanner through the CLI, one policy
  copy broken per case): **7/7** — missing detection-depth pack, missing core pack, invalid rules,
  gitignored vulnerable file, inline nosemgrep, target `.semgrepignore` cannot shrink the scope,
  unreadable directory. Each reaches an explicit error (or a recorded-suppression pass for the
  cannot-affect case) and the audit exits 1 where required.
- `tests/scanners/adapters.test.ts` 18/18 (new inventory-verification case),
  `tests/scanners/quality-opengrep.test.ts` 4/4, `tests/scanners/recipes-cli.test.ts` 2/2, the
  unit suite 574/574, typecheck and lint clean.
- Full `tests/scanners/audit-cli.test.ts`: **19/19** on the final post-change run (743 s). Two
  earlier post-change runs each had environmental failures, both diagnosed and fixed in this
  subphase: first ENOSPC (the machine's data volume sat at 100% — 1.5 Gi free of 466 Gi — and
  filled during the suite; the failed report write exits 1 with the reason, which is itself the
  P1.2 regression working as designed), then the empty-relevant-scope hang above.
- Recorded limitation: approved-suppression records (a reviewed record waiving a suppression)
  belong to the deferred P2.4/P6 machinery; until it exists, every target suppression is treated
  as unreviewed.
