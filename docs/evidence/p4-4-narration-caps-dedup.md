# P4.4 evidence — narration/tells, caps and independent dedup (observed 2026-10-17)

F-08, A-18, A-20 per the governing plan's six items. The Done gate: caps cannot erase evidence;
unrelated findings cannot overwrite security results; narration has measured recall/precision and
visible limitations.

## What changed

1. **A-18 — dedup folds only proven vulnerability equivalence** (`src/audit/report.ts`): the fold
   identity was `location|category` — two unrelated credentials at one line, or six advisories on
   one lockfile line, folded into one row and erased each other. The fold identity is now proven
   equivalence: the same credential identity (the digest), the same advisory id (the rule id the
   OSV recipe reports), or the same canonical rule at the same location — with the canonical rule
   coming from an explicit reviewed equivalence map (`RULE_EQUIVALENCE`: the core pack's pattern
   rules and the depth pack's taint rules that detect one vulnerability class — innerhtml,
   command injection, SSRF). Folding never infers equivalence from location or category alone.
   The fold keeps both provenances and the higher severity (A-7 unchanged).
2. **A-20 — detect all findings before any display limit** (`src/quality/tells.ts`): the analyser
   dropped findings at scan time (a per-rule cap of 60 and a total display budget) — a late
   high-severity debugger statement vanished behind early placeholder comments, and the machine
   results were incomplete. The analyser now emits every detected tell; the machine results are
   complete; the report renders the highest-severity rows first (its sort is severity → exposure →
   id, in place since A-7) and the fix-first display cap (ten rows) reconciles: the rendered
   section states the omitted count with the reason and names the machine results as the complete
   record.
3. **F-08 — the remaining tell families** (`src/quality/tells.ts`): undocumented environment
   variables (a `process.env` key that the reviewed `.env.example` does not document), hallucinated
   imports (a bare package specifier that package.json never declares — the route applies only
   when the declared set is known), inconsistent helper naming (mixed camelCase/snake_case
   function declarations in one file), and redundant validation (the same guard repeated on
   consecutive lines). Each is labelled a signal; node builtins, relative and path-alias imports
   are not package specifiers, and the analyser's own emit and pattern-definition lines are
   exempt from the hallucinated-import route.
4. **The narration recall measurement** (plan item 2): recall is measured on enumerated comment
   instances — not one hit per file. The calibration gate
   (`tests/scanners/staged-quality.test.ts`): a fixture with ten enumerated narration comments and
   ten genuine rationale comments must yield recall of at least 0.7 on the narration instances and
   zero false narration findings on the rationale comments.
5. **QUAL-09 control note** updated to the wired reality (the new families, the recall
   measurement, the detect-before-cap contract).

## Observed (2026-10-17, real tools)

- `tests/audit/report.test.ts`: 22/22 — the A-18 battery: a quality-low and a payment-critical
  finding at one line yield two rows with a critical security verdict; two unrelated credentials
  at one line stay independent; the same credential identity reported by two tools folds into one
  row with both provenances; six distinct advisories on one lockfile line stay six rows; the
  equivalent SSRF pattern/taint pair folds at one sink; and the fix-first display cap reconciles
  (ten rendered of twelve detected, the omission stated, nothing dropped from the results).
- `tests/scanners/staged-quality.test.ts`: 21/21 — the recall harness (ten enumerated narration
  instances and ten rationale comments: recall ≥ 0.7 measured per instance, zero false narration
  findings on the rationale comments) and the A-20 flood (a late high-severity debugger statement
  survives 130 earlier placeholder tells in the machine results).
- The self-audit restored to its recorded accepted finding: the first hallucinated-import pass
  flagged the analyser's own regex-definition and emit lines (the pattern text contains a quoted
  `', '` sequence) — the exemption now covers the emit and pattern-definition lines, and the
  specifier shape check rejects the non-package capture.
- Fast suite 610/610 (42 files); lint clean; build clean; the corpus regenerated security 31/38,
  quality 22/36 — **zero seed changes** (the 3-line diff is metadata only); preflight OK.
- The scanners gate: 9 files, 94/94 (recorded during this subphase's P4.3-era run; the P4.4
  additions ride in the staged-quality and report suites counted above).

## Limitations and scope

- The tell families are heuristics labelled as signals — never proof of authorship or of absence
  of review; the narration recall/precision are measured on the calibration fixture and reported
  in the gate, and the independent held-out measurement stays with the auditor (p0_d_03).
- The registry health route (P4.3) covers npm packages; the hallucinated-import route verifies
  the declared set only — whether an imported package actually exists in the registry is
  dependency-health's route.
- Near-duplicate helpers and mixed-paradigm structure are not detected in this build (the
  QUAL-09 limitation is unchanged on that point; the inconsistent-naming family is a per-file
  style signal, not a duplicate-helper detector).
