# P3.3 evidence — Supabase tokenizer and final-state inventory (observed 2026-10-16)

A-13/A-14, and the static half of F-06. The migration inventory is a conservative SQL tokenizer
over an ordered final state: every shape the governing plan names is a permanent fixture,
API exposure comes from reviewed configuration only, and every wording stays inside the evidence
actually observed.

## What changed

1. **New tokenizer** (`src/security/sql-tokens.ts`): statements split only on semicolons outside
   single-quoted strings (`''` doubling, `E''` backslash escapes), quoted identifiers (`""`
   doubling), line comments, nested block comments, and dollar-quoted bodies (`$$` and `$tag$`).
   Function bodies keep their internal semicolons; commented-out SQL never reaches a matcher;
   unquoted identifiers fold to lowercase while quoted identifiers keep case and identity. No SQL
   parser dependency enters the pack.
2. **Ordered final-state evaluation** (`src/security/migrations.ts`, A-13): create/drop/rename
   tables (a rename carries its protection state), RLS enable/disable/force (later statements
   overwrite — an enabled set is no longer monotonic), policy create/alter/drop (permissive vs
   restrictive, roles, operation, using/check true), grants/revokes as final privilege sets (a
   revoke clears; grant-then-revoke is silent), views with `security_invoker`, security-definer
   functions (the `set search_path` pin is looked for in the definition header — a body-level
   pin no longer silences the rule), and storage buckets (named or positional insert, `update
   storage.buckets set public`). Findings are read off the final state.
3. **Exposure from reviewed configuration** (A-14): `supabase/config.toml [api].schemas`, read
   as bounded text (absent/unparsable defaults to `public`, recorded in the result's `limits`).
   A `create schema` statement never adds exposure — previously every created schema was
   auto-exposed and the `rls-missing` check ignored schema exposure entirely.
4. **Bounded wording** (A-14): a write grant under enabled RLS is medium severity and never
   called a proven bypass ("The grant itself does not bypass RLS … review"); the implicit-UPDATE
   case names the `with check` default instead of claiming automatic vulnerability;
   public-bucket publication is separated from proven sensitive exposure; `rls-missing` states
   what was observed (no RLS state change in the migrations read; reachability depends on the
   grants in effect and the recorded API exposure).
5. **Gaps are recorded, not silent**: the recipe coverage note and the analyzer's `limits`
   result name dynamic SQL and DO blocks inside function bodies, exposure mechanisms beyond
   `[api].schemas`, live-database effective access (P7/P8 probes), and files skipped at the
   review bounds (counted, with the reason).
6. `recipes.ts`: the migration recipe's doc comment and coverage note updated to the
   final-state claim with the recorded gaps.

## Observed (2026-10-16)

- New suites: `tests/security/sql-tokens.test.ts` (14 tests) and `tests/security/migrations.test.ts`
  (22 tests) — 36/36. The fixture battery covers every required plan shape: enable→disable across
  files, later enable, commented enable, quoted identifiers and case folding, same-line
  statements, SELECT-first write grants, all privileges, multiple roles, revoke, dropped and
  renamed tables, unexposed schemas, reviewed-config exposure, intentional public SELECT,
  implicit UPDATE check, broad additional permissive policy and dropped policy, restrictive
  policy, definer search-path (header vs body), dollar-body phantom DDL, public bucket
  insert/update/positional, RLS-protected anon writes bounded (A-14), and skipped linked inputs
  recorded as limits.
- The corpus seed's five migration findings (S21–S25) are additionally pinned at the analyzer
  level — rules, severities (high), and exact locations (rls-missing file-only; `:7`, `:10`,
  `:12`, `:17`).
- Corpus regenerated (`tests/corpus/measure-corpus.mjs`): security 31/38, quality 17/36 —
  **zero seed outcome changes**; the 3-line diff is metadata only (generated_at, the
  measured-build pointer 90eed2a→6981fcb, audit_out_digest).
- Fast suite 610/610 (42 files); scanners suite 75/75 (8 files), including audit-cli 19/19;
  typecheck and lint clean; preflight OK (184 mandatory tasks still open).

## P3.2 leftover caught during this verification (fixed here, disclosed)

`tests/scanners/adapters.test.ts` had drifted from the production invocation in two ways: it
passed the pack **directory** as `--config` (P3.2 added `manifest.yaml` beside the packs, and a
directory load parses it as a rule file → `InvalidRuleSchemaError`), and it omitted the
production `--experimental` flag. Under runTool's stripped child environment (no `LANG`), the
legacy engine read `detection-depth.yaml` with the ASCII codec and died on the UTF-8 em-dashes
P3.2 added to the pack comments → exit 2, empty report → three adapter tests failed at the P3.2
HEAD. Production scans were never affected (they pass the pack files and `--experimental`; the
`--experimental` engine reads pack YAML independent of the locale). The test now loads the two
reviewed pack files with `--experimental`, mirroring the production invocation; the full
scanners suite is green after the fix.

## Limitations and scope

- Accuracy against held-out apps is the auditor's measurement (p0_d_03). The live half of A-14
  (effective grants/RLS explanations against a real database) is P7.4; the Supabase live
  linter/probe is P8.3.
- Reviewed shapes only: dynamic SQL (`EXECUTE`/`format`) and DO blocks inside function bodies
  are not evaluated; schema-qualified names split at the first dot; `revoke … on all tables in
  schema` is not applied (single-table revokes are); reported roles are the reviewed
  anon/public set (grants to other roles are tracked but silent); exposure covers only the
  `[api].schemas` key (other Supabase exposure mechanisms are unreviewed); temp/unlogged tables
  are not tracked.
- The measured-build pointer in `EXPECTED-outcomes.json` records the parent commit (6981fcb):
  the regeneration ran from the working tree before this commit landed.
