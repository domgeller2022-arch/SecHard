# P4.3 evidence — finish remaining quality capabilities (observed 2026-10-17)

QUAL-02/08/10/11/12/13 per the governing plan's seven items. Every new capability has a real
positive, a safe negative, a tool-failure and scope-failure path, and a marker/integrity test
(plan item 7); the catalogue notes were updated only after acceptance.

## What changed

1. **QUAL-02 — the strict type probe** (`src/quality/correctness.ts`): tsc runs from the isolated
   tools/quality package with SecHard's own strict configuration
   (`ci/configs/quality/tsconfig.strict.json`) against the application's type graph — the app's
   tsconfig is read as data (paths preserved, rewritten relative to the temporary merged
   configuration; tsc 7 has removed `baseUrl`), and the merged configuration is written to a
   private temporary directory. Module-resolution diagnostics (missing type dependencies, an
   absent tsconfig or node_modules, non-JSON tsconfig) are coverage gaps, never findings; the
   remaining strict diagnostics are findings. The handler merges the marker/any counts with the
   probe's findings and records the coverage state.
2. **QUAL-08 — test quality**: unchanged by design — coverage ratios and mutation scores need an
   isolated executed suite, which the audit isolation model forbids until P5.1; the gap stays
   named in the control note.
3. **QUAL-10 — formatting** (`src/quality/staged.ts`): Biome runs check-only with SecHard's own
   configuration (`ci/configs/quality/biome.json` — the target's biome.json is never discovered
   via `--config-path`), and Ruff format --check runs from the private virtual environment with
   SecHard's own `ruff.toml` for Python sources. Neither tool writes. Naming-consistency signals
   stay in the vibe-tells analyser.
4. **QUAL-11 — repository hygiene additions** (`src/quality/hygiene.ts`): committed generated
   artifacts (dist/.next/build/out present on disk and not covered by the target's .gitignore),
   and licence-description accuracy (a README claiming an open-source licence without a committed
   LICENSE file — an owner's private/no-licence choice is described accurately and never
   relabelled as open-source readiness).
5. **QUAL-12 — registry health** (`analyzeRegistryHealth`): bounded reviewed queries (at most 60
   packages per audit) against the approved npm registry — deprecation, major drift of two or
   more majors, and staleness beyond 24 months. Offline or failed queries are recorded as
   unknown, never as healthy; non-npm lockfiles name their ecosystem gap; this never replaces
   OSV advisory scanning.
6. **QUAL-13 — frontend quality**: the `quality/frontend-quality` handler is wired with its
   precondition named precisely (an approved running application target and a browser, which P8
   supplies) — a precondition gap, not an unimplemented handler or a fabricated verdict.
7. **Provisioning**: typescript 7.0.2 and @biomejs/biome 2.5.15 joined the isolated
   tools/quality package; ruff 0.17.1 joined the private virtual environment, whose
   `requirements.txt` now pins every package by wheel hash (`--require-hashes` route — the P4.1
   item-4 completion). The lint walk skips the provisioned venv.

## Observed (2026-10-17, real provisioned tools)

- `tests/scanners/staged-quality.test.ts`: 18/18 — the strict probe (a genuine strict error
  flagged at its location with the tree byte-identical; coverage gaps for a missing type graph
  and a missing tsconfig), formatting (Biome and Ruff positives, a formatted-file negative,
  check-only proven by the tree digest), the hygiene additions (committed generated artifacts and
  the licence mismatch flagged; a gitignored dist not flagged), registry health (major drift and
  deprecation flagged from stubbed registry documents; offline queries recorded as unknown; a
  non-npm lockfile never queried; the query bound recorded), and the frontend precondition
  reported as unsupported with the P8 reason.
- The strict-probe hardening discovered and handled two real toolchain facts: tsc 7 has removed
  `baseUrl` (the app's paths are rewritten relative to the temporary merged configuration), and
  under the stripped child environment tsc 7 writes its diagnostics to stderr (both streams are
  parsed).
- Fast suite 610/610 (42 files); lint clean (the provisioned venv is skipped); build clean;
  preflight OK.
- The corpus regenerated: security 31/38, quality 22/36 — **zero seed changes** (the 3-line diff
  is metadata only: generated_at, the measured-build pointer, the run digest). No seed pins the
  new capabilities; the corpus application has no node_modules, so the strict probe records a
  coverage gap rather than findings.
- The five control notes (QUAL-02/10/11/12/13) updated to the wired reality with the recorded
  gaps named precisely.

## Limitations and scope

- QUAL-08's coverage ratios and mutation scores stay recorded gaps until P5.1's isolated
  execution model permits running the target's test suite.
- The strict probe requires the application's tsconfig (strict JSON) and installed type
  dependencies; JSONC tsconfigs, missing dependencies, and unresolvable modules are coverage
  gaps named in the diagnostic.
- The registry health route covers npm packages; the PyPI/Go/Cargo ecosystem routes are recorded
  gaps, and the query bound (60) leaves the remainder unknown by design.
- The frontend quality routes execute against an approved running target with P8's preconditions;
  P4.3 delivers the preconditioned handler, not the browser tooling.
- The strict probe's diagnostic paths are normalized through realpath and matched against the
  scanned files because macOS temp-dir symlinks report /private/var while the walk used /var.
