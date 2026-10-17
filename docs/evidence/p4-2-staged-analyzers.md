# P4.2 evidence — four real analysers, execution-safe configuration (observed 2026-10-16)

F-07: the four staged quality analysers (duplication, complexity, dead code, module structure)
are real tools run for real, with SecHard-owned configurations — replacing the not-wired state
the audit recorded. The catalogue's four verifications (QUAL-03/04/05/06) already declared the
recipes; this subphase wired the handlers, the tool provisioning, and the configurations, and
updated the four stale "Not wired in this build" control notes.

## What changed

1. **The isolated tool package** (`tools/quality/` — plan item 3): a private package whose
   committed lockfile pins the reviewed exact versions (jscpd 5.4.1, knip 6.41.0,
   dependency-cruiser 17.0.1 — pinned at 17.0.1 because 18.x refuses this runner's Node and 16.x
   crashes on it), with `allowBuilds: {}` semantics via pnpm's `onlyBuiltDependencies: []` and
   the frozen-install route. Lizard 1.24.1 runs from a private virtual environment
   (`tools/quality/venv`). The audit uses absolute executables from that package — no npx, no
   target PATH, no global install, no install into the audited project.
2. **Four analyser modules** (`src/quality/staged.ts`): each runs its tool via the process
   layer, parses its real output (jscpd JSON clone pairs with both sites and the duplication
   percentage; Lizard per-function CSV with cyclomatic complexity, length and parameters; Knip
   unused files/exports/dependencies; dependency-cruiser `summary.violations`), and reports
   findings with both locations, the scanned scope in the notes, and the tool version in the
   recipe diagnostic. A missing tool is an explicit unsupported (P4.1: provisioning is separate
   from checking); a tool crash is an error carrying the diagnostic — never an empty success
   (plan item 6).
3. **Execution-safe configurations** (`ci/configs/quality/`): SecHard's own jscpd, Knip and
   dependency-cruiser configurations. Knip's config-loading plugins are all disabled and the
   entry declarations are SecHard's own — no target JS/TS config import via jiti. The
   dependency-cruiser rule file is static JSON (never an executable config), with rules for
   dependency cycles and UI → database/server-only imports matched against raw import
   specifiers (the alias and the relative-upward forms); the target's webpack/JS configuration
   is never loaded, and a target tsconfig.json is only ever parsed as data for path resolution.
4. **The toolchain note**: dependency-cruiser's rule matching runs against raw import
   specifiers on the pinned version (tsconfig alias resolution did not apply), so the reviewed
   patterns name both forms explicitly; recorded in the QUAL-06 control note.

## Observed (2026-10-16, real provisioned tools)

- **Corpus positives through the compiled CLI** (the Done gate): a corpus audit plans and runs
  all four checks — QUAL-03 duplication: 1 clone (formatPrice/legacyFormatter, 11 source files
  scanned, 3.3% duplicated lines); QUAL-04 complexity: 19 functions analysed, 1 finding
  (computeScore at CCN 10, the Q19 calibration); QUAL-05 dead code: 12 findings over 5 files
  (the unused left-pad dependency, the dead utils/format.ts file, and their siblings);
  QUAL-06 module structure: the UI data-access violation (app/dashboard/page.tsx). The five
  staged corpus seeds (Q03/Q04/Q05/Q19/Q27) flip to fired: quality 17/36 → **22/36**.
- The seed→finding matcher pins exact rule ids, so the five staged seeds' rule strings moved
  from their pre-landing recipe-name placeholders to the real analyser rule ids
  (`knip-unused-dependency`, `jscpd-clone`, `knip-unused-file`,
  `lizard-cyclomatic-complexity`, `depcruise-no-ui-database-access`) — the corpus-contract
  change that lands with the analysers.
- Clean twins: the complexity twin (a simplified computeScore) stays silent; used dependencies
  (next, react) produce no dead-code finding; allowed server-layer imports produce no
  module-structure finding on non-UI files; server API routes are excluded from the UI rule.
- `tests/scanners/staged-quality.test.ts`: 5/5 — the four corpus positives, the clean twins,
  and the execution-safety contract: a hostile next.config.js (proven executable in an isolated
  validation step) is never loaded during the scans, and the audited tree is byte-identical
  before and after (tree digest).
- An application the tools cannot apply to is **unsupported, not an error**: no
  JavaScript/TypeScript sources (jscpd/lizard/dependency-cruiser) or no package.json (knip)
  each yields an explicit unsupported with the reason — the Python-only and FastAPI fixture
  audits carry the four staged checks as could-not-check, never as failures (the P4.1 contract
  extended: a failed or omitted install cannot claim completion, and neither can an empty
  applicable scope).
- Fast suite 610/610 (42 files); lint clean; build clean; preflight OK.
- The corpus diff: exactly five `fired: false → true` seed flips (Q03/Q04/Q05/Q19/Q27) plus the
  measured-build metadata — the intended change this subphase exists for.

## Limitations and scope

- Lizard cannot parse JSX/TSX in its own directory walk, so the analyser names every source
  file explicitly (bounded by the shared scan walk, 1200 files) — recorded in the QUAL-04 note.
- dependency-cruiser 17.0.1's tsconfig alias resolution did not apply on this runner, so the
  reviewed module-structure patterns match raw import specifiers (the alias and
  relative-upward forms) — recorded in the QUAL-06 note.
- Python-source duplication (jscpd) and Vulture for Python dead code are recorded gaps
  (QUAL-03/QUAL-05 notes).
- The staged corpus seeds' rule strings moved to the real analyser rule ids (disclosed above);
  the security seeds are untouched.
- Knip's reduced plugin precision is documented in its control note: with every config-loading
  plugin disabled, framework-specific entry detection is limited to the declared entry patterns.
