# P3.5 evidence — product-level planning and detection (observed 2026-10-16)

A-17, the payments/self-detection half of A-32, and F-09's P3.5 share (the AI-evidence half of
F-09 is P8.4 per the ledger split).

## What changed

1. **A-17 — python-web plans static analysis** (`profiles/python-web.yaml`): `static_analysis` is
   required at pr and release; the description and support constraints name the supported
   families (SQL injection, SSRF, path traversal, cookie attributes from the detection-depth
   pack) and keep the expansion families (framework secret handling, template injection,
   Bandit/Ruff) as recorded gaps. The obsolete "static analysis is deliberately NOT required …
   JavaScript/TypeScript only" text is gone, and detect.ts's matching banner now states the
   supported families instead of a blanket unsupported claim.
2. **The opengrep inventory covers Python** (`OPENGREP_SOURCE_EXTENSIONS` gains `.py`), and the
   intended scope is **pack-relative**: a pack's rules declare their languages, so a file outside
   them cannot be an unexamined gap for that pack. The core and quality packs are
   JavaScript/TypeScript only; the detection-depth pack declares python and intends the Python
   sources. An empty language scope is an explicit unsupported with the reason, and the
   aggregation refinement means an empty-language-scope sibling never masks a passing sibling's
   real results — the P3.1 findings-carrying and error rules are unchanged.
3. **A-32 — detection reads executable evidence** (`src/audit/detect.ts`): dev-only Vite/Vitest
   no longer classifies anything as a browser SPA — a production browser-framework dependency,
   or Vite plus a shipped `index.html`, is required, so SecHard itself detects as `unknown` with
   the unsupported-stack gap instead of react-spa + payments. Payment evidence requires
   executable shapes: a line-start SDK import, a production payments dependency (unchanged), or
   quoted event-name string literals. The loose "mentions stripe AND webhook" text check is
   deleted — it was the class of check that matched SecHard's own adapter, matcher definition,
   and explanation prose.
4. **Quick/standard/deep selection in one registry table** (`DEPTH_RECIPE_SELECTION` in
   `src/commands/audit.ts`): quick skips the history scan, browser-output inspection, and live
   HTTP, each reported with its skip reason; standard runs the full reviewed set; deep runs the
   same set and the report states that honestly — additional deep behaviour requires reviewed
   safe-execution preconditions before it can be added, never a silent alias or automatic target
   code execution.

## Observed (2026-10-16, pinned opengrep v1.30.0 through the compiled CLI)

- **A-17 acceptance**: a Python-only Flask fixture (`tests/fixtures/audit/python-only`) through
  `hardening audit --depth standard`: the static-analysis check passes ("examined 1/1 inventoried
  relevant files; sibling pack had no applicable language scope"),
  `hardening.taint-sql-injection-python@app.py:16` and `hardening.taint-ssrf-python@app.py:30`
  fire, the parameterized and literal-URL twins stay silent, and the report's detection line
  states the supported families. Quick depth runs static analysis too (it is not in the quick
  skip list). Pinned as the audit-cli test "a Python-only app reaches the planned static
  analysis…".
- **A-32/F-09**: `tests/audit/detect.test.ts` — SecHard itself (via `packageRoot()`) detects as
  not-payments and not-browser-SPA; dev-only Vite/Vitest fixtures detect as `unknown` with the
  unsupported-stack gap and no react-spa profile; a self-shaped repository with matcher
  definitions, explanatory prose, and a commented import keeps payments/webhooks unknown; a real
  webhook handler (line-start import + quoted event literals) is still detected; a vanilla Vite
  app with an entry point is still a SPA; the flutter fixture composes the generic checks with
  the explicit unsupported-stack gap.
- Detection suite 43/43; fast suite 610/610 (42 files); example real-build 5/5; scanners suite
  76/76 (8 files), including audit-cli 20/20; typecheck and lint clean; preflight OK.
- Corpus regenerated: security 31/38, quality 17/36 — **zero seed outcome changes**; the 3-line
  diff is metadata only (generated_at, the measured-build pointer, audit_out_digest).

## Limitations and scope

- The AI-evidence half of F-09 is P8.4 (runtime-AI profile behaviour); until then the exact AI
  coverage warning is preserved unchanged.
- The quality-errors pack has no Python rules: on a Python-only app that check reports
  unsupported (could-not-check) rather than a fabricated pass — the expansion families stay
  recorded gaps.
- Pack-relative scope maps the declared rule languages (javascript/typescript/python) to
  extensions; a pack declaring only unrecognised languages never narrows its scope, and a file
  dropped from one pack's scope is still intended by any pack whose languages cover it.
- The scanLimit-800 import-scan bound, the fixture/exclusion rule for feature detection (never a
  blanket removal from security scans), and the bounded walk caps are unchanged.
