# P3.2 evidence — vulnerable/safe security-rule matrix (observed 2026-10-16)

A-15/A-16, F-04/F-05/F-09 re-check. Every audit counterexample is fixed at the rule, every missed
ordinary shape fires, and every safe twin is a pinned-binary CLI regression under the permanent
rule matrix.

## What changed

1. **A-15 false positives silenced at the rule** (`ci/configs/opengrep-rules/detection-depth.yaml`):
   - SQL: the sink is any argument except when the statement text is a string literal — the
     reviewed bound-parameter usage (`query("... id=$1", [req.query.id])`) stays silent however
     tainted the parameters are. `focus-metavariable` was tried first and is broken on the pinned
     build for intermediate-variable flows (the corpus S08/S09 shapes stopped firing); the
     structural literal-text exclusion is the fix, bisected empirically and recorded in the pack.
   - Stripe: a handler whose covered function shape (function, async function, one- or
     two-parameter arrow) assigns the verified event from `constructEvent` is silent; uncovered
     shapes still fire (conservative).
   - Paths: a join of two fixed strings stays silent; the joined value must be a non-literal.
   - CORS: the wildcard+credentials message is now factual — browsers refuse that exact
     combination, so it is a broken configuration, not a proven exposure (was: "any site can read
     authenticated responses").
2. **A-16 missed ordinary shapes now fire:**
   - split `body = await request.formData(); body.get(...)` as a SQL taint source
   - assigned Python query variables (any execute argument is the sink; a literal statement text
     with bound parameters is excluded)
   - Python `requests` SSRF (new rule `hardening.taint-ssrf-python`)
   - Python `send_file`/`open` traversal (new rule `hardening.taint-path-traversal-python`)
   - session cookies with omitted httpOnly (new rule `hardening.cookie-missing-attributes`)
   - reflected-origin CORS exposure (new rule `hardening.cors-origin-reflection`)
3. **The permanent matrix**: `ci/configs/opengrep-rules/manifest.yaml` — one entry per rule in the
   three packs (35) with languages, expected grade, confidence, recorded limitations, and fixture
   anchors (twins/corpus/adapters), enforced by `tests/scanners/rule-manifest.test.ts`
   (pack↔manifest lockstep; twin anchors resolve; every fires-anchor has its safe twin).
4. **explanations.ts**: the CORS entry corrected to the factual wording; the four new rules carry
   explanations.

## Observed (2026-10-16, pinned opengrep v1.30.0 through the compiled CLI)

- New acceptance `tests/scanners/rule-twins.test.ts`: 19 vulnerable/safe twin cases (one per
  counterexample shape plus its twin) — every missed shape fires, every safe twin silent —
  20/20 including the audit run, re-verified twice.
- `tests/scanners/rule-manifest.test.ts`: 4/4.
- Corpus (`tests/corpus/measure-corpus.mjs` regenerated): security 31/38, quality 17/36 — **zero
  seed outcome changes vs the pre-P3.2 baseline** (the S08 concat still fires; the old positives
  and negatives are intact; the regenerated baseline is committed as the disclosure).
- Full suites: audit-cli 19/19 (516 s); adapters, quality-opengrep, recipes-cli, pack-failures,
  and the unit suite (40 files) all green; typecheck and lint clean.
- One diagnostic detour recorded: `focus-metavariable` in taint sinks silently dropped
  intermediate-variable flows on the pinned build (corpus S08/S09 stopped firing) — caught by the
  corpus disclosure diff, bisected (old/no-source/no-focus variants), and replaced with the
  structural exclusion.

## Limitations and scope

- Accuracy against held-out apps is measured by the independent auditor (decision p0_d_03); this
  matrix pins claims and twins, not a general coverage promise.
- A constant-text SQL variable (`const Q = "SELECT $1"; query(Q, [tainted]))` is not recognised as
  a literal and may flag (conservative direction).
- The Python rules land in the packs here; planning them for Python audits is A-17 (P3.5).
- Approved-suppression records remain with the deferred P2.4/P6 machinery.
