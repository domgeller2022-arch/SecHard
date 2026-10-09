# Batch Q checkpoint

Batch Q of `docs/audit/2026-10-08-remediation-plan.md`, worked on the owner's explicit instruction
("lets start with batch Q"). Scope: Q1 (quality controls), Q4 (the tells analyser), Q6 (the
calibration corpus), gap A2 (the reference-app M8 findings), and gap D3 (catalogue versioning).

## Status

- **Q1 — twelve quality controls (QUAL-02…13): defined, catalogue v2 with a migration note.** All
  `draft`; six wired to recipes, six honestly `unsupported` with the required external analyser
  named.
- **Q4 — the tells analyser: verified.** Ten rules, each judged against real false positives found
  in this repository's own self-audit. The rationale/narration distinction is the design centre:
  a comment explaining WHY is not a tell.
- **Q6 — calibration: measured.** Recall **1.0** over 18 seeded issues, precision **1.0**, clean
  twin **0 findings**; floors 0.8/0.6/0 in the reviewed thresholds policy, cleared with room.
- **A2 — the reference-app M8 defects: fixed and verified live** (curl against the production
  build: X-Powered-By absent, CSP + COOP + CORP present; `updateNote` writes the body; write
  errors surfaced).
- **D3 — catalogue versioning: enforced.** v2 carries a migration note; schema and tests make a
  silent ID-set change impossible.
- **The self-audit checkpoint — "SecHard passes its own quality audit": met with one recorded
  exception.** Zero high or critical findings; the single accepted LOW is the deliberately absent
  licence (a recorded owner decision the hygiene check reports, because an unrecorded absence is
  indistinguishable from an oversight). No comments were trimmed: the repository's comments are
  rationale, the narration rules were calibrated to say so, and the plan's "trimming" outcome was
  resolved by precision rather than deletion.

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` | 522 passed, 33 files (calibration, self-audit, migration, composition assertions) |
| `pnpm run test:scanners` | 31 passed (4 new opengrep quality-pack tests with the real binary) |
| `pnpm run test:integration` / `test:example` | 8 / 5 passed (example rebuilt) |
| `pnpm run typecheck` / `typecheck:tools` / `lint` | clean |
| Calibration | recall 1.0 / precision 1.0 / clean twin 0 — floors 0.8 / 0.6 / 0 |
| Self-audit | 1 accepted LOW finding (licence decision), 0 high/critical, pinned by test |
| Reference app headers | verified live: X-Powered-By absent, 7 security headers present |
| opengrep quality pack | every rule fires on its seed; clean twin silent |

## Defects found in this batch (all fixed, most with regression tests)

1. **A real `.skip` in this repository's own test fixture** (the change-report detection material)
   — found by the test-quality analyser while calibrating; composed at runtime per the
   repository's established technique.
2. **Five false-positive classes in the tells/test analysers**, each found by the self-audit and
   fixed with a stated principle: CSS hex colours read as comments (`#b00020`), wrapped prose read
   as narration, Playwright parameter destructuring read as assertion-free tests, the analysers'
   own pattern text read as findings (mention-vs-use, decided by string-literal context), and
   config/tools files flagged for local addresses.
3. **The pinned opengrep crashes on non-ASCII rule packs** under the minimal recipe environment
   (locale-dependent codec in `config_resolver.py`). Reviewed packs are ASCII-only now; the pack
   header records the constraint. Upstream bug recorded.
4. **Semgrep-style rule-id mangling** (config path prefixed onto every id) — the adapter now
   normalises to the reviewed pack namespace.
5. My own typecheck turned a `@ts-expect-error` mention in a comment into a live compiler
   directive — the exact suppression-discipline the QUAL-02 rule exists to flag, demonstrated by
   the batch itself.

## Deviations from the plan

1. **Q2/Q3 (external analyser provisioning) are staged**, not skipped: jscpd, Lizard, Knip,
   dependency-cruiser, formatters, and axe-core each need reviewed provisioning under the
   dependency policy (age delay, digests, fixtures) and are their own reviewed change. The six
   recipes that could be owned honestly are wired; the rest report `unsupported` with the tool
   named — the same standard Batch W set for unwired recipes.
2. **Q6's external targets (Juice Shop, NodeGoat) are deferred**: they are security-recall corpora
   first and need disposable containers; the quality calibration is the local corpus plus the
   repository self-audit, which is where the real precision work happened.
3. **Q5 (advisory AI review) is untouched**: it needs the owner's explicit opt-in, a provider
   decision, and a data-handling statement.
4. The "trimming comments" outcome was resolved by calibration, not deletion: the self-audit
   shows the repository's rationale-comment style is distinguishable from narration, which is a
   measured claim, not a stylistic judgement.

## Blockers and owner actions needed

1. **Review and approve the twelve new control definitions** (`controls/controls.yaml`, catalogue
   v2 migration note). They are `draft` and deliberately unresolved; a release evaluation blocks
   on them until approved.
2. **Review the quality profile** (`profiles/quality.yaml`) — note QUAL-08 is `never` exceptable: a
   skipped or gutted test is a control removal, not a risk to accept.
3. **Review the thresholds** (`policy/quality-thresholds.yaml`) — calibration values, not security
   limits; recalibration is a reviewed change.
4. `authorised_batch` stays `U` until the owner updates it; Batch S (standards) or X (expansion)
   can follow.

## Owner review list

- `src/quality/tells.ts` — the rules, the rationale/narration distinction, and the calibration
  comments naming the real false positives each guard against.
- `tests/corpus/` — the seeded-issue record (`SEEDED-ISSUES.yaml`) and the clean twin; recall and
  precision are measured against this list.
- `tests/quality/self-audit.test.ts` — the pinned self-audit outcome.
- `controls/controls.yaml` — catalogue v2 and the twelve definitions.
- `examples/nextjs-supabase/app/notes/` and `next.config.ts` — the M8 fixes, and the live-header
  verification record in the progress entry.

## Known limitations and risks

- The tells analyser's precision is calibrated on this repository and the corpus; a different
  codebase's comment style may need recalibration, which is a reviewed thresholds/policy change.
- The opengrep locale bug is worked around (ASCII-only packs), not fixed upstream.
- Registry-based dependency health (deprecation, major drift) is not measured in this build.
- The quality score covers only the checks that ran; the report states the coverage caveat beside
  it, and quality never changes the security verdict.

## Proposed next batch

**Batch S — standards**: requirement-level incorporation of the blueprint's standards (ASVS L1,
Top 10 2025, API Top 10, WSTG citations, SSDF, OSPS), the coverage matrices, and the agent-guidance
source curation. Batch X (expansion) remains the other candidate. Owner preparation: authorise the
batch and review this checkpoint.
