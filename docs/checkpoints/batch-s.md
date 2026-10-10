# Batch S checkpoint

Batch S of `docs/audit/2026-10-08-remediation-plan.md`, on the owner's instruction ("lets start
with S"). Scope: S1 (mapping data model + coverage matrices), S2 (per-standard work), S4
(comparison-project records), D7 (Scorecard pinning). S3 staged with a recorded reason; the SLSA
release row staged because no release exists.

## Status

- **S1: verified.** A `standard-mapping` schema, eight mapping files (518 requirement entries),
  generated coverage matrices for every standard, and a per-application standards-coverage
  statement in every audit report.
- **S2: verified** for ASVS, Top 10 2025, API Top 10 2023, WSTG citations, SSDF, OSPS, MVSP,
  ASD SBD, MCP (link-only), and AUTH-03 (RFC 9700) at catalogue v3.
- **The plan's acceptance criteria all run as tests:** no unmapped ASVS id, no invalid chapter,
  exact 2025 Top-10 names, API1–API10, WSTG citation on every test recipe (or a recorded reason),
  42 active SSDF tasks, link-only MCP with zero adapted text.

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` | 535 passed, 34 files (13 new standards tests) |
| `pnpm run test:scanners` | 31 passed; six new opengrep rules fire on fixtures, clean twins silent |
| `pnpm run test:integration` / `test:example` | 8 / 5 passed |
| `node tools/generate-coverage.ts` | 8 matrices + index under `controls/coverage/` |
| ASVS mapping | 345/345 mapped; L1 70: 12 automated, 20 manual, 38 gap |
| Top 10 2025 | names fetched from the published edition and pinned by test |
| SSDF | 47 ids from the official PDF: 42 active + 5 recorded consolidations |
| OSPS | 64 active requirements + 1 retired, from the published baseline |

## OSPS Level 1 applied to SecHard itself

Mechanically or documentarily **met**: CI default-lowest and minimal permissions (trust-tested
workflows); untrusted-metadata handling (the zizmor template-injection fix); secrets scanning
wired in CI with zero findings; standardized dependency tooling with a committed lockfile;
generated-executable exclusion (`tools/bin` is gitignored); branch status checks and test
execution enforced by the hardening-gate job; dependency and SAST policy evaluation in CI;
build and test documentation (README); support-scope statements (`docs/supported-versions.md`);
contribution guide (CONTRIBUTING.md); threat model and trust model (docs/); automated test-run
policy (AGT-03 and the review manifest).

**Owner-blocked misses, recorded decisions rather than oversights**: no licence file and no OSI
licence (deliberate: private, sole-maintainer, undistributed - `release_scope` in the owner
decisions); repository deliberately private, so public-readability and public-change-record
requirements do not hold; security contacts recorded as not-applicable-private; contributor
legal-assertion (DCO/CLA) not configured - an owner decision to make or decline explicitly.

**Pending, not failed**: release-side requirements (unique version identifiers, signed
manifests, verification instructions) attach to releases, and none exists - they become live
with Batch D; branch-protection enforcement is a platform setting awaiting the GitHub test
environment; SBOM and VEX generation are not implemented.

**D7, recorded**: when OpenSSF Scorecard is adopted for CI posture checking, it must be
SHA-pinned like every external action - the Trivy/KICS compromise lesson applies to it exactly.

## Defects found in this batch (fixed as found)

1. **This repository's own Batch Q note misnamed a Top 10 category** - it called A10 "software
   and data integrity failures"; the published 2025 list's A10 is Mishandling of Exceptional
   Conditions (integrity is A08). Found by fetching the real list instead of trusting memory;
   corrected in `controls.yaml` and in the chapter-level mappings.
2. **The plan's counts were estimates, and the real editions differ**: SSDF's "42 tasks" is the
   active count (47 ids including 5 consolidated); OSPS's "67 requirements" is 64 active plus 1
   retired. The mappings follow the published data and record the discrepancies.
3. **Semgrep `paths` filters and unquoted rule patterns** produced silent non-matches and rule
   load failures while wiring the six new rules - the same class of tool defect Batch Q hit;
   both recorded in the rule pack and adapter tests.
4. **My own first instinct for a missing canonical URL was to guess one** - caught by rereading
   the rule against it; the stand-in entry now states the limitation instead.

## Deviations from the plan

1. **S3 (agent-guidance curation) is staged**, with the three sources already licence-recorded:
   adapting them regenerates the guidance an agent reads, and that deserves its own reviewed
   pass rather than the tail end of a 518-entry mapping session.
2. **The SLSA row is staged to Batch D**: no release exists for provenance to attach to.
3. **MCP is link-only** exactly as the plan requires; its licence makes anything else unusable.
4. **astoj's IaC project could not be recorded**: the plan names it without a URL, and guessing
   repositories is how wrong sources enter records. A gap, stated.

## Owner review list — the checkpoint's core ask

- **ASVS L1, line by line**: `controls/coverage/asvs.md` (the L1 rows), against the official
  text in `controls/mappings/data/asvs-5.0.0-en.csv`. The owner verdict on each L1 gap is the
  batch's review.
- **Top 10 2025, line by line**: `controls/coverage/owasp-top-10.md`.
- `controls/controls.yaml` — AUTH-03 at catalogue v3, and the fourteen WSTG-citation edits that
  deliberately invalidated approvals (Batch D re-approves the sheet).
- `docs/checkpoints/batch-q.md` remains open for the twelve QUAL approvals; this batch adds
  AUTH-03 and the WSTG re-approvals to that list.
- The OSPS owner-blocked table above: accept the private/licence/contact decisions explicitly or
  change them.

## Known limitations and risks

- The audit report's standards statement is composition-level truth: it says what the composed
  profiles and wired recipes could check for the audited application. Full ASVS-style verification
  is an assessment service, not a scan; the report's wording says so.
- Requirement-level summaries are paraphrases; the vendored CSV carries the official text for
  the owner's line-by-line review.
- The six new opengrep rules are syntactic with stated limitations (recorded in each rule and in
  the SSRF fixture, which includes the indirect-routing shape the rule honestly misses).

## Proposed next batch

**Batch X — expansion** (Supabase depth, runtime-AI profile, live exposure probes, more stacks)
or **Batch D — adoption and release** (independent adoption, maintenance, release verification —
which the SLSA/SBOM/release-signing staged items belong with). Owner preparation: authorise the
batch and review this checkpoint, ASVS L1, and Top 10 2025.
