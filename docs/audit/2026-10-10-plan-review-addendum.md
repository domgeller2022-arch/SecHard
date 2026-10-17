# Addendum to the 2026-10-10 follow-up remediation plan

**For the implementing AI.** This is an independent review of
`docs/audit/2026-10-10-follow-up-remediation-plan.md` against the fix brief and the code at
`f3c9727`. Apply these corrections and additions before starting Batch F1.

Where this addendum conflicts with the plan, this addendum wins, unless the owner decides otherwise.

**Verdict.** The plan is solid:
- it covers all 17 brief items;
- it keeps the brief's rules;
- the file and line references were spot-checked and are accurate (gate-policy 48/71,
  evaluator 834, detect `SKIP_DIRS`, planner 142, `makeResult` call sites, gitleaks severity,
  `.gitignore:5`, hardening-pr line 64);
- the design choices are good: F-15 as the single root fix for F-01, a total secret classifier,
  manual companion checks, one opengrep process for several packs, and an owner decision register.

It needs the corrections and additions below. Two of them (A-1, A-3) prevent new security or
honesty defects.

---

## Corrections

### C-1 Rule 2 cites the wrong item (an error in the original brief)

Rule 2 says "F-06 exists because this happened". The narrowing incidents are **F-08**: the
narration rule was narrowed during the self-audit. **F-10** is related: the self-audit omitted a
recipe. Fix the reference in both the brief copy and the plan.

### C-2 Probe P7 must keep testing the `unknown` path

The plan rewrites P7 to construct the secret finding "as it would appear post-classification
(category set, severity critical)". That duplicates P6, since critical is already non-waivable,
and stops testing the exact hole the audit found.

Keep the original and add one:
- **P7a:** `category: 'secret'`, severity **`unknown`**, valid exception → blocked,
  `waiver.forbidden`. This proves the belt-and-braces ban in F-02 step 5 works.
- **P7b:** a gitleaks-origin finding with **no `category` field** and severity `unknown`, valid
  exception → blocked. If the classifier ever regresses and stops setting `category`, the ban must
  still hold. Key the ban on `category === 'secret'` **or** a secret-scanner origin (`tool.name` in
  the declared secret-scanner list), not on the category alone.
- Add a test that the classifier is total: no gitleaks or client-asset finding leaves it with
  `unknown` severity or without a category.

### C-3 F-16 options table is missing two options

Add:
- **"Make SecHard public"**: the simplest option. No secrets, and pinning by commit SHA still gives
  immutability. It is an owner visibility decision.
- **"Audit mode only for adopters"**: run `hardening audit` locally or from a vendored copy, with no
  callable workflow.

Also note that a reusable workflow in a private repository can only be called from other
repositories after the owner enables Actions access sharing for that repository, and that setting
does not help `actions/checkout`, which still needs a credential. Present all five options for
O-5.

---

## Additions

### A-1 Knip and dependency-cruiser can execute the audited app's code (F-07)

Knip's plugins load and **execute** JavaScript/TypeScript config files (`vite.config.ts`,
`next.config.js`, `vitest.config.ts`, and so on) via jiti; this is documented by Knip.
dependency-cruiser can likewise load JavaScript config, such as a webpack config, when told to.
Running them on an untrusted vibe-coded app breaks audit mode's contract that "no recipe executes
application code" (gap D1).

Required:
1. Run Knip with config-loading plugins **disabled**. Use SecHard's own Knip config, which turns off
   every plugin that imports a config file, and accept the reduced precision as a stated
   limitation. Alternatively, mark the recipe `requires_isolation: true` and refuse it until the
   isolation model exists.
2. Run dependency-cruiser with SecHard's own config. Never pass the target's
   `--webpack-config`/`--ts-config` if they are JS.
3. Add a test: a fixture whose `vite.config.ts` writes a marker file when executed. After
   `hardening audit`, the marker must not exist, and the tree-checksum test must still pass.
4. jscpd and Lizard only read files. Confirm this by the same marker test.

### A-2 How the npm-based quality tools are provisioned (F-07)

jscpd, Knip, and dependency-cruiser are npm packages, not release binaries, so the plan's
"per-platform map in `toolchain.yaml`, digest-verified by `fetch-tools.mjs`" does not describe how
they get installed.

Specify:
- an isolated `tools/quality/` package with its own committed lockfile;
- installed with `--frozen-lockfile`, the 7-day release-age policy, and `allowBuilds: {}` (no
  install scripts);
- invoked by absolute path from that package's `node_modules/.bin`;
- the lockfile integrity hashes are the pin; record them in `toolchain.yaml` as this tool class's
  identity.

Lizard's wheel pinned by SHA-256 into a venv (as the plan says) is fine.

### A-3 Appendix A stops being independent once the implementer has read it (F-12)

The implementing AI now knows all 63 seeds. Rules written in F2 will be tuned, consciously or not,
to exactly those seeds, so Appendix A recall after F2 measures fit, not detection. This is the same
self-grading problem F-12 exists to remove.

Required:
1. Keep Appendix A as a **development corpus**, and label it so.
2. Accuracy claims must come from a **held-out corpus the implementer has never seen**. The owner
   (or an independent auditor) supplies a second blind app at each checkpoint, along with OWASP
   Juice Shop and NodeGoat.
3. Report three numbers per checkpoint:
   - self-authored corpus (self-consistency);
   - Appendix A (development);
   - held-out (accuracy).

   Only the held-out number may appear in the README as detection accuracy.
4. Juice Shop and NodeGoat need ground-truth lists. Use their published vulnerability and challenge
   lists, mapped to SecHard categories, recorded with source and version. A target without a ground
   truth gives no recall number.

### A-4 False-positive path for never-waivable secrets (F-02)

With high and critical secrets never waivable (O-1), a gitleaks **false positive** (a test fixture,
example key, or documentation sample) would block forever. Consumers currently have no supported way
to record triage, since only SecHard's adapters set `triage`.

Add a reviewed path:
- a consumer record `.hardening/triage.yaml`, with each entry naming finding fingerprint, rule,
  file, `false_positive`, a reason of 20+ characters, reviewer, and date;
- it is subject to the PR base-records rule (F-14), so a PR cannot triage its own new findings;
- the evaluator accepts `false_positive` only from this record, never from a result file;
- revalidation when the file content changes (the fingerprint no longer matches → finding returns);
- tests: a valid triage clears the finding; a triage added in the same PR does not; a changed
  fingerprint reopens it.

This also gives P10/F-17.4 a clean home: `accepted` is not a triage value at all, and acceptance
goes through exceptions.

### A-5 F-03 needs a stated stage behaviour, or every PR and audit gets noisier (owner decision O-10)

The plan plans manual companion checks "whenever the tool check is planned", at every stage. That
means:
- every pull request in every adopting repository blocks until 24 manual attestations exist and are
  fresh;
- every `hardening audit` report gains 24 more open items.

Which behaviour is wanted is an owner decision. The recommended default:
- **release:** companion required and blocking;
- **pr:** companion planned and reported as "awaiting manual review"; the control is **not
  `satisfied`** (that was the bug) but does not block the PR unless the profile says so;
- **audit mode:** companions grouped in the report as a short "Things you need to confirm yourself"
  checklist, separate from findings, so a non-coder sees them as tasks, not 24 failures.

Whatever is chosen, M1's assertion stays: those controls are never `satisfied` without the manual
half.

### A-6 SQL parsing pitfalls for the Supabase rules (F-06)

"Line/pattern based, no SQL parser" will produce false negatives and false positives unless it
handles:
- statement splitting on `;` **outside** strings, comments, and **dollar-quoted bodies**
  (`$$ … $$`, `$fn$ … $fn$`). Function bodies contain semicolons;
- case-insensitivity and line breaks inside statements;
- quoted identifiers and `if not exists`;
- unqualified table names, which default to `public`;
- RLS enabled in a **later** migration file. The plan says "same migration set", which is right:
  evaluate across all files in timestamp order;
- policies, grants, and bucket inserts written in different but equivalent forms
  (`grant all privileges`, `to anon, authenticated`, `public := true` via `update storage.buckets`).

Write a small tokenizer: strings, comments, and dollar-quotes, then statement split. Give each rule a
fixture that exercises at least one of these shapes.

### A-7 Rank every finding by exposure, not only secrets (F-02 step 6)

The exposure ranking is specified only for secrets. Apply the same ordering to all findings:
- a request-reachable injection, SSRF, auth, or XSS finding in a route, API handler, or Server
  Action outranks repository and workflow hygiene at equal severity;
- de-duplicate across tools by location and category. During F-04 the old regex SSRF rule and the
  new taint rule will both fire on the same line; the report should show one finding.

### A-8 Python coverage for the taint pack (F-04)

The plan adds Python sources and sinks to the taint pack. At `f3c9727` the opengrep recipe is
effectively JS/TS-only ("Python static analysis not run"). Confirm the security recipe is planned
and executed for the `python-web` profile, and add a Python vulnerable/fixed fixture pair through
the CLI. Otherwise the Python rules exist but never run.

### A-9 Make the "could not check" list readable (audit report)

A default audit lists about 40 "not implemented in this build" lines, which drown the useful
content for a non-coder owner. Group the list by area (authorization, sessions, quality structure,
release, …) with counts and a one-line plain-English meaning per group, and keep the full list in
an expandable or appendix section. No information is removed; only the presentation changes.

---

## Owner decision register: additions

| ID | Decision | Recommendation |
| --- | --- | --- |
| O-10 | F-03 stage behaviour of manual companions (A-5) | Release blocking; PR "awaiting review", not satisfied and not blocking unless the profile says so; audit as a checklist |
| O-11 | Knip config-loading plugins: disable them, or require isolation (A-1) | Disable by default; isolation-only full mode later |
| O-12 | Who supplies the held-out corpus each checkpoint (A-3) | The owner or an independent auditor, never the implementer |

## O-9 is resolved

The follow-up audit report is supplied alongside this addendum as
`docs/audit/2026-10-10-follow-up-audit.md`. Commit it unchanged.
