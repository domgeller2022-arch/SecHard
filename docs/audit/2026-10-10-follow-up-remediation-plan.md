# Follow-up remediation plan — 2026-10-10

Successor to `docs/audit/2026-10-08-remediation-plan.md` (Batches R/W/A/Q/S are complete; X and D
are not). Companion to three documents, all in this repository's `docs/audit/`:

- `2026-10-10-fix-brief.md` — the actionable brief (source: `SecHard-fix-brief-2026-10-10.md`
  outside the repo). Finding IDs (F-01 … F-17) and probe IDs (P1 … M1) refer to it, including its
  Appendix A (independent test app) and Appendix B (probe tests).
- `2026-10-10-follow-up-audit.md` — the full audit reasoning behind the brief, supplied by the
  owner on 2026-10-11 and committed unchanged (owner item **O-9**, resolved).
- `2026-10-10-plan-review-addendum.md` — an independent review of a first draft of this plan. Its
  additions (A-1 … A-9) and corrections (C-1 … C-3) are incorporated into the text below. Where
  the addendum and an earlier draft of this plan conflicted, the addendum won; where it conflicts
  with anything here, the owner decides.

**Verification status.** Before this plan was written, every code-level claim below was re-read in
the current tree and the file:line references in each item were confirmed as of 2026-10-11. Items
whose evidence is behavioural (probe outcomes, measured recall) cite the brief's audit runs and are
re-verified by the acceptance tests as they land.

A coding agent works one authorised batch at a time (F1 → F2 → F3), stops at each checkpoint, and
the owner reviews. Every rule in the brief's section 0 applies, restated here because they are the
terms of the work:

1. **Run real checks.** A recipe is done only when the CLI (`hardening audit` / `hardening check`)
   produces a real result on a real target. Adapter unit tests alone do not count.
2. **Never weaken a security test or rule to get green.** If a rule fires on SecHard's own code,
   fix the code or record an owner-approved exception. Items F-08 (the narration rule was narrowed
   during the self-audit) and F-10 (the self-audit omitted a recipe) exist because this happened.
   [C-1: an earlier draft repeated the brief's citation of F-06 here — the brief's error, corrected
   in the repo copy.]
3. **No self-graded accuracy claims.** Detection rates are measured on code the rule author did
   not write (F-12). Report the numbers as measured, including misses.
4. **Security-relevant loosening needs owner review before merge.** Coverage requirements,
   severities, waiver rules, rule narrowing, exclusions — each one listed in the checkpoint's owner
   review list.
5. **No real secrets anywhere.** Fixture secrets are synthetic and composed at runtime.
6. **SecHard never modifies the audited project.** The tree-checksum test must pass for every new
   recipe.
7. **Keep `docs/implementation-progress.md` and `CHANGELOG.md` accurate.** Watch every CI run to
   completion after each push (the Batch W monitoring defect must not recur).
8. **Do not push to `main` without the owner's go-ahead.** Work on a branch.

---

## 1. Already fixed and verified — do not redo

The follow-up audit confirmed by execution; no work is planned on these:

- scanners wired into `check` and `audit`;
- Linux tool pins fetched and verified on linux-x64;
- fail-closed PR and release gate;
- CI green on runs 10–13;
- `hardening audit PATH` with zero setup, never writing to the target;
- waiver bypasses H1/H2/H3 fixed;
- base-branch records used for PRs;
- client-asset secret markers extended, JWT role decoding works;
- report escaping and redaction in place;
- truthful README;
- tests no longer dirty the tree;
- reference-app M8 fixes;
- environment-branching CLI tests (both branches still assert fail-closed exits).

---

## 2. Batch structure

| Batch | Purpose | Items | Depends on |
| --- | --- | --- | --- |
| **F1** | Small fixes with large impact | F-01, F-15 (pulled forward as F-01's root fix), F-02, F-03 | — |
| **F2** | Detection depth — the main gap | F-04, F-05, F-06, F-07, F-08, F-09 | F1 (F-15's relativization is assumed by the corpus work) |
| **F3** | Correctness, honesty, documentation | F-10, F-11, F-12, F-13, F-14, F-16, F-17 | F1; F-12's recall numbers also depend on F2 |
| **X** | The 2026-10-08 plan's remaining expansion batch (X2/X3 leftovers) | per the 2026-10-08 plan | F2 |
| **D** | Adoption and maintenance; owner re-approves every control against the final review sheet | Steps 15–16 | all above |

Checkpoint stops after F1, F2, and F3 (format in section 8). The manual-review halves introduced by
F-03 make some Batch D re-approvals heavier — plan for that in D's schedule.

**Where the addendum's items live:** A-1 and A-2 → F-07 steps 2–3; A-3 → F-12 and sections 6/8;
A-4 → F-02 step 9 and F-17.4; A-5 → F-03 step 2 (O-10); A-6 → F-06 step 1; A-7 → F-02 steps 7–8;
A-8 → F-04 step 5; A-9 → the "Report readability" item in Batch F3; C-1 → section 0 rule 2 and the
brief copy; C-2 → F-02 steps 5–6 and the probe table (P7a/P7b); C-3 → F-16.

---

## 3. Batch F1 — small fixes with large impact

### F-01 + F-15 — relativize every location at result creation (F-15 is the root fix of F-01)

**Evidence (verified).** `src/execution/recipes.ts:294–310`: `runQualityErrors` takes
`(finding.location ?? '').split(/[/:\\]/)[0]` as the first path segment and requires it to be in
`PRODUCTION_SOURCE_DIRS`. Audit mode passes absolute locations (`/tmp/.../app/...`), so the first
segment is `''`, the `console.log` rule never fires in audit mode, and the password-logging
`console.log` in the test app was silently held back. Separately, only the SARIF writer relativizes
locations (`src/audit/report.ts:620`); `report.md`, `report.html`, and `report.json` carry absolute
machine paths.

**Fix (F-15, done first; F-01 then needs no separate change).**
1. Add an `appRoot` parameter to `makeResult` (`src/commands/check.ts:95`). All four call sites are
   in `src/commands/run.ts` (lines 213, 238, 259, 298) and already have `paths.appRoot` in scope.
2. In `makeResult`, relativize `finding.location` before redaction:
   - if the location starts with `appRoot` + separator, strip the prefix;
   - if it is an absolute path **not** under `appRoot`, keep it as-is (rare; honest);
   - if it starts with `http://` or `https://`, never touch it (live HTTP findings are URLs);
   - apply the same rule to every `scope.files` entry.
3. `runQualityErrors`' first-segment check (`recipes.ts:303`) then works on both relative and
   absolute targets with no change of its own. Do not "fix" it by adding a second relativization
   there — one boundary, one rule.
4. Regression test: run the recipe against an **absolute** target path containing `app/x.ts` with
   `console.log`; the finding must be reported. A `scripts/x.ts` `console.log` must still be held
   back. Use a unique temp path string (e.g. `sechard-f15-<random>`); assert the string appears in
   no report format (`report.md`, `report.html`, `report.json`, SARIF) — one test covers both the
   F-15 acceptance and the audit-mode variant of F-01.

**Dependencies.** None. Everything else in this plan reports through `makeResult`, so land F-15
first; later items inherit correct paths for free.

### F-02 — secret findings: classify, title, de-duplicate, ban waivers, rank by exposure

**Evidence (verified).** `src/adapters/gitleaks.ts:65–75`: every finding is emitted with
`severity: 'unknown'`; the `Fingerprint` field is already captured into `resource` and used in
`stableFindingId`, so a de-duplication key exists. `policy/gate-policy.yaml:71` sets
`critical_findings_never_waivable: true` — which is exactly why an `unknown` service-role JWT was
waivable (probe P7 passed the gate). `src/domain/evaluator.ts:831–844` makes `unknown` severity
acceptable whenever any triage label other than `'unresolved'` is present. Ranking treats all
severities generically, so four duplicate `unknown` rows ranked #7–10 below an unpinned Action.

**Fix.**
1. **Classifier.** New post-processing step between the adapter and the result:
   `src/evidence/secret-severity.ts`. Input: findings whose `tool.name` is `gitleaks` or
   `client-asset-inspection`. Reuse the client-asset markers and JWT role-decoding already in the
   codebase. Classes:
   - **critical** — privileged or live material: Supabase `service_role` JWT (decode the `role`
     claim), `sb_secret_`, Stripe `sk_live_`/`rk_live_`, OpenAI `sk-` (20+ chars), `sk-ant-`,
     `AKIA…`, `ghp_`/`gho_`/`ghs_`, private-key blocks, database URLs with an embedded password
     (`postgres://user:pass@…`);
   - **high** — any other credential-shaped rule hit;
   - **low** — publishable/anon keys (`sb_publishable_`, `anon` role JWT), informational.
   Post-classification there is **no unknown-severity secret finding**; the classifier is total.
2. **Titles/explanations.** Each class gets a plain-English title and explanation, e.g.
   "Supabase service-role key exposed: it bypasses all row-level security". Keep the original rule
   id in a field for traceability.
3. **De-duplicate across `gitleaks/repository` and `gitleaks/history`.** Key: `rule_id` +
   relative file + `Fingerprint`. Keep one finding — prefer the repository scan — and append to its
   detail: "also present in committed history (commit scan)". With F-15 landed, the file component
   of the key is relative and stable across the two recipes.
4. **Category marker.** Add optional `category?: 'secret'` to the Finding type; the classifier sets
   it. The evaluator reads the category, not the tool name, so a future secret scanner is covered
   by declaring the category.
5. **Waiver ban (C-2 hardening).** In `policy/gate-policy.yaml`, next to
   `critical_findings_never_waivable`: `secret_findings_never_waivable: true`. The evaluator keys
   the ban on `category === 'secret'` **or** `tool.name` in the policy-declared secret-scanner list
   (`gitleaks`, `client-asset-inspection`) — **not** on the category alone. If the classifier ever
   regresses and stops setting `category`, the ban must still hold; that is what probe P7b asserts.
   The ban covers severities `critical`, `high`, **and** `unknown` (the last is belt-and-braces;
   the classifier makes it unreachable — see the totality test below). This is owner decision
   **O-1**: high secrets become never-waivable.
6. **Classifier totality test (C-2).** A test that no `gitleaks` or `client-asset-inspection`
   finding leaves the classifier with `unknown` severity or without `category: 'secret'`. The
   classifier is total or it is a bug.
7. **Ranking (A-7: every finding, not only secrets).** "Fix these first" ranks by severity, then
   by exposure, for **all** findings. Exposure classes: `request-reachable` (a finding in a route,
   API handler, or Server Action — injection, SSRF, auth, XSS findings here outrank repository and
   workflow hygiene at equal severity), `client-reachable` (file imported by a `'use client'`
   module — the client-assets machinery already computes this), `committed-history` (from the
   de-dup annotation). A critical-with-exposure finding outranks everything: in Appendix A the
   service-role key and the Stripe live key must be the top two rows, `critical`, one row each.
8. **Cross-tool de-duplication (A-7).** During F-04 the old regex SSRF rule and the new taint rule
   will both fire on the same line; de-duplicate across tools by location + category so the report
   shows one finding. Keep the provenance of both in the finding's detail.
9. **False-positive path (A-4).** Never-waivable secrets need a reviewed way to record a false
   alarm (a test value, example key, documentation sample) — otherwise one gitleaks false positive
   blocks a consumer forever, since only SecHard's adapters currently set `triage`. Add a consumer
   record `.hardening/triage.yaml`; each entry names the finding fingerprint, rule, file,
   `false_positive`, a reason of 20+ characters, reviewer, and date. Rules of engagement:
   - it is subject to the PR base-records rule (F-14), so a PR cannot triage its own new findings;
   - the evaluator accepts `false_positive` **only** from this record, never from a result file;
   - revalidation: when the file content changes so the fingerprint no longer matches, the finding
     returns;
   - tests: a valid triage clears the finding; a triage added in the same PR does not; a changed
     fingerprint reopens it.
   This is a security-relevant mechanism — list at checkpoint (owner decision **O-1** scope:
   confirm `false_positive` requires the full record, not a bare label).

**Acceptance (from the brief, updated per the addendum).** Test app top two rows are the
service-role key and the Stripe live key, `critical`, one row each. P7a and P7b → blocked,
`waiver.forbidden` (section 7). The totality test passes. A `false_positive` triage record clears
a planted false alarm; the same record added in the PR that introduces the finding does not.

**Status note (12 October 2026, F1 checkpoint).** The Appendix-A "top two rows" acceptance is
**pending the F2 corpus** (F-12) — the corpus does not exist yet, so that measurement has not been
made and no claim is made. The equivalent properties are already pinned by the F-02 scanner tests:
the service-role key and the Stripe live key are classified `critical`, reported exactly once each
(repository/history folded), and the exposure ordering that puts them ahead of workflow hygiene at
equal severity is unit-tested in the report suite. The full Appendix-A before/after run lands with
F2.

**Owner review.** O-1 (waiver ban scope), and the severity classes themselves are
security-relevant hardening — list at checkpoint.

### F-03 — "mixed" controls pass on partial tool output with no manual evidence

**Evidence (verified).** `src/domain/planner.ts:142`: `required_coverage:
method.coverage === 'automated' ? 'complete' : 'partial'` — mixed methods get `partial`, and
nothing else is required of them. `planner.ts:105–149`: one check is planned per verification
method that survives the stage's `required_methods` filter; `planner.ts:47–48`: `manual_attestation`
is in the `pr`/`release` fallback method lists, but the **profiles'** `required_methods` govern
(line 84–89), and the core profile's `pr` list does not include `manual_attestation`. Result: the
24 mixed-only controls (list in the brief) plan no manual check, and probe M1 shows SEC-01, CI-01,
GOV-01, WEB-01, AGT-01 `satisfied` on partial tool output with `manualEvidence: []`. The
implementation plan's definition — mixed means tool evidence **plus** reviewed manual evidence — is
not enforced anywhere.

**Fix.**
1. **Planner.** In the method loop (`planner.ts:105`), when a method has `coverage: 'mixed'` and
   its tool check is planned, also plan a manual companion check:
   - `check_id`: `${controlId}:manual_attestation:${method.recipe}/review:${input.stage}`;
   - `method: 'manual_attestation'`, `mode: 'manual'`, `required_coverage: 'partial'`;
   - `recipe`: the control's declared manual recipe if it has one, else `${method.recipe}/review`
     (e.g. `gitleaks/repository/review` = operator reviews the findings and records triage —
     finding triage **is** the manual half of secret scanning).
   The stage method filter applies to the tool check; the manual companion is planned whenever its
   tool check is. This is the honest reading of "mixed": the obligation exists whenever the method
   is exercised, independent of which stage lists happen to include `manual_attestation`.
2. **Stage behaviour (A-5, owner decision O-10).** Planning the companions "whenever the tool check
   is planned" at every stage would make every adopting PR block until 24 attestations exist and
   would add 24 open items to every audit report — honest, but unusable. The recommended default
   (adopt it unless the owner overrides):
   - **release:** companion required and blocking;
   - **pr:** companion planned and reported as "awaiting manual review"; the control is **not
     `satisfied`** (that was the bug) but does not block the PR unless the profile says so;
   - **audit mode:** companions grouped in the report as a short "Things you need to confirm
     yourself" checklist, separate from findings, so a non-coder sees tasks, not 24 failures.
   Whatever is chosen, M1's assertion stands: those controls are never `satisfied` without the
   manual half.
3. **Evaluator.** No new semantics needed: a control aggregates across its checks, and a required
   unmet manual check makes the control `unmet` with the existing `manual.missing` reason. M1's
   expected outcome falls out of composition. The stage behaviour above is a planning/reporting
   concern (`required`, report grouping), not an evaluator change.
4. **Where a tool truly gives complete coverage**, reclassify that method `automated` and require
   `complete` — candidate: CI-01's workflow analysis once F-05's zizmor permission rules land.
   Each reclassification is a security-relevant change; list at checkpoint (owner decision **O-2**,
   batch-at-a-time).
5. **Ripple effects.** Check counts change for the 24 controls at every stage that plans them:
   fixture-based plan tests, PR plan derivation (33 → more checks), consumer workflow expectations.
   Update them honestly — the count going up is the defect being fixed, not a test to appease.
6. **Manual-evidence freshness** already exists and gates; the companions inherit it. No new
   machinery.

**Acceptance.** M1: those controls `unmet` with `manual.missing`; supplying current manual
evidence flips them to `satisfied`. The change (and each later reclassification) is on the
checkpoint's owner review list.

---

## 4. Batch F2 — detection depth

Measured baseline at `f3c9727` on Appendix A: security 7/33, quality 17/30; a default Next.js
audit says "not implemented in this build" for 40 of 51 checks. Target after F2: security ≥ 26/31
statically checkable, quality ≥ 26/30 (floors re-set by the owner after F-12's measured numbers —
owner decision **O-3**).

### F-04 — taint-mode security rule pack

**Fix.**
1. New pack `ci/configs/opengrep-rules/taint-flows.yaml` using opengrep's `mode: taint` (opengrep
   is a semgrep fork; taint mode is supported). Sources: `req.query`, `req.body`, `req.params`,
   `searchParams.get(...)`, `request.nextUrl`, `await req.json()`, `formData.get(...)`, Python
   `request.args`, `request.form`, `request.json`. Sinks per the brief's table: SQL injection
   (`pool.query`, `client.query`, `db.execute`, `sequelize.query`, `knex.raw`, Prisma
   `$queryRawUnsafe`, Python `cursor.execute` with f-strings or `%`); XSS
   (`dangerouslySetInnerHTML={{ __html: … }}`, `innerHTML`, `document.write`); SSRF (`fetch`,
   `axios.*`, `got`, `node-fetch`, `http(s).request`, Python `requests.*` — this **replaces** the
   regex-only SSRF rule, which stays only until the taint rule's fixtures prove both sides);
   path traversal (`fs.readFile*`, `fs.createReadStream`, `path.join` into fs, `send_file`);
   open redirect (`NextResponse.redirect`, `res.redirect`, `redirect()` with tainted URL);
   command injection (`exec`/`execSync` with tainted string; Python `subprocess(..., shell=True)`).
2. Wiring: `runOpengrepWithPack` (`src/execution/recipes.ts:248`) takes one pack path. Change the
   signature to accept a list (opengrep takes repeated `--config` flags) and have the security
   recipe pass both `hardening-core.yaml` and `taint-flows.yaml`. One opengrep process, both packs —
   do not run the tool twice.
3. `dangerouslySetInnerHTML` with **any** non-literal value → at least **medium**, as a plain
   pattern rule in the taint pack (taint not required for this one).
4. Propagation through variables is the entire point: each rule's vulnerable fixture must include
   the indirect shape `const u = searchParams.get('url'); fetch(u)`, plus a fixed twin. The pinned
   binary must detect the vulnerable fixture and stay silent on the fixed twin **through the CLI**.
5. **Python must actually run (A-8).** At `f3c9727` the opengrep recipe is effectively JS/TS-only
   ("Python static analysis not run"). Confirm the security recipe is planned **and executed** for
   the `python-web` profile, and add a Python vulnerable/fixed fixture pair proven through the CLI.
   Otherwise the Python rules in the pack exist but never run.

### F-05 — pattern rules for common vibe-coded mistakes

One reviewed pack addition (`ci/configs/opengrep-rules/vibe-patterns.yaml`) with vulnerable/fixed
fixture pairs for each rule:

1. weak password hashing: `createHash('md5'|'sha1')` applied to a value named `password`/`pwd`;
2. JWT: `algorithm: 'none'`; `algorithms` containing `'none'`; a hardcoded string literal as the
   `jwt.sign`/`jwt.verify` secret;
3. insecure cookies: `cookies.set`/`res.cookie` with `httpOnly: false` or `secure: false`, or a
   session cookie without either;
4. CORS: `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true`;
   `cors({ origin: true, credentials: true })`;
5. weak randomness: `Math.random()` feeding a variable/function named token/id/reset/otp
   (name heuristic, stated as such in the rule's metadata);
6. logging secrets: `console.*` or a logger receiving a variable named password/token/secret/
   apiKey;
7. OpenAI/Anthropic SDK constructed in a `'use client'` file or with
   `dangerouslyAllowBrowser: true`;
8. dangerous Next.js config: `productionBrowserSourceMaps: true`,
   `typescript.ignoreBuildErrors: true`, `eslint.ignoreDuringBuilds: true`;
9. **zizmor `excessive-permissions` / `permissions: write-all` did not surface on the test
   workflow.** First step is an investigation, not a rule: run the pinned zizmor against Appendix
   A's `ci.yml` and read the raw output. If the rules exist in the pinned version and were filtered
   by the adapter, fix the filter; if the pinned version is too old, pin the newer one and
   re-verify the existing detections still fire. Record which it was in the checkpoint. Do not
   write a hand-rolled permissions rule while zizmor's own exists — that duplicates the upstream
   detection and would drift.

### F-06 — Supabase migration rules (starts Batch X1)

**Fix.**
1. Static SQL rules over `supabase/migrations/*.sql`, as a new internal recipe
   (`src/quality/supabase-sql.ts` using the existing internal-rule machinery) rather than opengrep
   patterns, because the first rule is cross-statement (per-file state: tables created vs tables
   with RLS enabled) and opengrep cannot express it cleanly. Rules:
   - table created in `public` (or another exposed schema) with no `alter table … enable row level
     security` in the same migration set;
   - policy with `using (true)` or `with check (true)`;
   - `grant all` or `grant insert/update/delete … to anon`;
   - `security definer` function without `set search_path` — flag harder when it updates privilege
     columns;
   - `insert into storage.buckets … public = true`;
   - view in an exposed schema without `security_invoker = true`.
   Line/pattern rules need a **small tokenizer first** (A-6): naive line matching false-negatives
   and false-positives on real migration SQL. The tokenizer handles strings, comments, and
   dollar-quoted bodies (`$$ … $$`, `$fn$ … $fn$`), then splits statements on `;` **outside**
   those — function bodies contain semicolons. The rules must additionally cope with:
   case-insensitivity and line breaks inside statements; quoted identifiers and `if not exists`;
   unqualified table names (they default to `public`); RLS enabled in a **later** migration file —
   evaluate across all files in timestamp order; and equivalent forms (`grant all privileges`,
   `to anon, authenticated`, `public := true` via `update storage.buckets`). Each rule gets at
   least one fixture exercising one of these shapes. Still no SQL-parser dependency.
2. **Then** integrate `supabase/splinter` — verify its licence **first** and record the verdict
   before any code; if it is not usable, record why and stop that sub-item.
3. **Then** the read-only live anon-key probe from the 2026-10-08 plan's X1 (it stays a live check,
   not static). Sequence: static rules → splinter → live probe; the static rules are valuable even
   if the later steps slip.

### F-07 — structural quality (the core of the "10x engineer" goal)

1. **Four analysers, staged and pinned like the scanners** (adapters in `src/adapters/`, one
   recipe each):
   - **jscpd** (MIT) — duplication; report clone pairs with both locations;
   - **Lizard** (MIT) — cyclomatic complexity, function length, parameter count. Lizard is a
     Python package: pin the wheel by SHA-256 and install it into an isolated venv created by the
     fetch step (same trust posture as the binary pins; do not require a system-wide pip);
   - **Knip** (ISC) — dead exports, unused files, unused dependencies, read from `package.json`
     (this covers the no-lockfile variant of Appendix A; the lockfile path stays with OSV);
   - **dependency-cruiser** (MIT) — import cycles, and a committed rule file forbidding UI modules
     from importing database or server-only clients (catches "data access mixed into a UI
     component").
2. **Provisioning (A-2).** jscpd, Knip, and dependency-cruiser are npm packages, not release
   binaries, so "per-platform binary map" does not describe their pin. Instead: an isolated
   `tools/quality/` package with its own committed lockfile; installed with `--frozen-lockfile`,
   the 7-day release-age policy, and `allowBuilds: {}` (no install scripts); invoked by absolute
   path from that package's `node_modules/.bin`. The lockfile integrity hashes are the pin —
   record them in `policy/toolchain.yaml` as this tool class's identity. Lizard stays as the
   wheel-pinned venv above.
3. **Execution safety (A-1, owner decision O-11).** Knip's plugins load and **execute** the
   audited app's config files (`vite.config.ts`, `next.config.js`, `vitest.config.ts`, …) via
   jiti; dependency-cruiser can likewise load JavaScript configs. Running them unconfigured breaks
   audit mode's contract that no recipe executes application code. Required:
   - run Knip with config-loading plugins **disabled**, using SecHard's own Knip config that turns
     off every plugin importing a config file; accept the reduced precision as a stated
     limitation (or, per O-11, mark the recipe `requires_isolation: true` and refuse it until an
     isolation model exists — recommended default: disable);
   - run dependency-cruiser with SecHard's own config; never pass the target's
     `--webpack-config`/`--ts-config` when they are JavaScript;
   - a marker test: a fixture whose `vite.config.ts` writes a marker file when executed. After
     `hardening audit`, the marker must not exist, and the tree-checksum test must still pass;
   - jscpd and Lizard only read files — confirm by the same marker test, not by assumption.
4. **Four internal rules** in the existing quality machinery:
   - swallowed Supabase error: `const { data } = await supabase.from(...)` with `error` never read,
     or `.then(({ data }) => …)`;
   - mock/demo data in production paths: `mockUsers`, `john@example.com`, `Lorem ipsum`, `fakeData`;
   - README commands that do not exist in `package.json` scripts (e.g. `npm run start:prod`);
   - duplicate-role libraries read from `package.json` when there is no lockfile: moment + dayjs,
     axios + node-fetch.
5. **Acceptance:** each detects its matching Appendix A item through `hardening audit` — jscpd the
   `formatPrice`/`formatMoney` clone, Lizard `computeScore`, Knip `legacyFormatter` + `left-pad`,
   dependency-cruiser the dashboard's data access, the internal rules their four seeds — **and**
   the A-1 marker test passes: nothing executed, nothing written, tree unchanged.

### F-08 — narration-comment rule recall

**Evidence (verified).** `src/quality/tells.ts` requires two identical identifiers shared between
comment and next line — catches 1 of ~12 typical narration comments.

**Fix.** Three additions, in order of safety:
1. verb-and-object restatement with synonym sets (fetch/get/load, query/select, render/return,
   check/verify, add/push, create/new) — the comment's verb+object restates the next line without
   sharing an identifier;
2. a density signal: a function where a narration-shaped comment precedes more than half of its
   statements is itself a finding (one finding per function, not per comment);
3. generic helper headers: "Helper function to …", "Utility to …", "This function …".

`RATIONALE_MARKERS` stays as the exemption. **Acceptance:** measured recall on Appendix A
narration comments ≥ 0.7 with the misses listed, and zero findings on SecHard's own rationale
comments — the second must not be achieved by narrowing the first (rule 2 of section 0).

### F-09 — detection fixes

1. **Payments enablement:** also enable payments when `package.json` depends on `stripe`,
   `@stripe/stripe-js`, `paddle`, or `lemonsqueezy`, **or** source mentions
   `checkout.session.completed`, `payment_intent.*`, or `invoice.paid` (extend the feature
   detection in `src/audit/detect.ts`).
2. **Webhooks:** a route reading such event types without `stripe.webhooks.constructEvent` or a
   signature check is a **critical BIZ-01 finding**, not a feature flag. One opengrep pattern
   pair (event-type mention ⊕ absent verification call) evaluated per file.
3. **Runtime AI gap banner:** when `runtime_ai` is enabled and no runtime-ai profile exists, the
   report gains an explicit "What we could not check" entry and the gap banner verbatim from the
   brief: "This app calls AI models; prompt-injection, spend-limit, and model-output safety checks
   are not covered."
4. **SecHard misdetected:** `src/audit/detect.ts:50–52` `SKIP_DIRS` lacks `tests`, `fixtures`,
   `examples`, `corpus` — SecHard detects itself as react-spa + supabase + payments from fixture
   content. Extend the skip set with a detection-exclusion list (`tests`, `examples`,
   `tests/fixtures`, `tests/corpus`, and the fixture directory convention). Detection walks the
   audited app, not SecHard's own test corpus. (SecHard auditing itself still sees its real `src/`
   and `examples/` reference app; the exclusion applies to stack detection, not to scanning.)

---

## 5. Batch F3 — correctness, honesty, and documentation

### F-10 — "passes its own quality audit" must use the real audit

1. `tests/quality/self-audit.test.ts` currently runs 5 of 6 quality recipes and omits the opengrep
   error-handling pack. Replace the harness: in the **scanner CI job** (tools fetched), run the
   actual `hardening audit` CLI on SecHard itself (excluding audit probes) and assert on the real
   result. The unit-suite variant keeps whatever runs toollessly, honestly named.
2. **Recalibrate empty-catch severity** — the pack rule detects, a small post-processing step in
   the recipe refines: empty catch **with an explanatory comment** → `low` (an intentional,
   visible suppression); no comment → `medium`; empty catch around **persistence or network
   writes** (supabase/db/fetch/axios inside the `try`) → `high`. Severity change → owner decision
   **O-4**, listed at checkpoint.
3. Known real findings from the brief's audit run: 4 high `quality-empty-catch`
   (`src/execution/process.ts:115`, `src/quality/common.ts:55`, `tools/generate-status.mjs:97`,
   `examples/nextjs-supabase/lib/supabase/server.ts:33`), 1 medium
   `api-unvalidated-response-consumption` (`tools/fetch-tools.mjs:115`), quality score 0. Fix each
   in code, or record an owner-approved exception (rule 2: no narrowing). Then update the
   changelog claim to whatever is true.

### F-11 — coverage matrices are gitignored

The root `.gitignore:5` rule `coverage/` also hides `controls/coverage/`. Fix: change it to
`/coverage/`, commit `controls/coverage/*.md`, add a `--check` mode to
`tools/generate-coverage.ts` and run it in CI so drift between mappings and matrices fails the
build.

### F-12 — independent calibration (replaces self-graded recall; A-3 tightens it)

**The honesty problem A-3 adds:** the implementing AI has now read every one of Appendix A's 63
seeds. Rules written in F2 will be tuned, consciously or not, to exactly those problems, so
Appendix A recall after F2 measures **fit**, not detection. The same self-grading problem F-12
exists to remove. Three corpora, three numbers:

1. **Development corpus — Appendix A** as `tests/corpus/independent-nextjs/`: a builder script
   composes the fixture at runtime (synthetic, runtime-composed secrets — never literal), one
   variant without a lockfile, one **with** a lockfile pinning lodash 4.17.15, axios 0.21.0,
   jsonwebtoken 8.5.1, next 14.0.0 so dependency advisories exercise. An expected-findings manifest
   carries one entry per seed, with the statically-checkable items separated from the declared
   not-statically-checkable ones. **Label it "development corpus" in every report of its numbers.**
2. **Held-out corpus (accuracy):** a fresh app the implementer has never seen, supplied by the
   owner or an independent auditor at each checkpoint (owner decision **O-12** — never the
   implementer, including this plan's author), with its own expected-findings manifest. This is the
   only number that may appear in the README as detection accuracy.
3. **External targets:** OWASP Juice Shop (MIT) and NodeGoat (Apache-2.0) as pinned external
   targets (pinned ref + digest), run in the scanner CI job or a scheduled job. Both need
   **ground-truth lists**: use their published vulnerability and challenge lists, mapped to
   SecHard categories, recorded with source and version. A target without ground truth gives no
   recall number.
4. Each checkpoint reports all three numbers — self-authored corpus (**self-consistency**),
   Appendix A (**development**), held-out (**accuracy**) — recall **and** precision per category,
   with misses listed. No README claim may exceed the measured value.

**Acceptance:** CI prints measured recall per corpus; floors are set by the owner (**O-3**) after
the first real numbers; README ≤ the held-out measurement, always.

### F-13 — standards mappings that overstate coverage

13 `method: automated` entries have no wired recipe (ASVS V10.4.4, V10.6.1; OSPS AC-04.01,
BR-05.01, QA-02.01, QA-03.01, QA-06.01; SSDF PO.3.3, PO.4.2, PW.1.2; MVSP 2.5, 3.1; ASD-SBD-5).
Fix: a test that every `automated` entry names at least one recipe present in
`src/execution/recipes.ts`; downgrade the 13 entries until their recipes exist. As F-04–F-06 land,
move the newly covered ASVS V1/V2/V3/V6/V7/V8/V11/V13/V14 gaps to `automated` — mappings update
with each rule batch, not in a lump at the end (context: ASVS 5.0.0 currently 22 automated, 54
manual, 257 gaps, 12 not applicable).

### F-14 — PR workflow record changes

`.github/workflows/hardening-pr.yaml`: the "use base-branch records" step (line 88) exits 1 when
the PR changes `.hardening/` records and later steps lack `if: always()`, contradicting the
CHANGELOG's claim that evaluation still runs. Fix: copy the base records first, run
validate/plan/check/report/gate on them with `if: always()`, keep the review-required failure as a
separate final step so the evaluation evidence and the review requirement are both visible.
Document the reviewed-merge path for a legitimate record change in `docs/ci-trust.md` so the owner
is never pushed toward bypassing the required check.

### Report readability — group the "could not check" list (addendum A-9)

A default audit lists ~40 "not implemented in this build" lines, which drown the useful content
for a non-coder owner. Group the list by area (authorization, sessions, quality structure,
release, …) with counts and a one-line plain-English meaning per group; keep the full list in an
appendix section. **No information is removed — only presentation changes.** This composes with
A-5's audit-mode checklist: the report's structure becomes findings → exposure-ranked fix list →
"things you need to confirm yourself" → grouped "could not check" areas → full appendix.

### F-15 — relative paths in every report format

Landed in Batch F1 as F-01's root fix (section 3). Cross-referenced here because the brief files
it under F3; the acceptance (no report format contains the audit root's absolute path, tested with
a unique temp path string) is asserted in F1's regression test and never un-done later.

### F-16 — consumer workflows while SecHard is private

`hardening-pr.yaml:64,185` and `hardening-release.yaml:47,142` check out
`domgeller2022-arch/SecHard` with the consumer's default token, which cannot read a private
repository — gate mode fails in every adopting repository. **This needs an owner decision first
(O-5); ask before implementing.** Options with trade-offs to present:

| Option | Trade-off |
| --- | --- |
| **Make SecHard public** | the simplest option; no secrets; commit-SHA pinning still gives immutability; purely an owner visibility decision |
| read-only deploy key / GitHub App token | works today; adopters hold a secret; revocation is manual per adopter |
| published release artefact (attached to a tag) | no secrets; versioned and digest-pinnable; SecHard must actually release, and the artefact is public while the repo is private |
| vendored pinned copy | zero infra; adopters drift until they re-vendor; update procedure needed |
| **audit mode only for adopters** | run `hardening audit` locally or from a vendored copy, with no callable workflow at all; no access problem, no gate in CI |

A reusable workflow in a private repository can only be called from other repositories after the
owner enables Actions access sharing for that repository — and even with that setting,
`actions/checkout` of the private repo still needs a credential. Present all **five** options for
O-5.

Implement the chosen option, document it in `docs/adoption.md`.

### F-17 — smaller items

Each is small; each still gets its acceptance:

1. **`--fail-on <severity>`:** `hardening audit --fail-on <severity>` exits 1 when findings at or
   above that severity exist; default stays exit 0, as documented. Test both exits.
2. **Typecheck on a fresh checkout:** `tests/domain/standards-coverage.test.ts:7` imports
   `../../dist/execution/recipes.js`, so `pnpm run typecheck` fails before `build`. Import from
   `src/` per the pattern Batch R established for tools.
3. **Reference-app CSP:** it allows `script-src 'unsafe-inline'`. Move to a nonce-based CSP via
   middleware — the Next.js-documented approach — not a looser header.
4. **Triage `accepted` (probe P10):** `src/domain/evaluator.ts:834` — any triage value other than
   `'unresolved'` makes an unknown-severity finding acceptable, including `accepted` with no
   exception record. **Per A-4, remove `accepted` as a triage value entirely:** acceptance is what
   an exception record is for, and A-4's `.hardening/triage.yaml` gives false alarms their own
   reviewed home. Triage labels then mean only `fixed`/`unresolved`-style progress states, and the
   evaluator's "triaged unknown is acceptable" branch applies to a far narrower, honest set — with
   `false_positive` accepted only from the triage record, never a result file. P10 (`accepted`, no
   exception) becomes structurally impossible; the probe stays as the regression that proves it
   stays impossible.
5. **AUTHZ severity (probe B1):** `policy/gate-policy.yaml:48` `blocking_severities: [critical,
   high]`, so a **medium** AUTHZ-01 finding passes today. The blueprint says unauthorized data
   access blocks regardless of scanner label. Add
   `blocking_controls_regardless_of_severity: [AUTHZ-01, AUTHZ-02, AUTHZ-03]` to gate-policy and
   enforce in the evaluator: an unresolved finding on those controls blocks at any severity,
   including `unknown`. Do not extend the list silently to other `never_exceptable` controls — the
   blueprint's wording is about unauthorized data access only (owner decision **O-7**).
6. **DNS pinning:** `src/audit/url-guard.ts:112` resolves DNS once (the vetted addresses are
   recorded); the live HTTP check then resolves again — a DNS-rebinding window. Thread the vetted
   addresses into the HTTP adapter and connect with a custom `lookup` (Node's `http.request`
   `lookup` option) that answers only with the vetted addresses. The guard already recorded them;
   this closes the gap between guard and request.
7. **S3 curation:** curate CodeGuard (CC BY 4.0 — check the licence terms before vendoring),
   the OpenSSF AI-instructions guide, and the OWASP Secure Coding with AI cheat sheet into
   `agent-rules/core/` with attribution files. This is the second deferral; do it.
8. **astoj comparison project:** the blueprint links `https://github.com/astoj/vibe-security`
   (MIT). It was skipped on the incorrect premise that no URL was given. Record and review it
   properly: what it covers, what SecHard covers that it does not, what it does that SecHard
   should adopt; write the comparison into the audit docs.
9. **Batch authorisation records:** `authorised_batch` in `01-owner-decisions.md` must reflect what
   was actually authorised and be kept current at every checkpoint (it is the audit trail of
   consent; a stale one is worse than none).

---

## 6. Appendix A corpus build — the **development** corpus (A-3; exercised by all of F2)

- Location: `tests/corpus/independent-nextjs/`. A builder composes the app at test time from
  per-file templates matching the brief's Appendix A exactly (33 security seeds, 30 quality seeds,
  the ✓/✘ table is the pre-F2 baseline, not the manifest).
- Every secret-shaped value is composed at runtime from fragments (the repository's existing
  gitleaks-avoidance technique) so gitleaks never flags SecHard itself.
- Two variants: no lockfile (hygiene seed + package.json-only rules) and with lockfile (advisory
  rules: lodash 4.17.15, axios 0.21.0, jsonwebtoken 8.5.1, next 14.0.0).
- The expected-findings manifest lists one entry per seed with its expected rule id, severity
  (post-F2), and the not-statically-checkable exceptions declared as such (e.g. missing auth
  check on a route).
- A test runs the real `hardening audit` on the built fixture and diffs result vs manifest →
  per-category recall **and** precision, printed. **A-3 caveat, stated wherever these numbers
  appear:** the implementer has read every seed, so this corpus measures development fit. It is
  the development-corpus number in the three-number checkpoint report (self-consistency /
  development / held-out accuracy); only the held-out number is accuracy, and only it may appear
  in the README.

## 7. Appendix B probes — permanent regression tests

Location: `tests/gate/probes.test.ts`, using `tests/helpers/fixtures.ts`
(`allPassing`/`allManual`, verified at lines 144/153). Each probe builds `planFor(stage)`, replaces
one result's findings, supplies manual evidence unless stated, and asserts the evaluator outcome:

| Probe | Setup | Expected after fixes | Guards |
| --- | --- | --- | --- |
| P1 | critical on AUTHZ-01; exception `scope: { rule_id }` only | blocked; `exception.invalid` | already passes — keep it so |
| P2c | high on AUTHZ-01; exception `scope: { finding_id }` only | blocked; `waiver.forbidden` | already passes — keep it so |
| P4 | high on CODE-01; valid exception (control, finding_id, environment) | `satisfied=true`, CODE-01 `waived` | already passes — keep it so |
| P5 | errored result on CODE-01 with a waived finding | not waived | already passes — keep it so |
| P6 | critical on CODE-01 with a valid exception | `waiver.forbidden` | already passes — keep it so |
| **P7a** | finding with `category: 'secret'`, severity **`unknown`**, on SEC-01, with a valid exception | **blocked; `waiver.forbidden`** | F-02 step 5 — the belt-and-braces ban holds on the exact hole the audit found (`unknown` secret + waiver) |
| **P7b** | gitleaks-origin finding with **no `category` field**, severity `unknown`, valid exception | **blocked; `waiver.forbidden`** | F-02 step 5 keyed on category **or** secret-scanner origin — proves a classifier regression cannot reopen the hole |
| P8 | high at release; exception with `self_review` omitted, approver == owner | `waiver.forbidden` | already passes — keep it so |
| **P10** | unknown-severity finding, `triage: 'accepted'`, no exception | **blocked** | F-17.4 |
| **B1** | medium on AUTHZ-01, no exception | **blocked** | F-17.5 |
| **M1** | every tool result `coverage: 'partial'`, `manualEvidence: []` | SEC-01, CI-01, GOV-01, WEB-01, AGT-01 **`unmet` with `manual.missing`** | F-03 |

Note on P7 (C-2): the split matters. P7a keeps testing the **`unknown` path** the audit actually
found — a post-classification `critical` variant would duplicate P6 and stop guarding the hole.
P7b guards the failure mode where the classifier regresses and stops setting `category`. Alongside
the probes, the classifier-totality test (F-02 step 6) asserts no secret finding ever leaves the
classifier `unknown` or uncategorized.

## 8. Checkpoint format (after each of F1, F2, F3)

1. **Commands actually run**, with outcomes, plus the CI run IDs watched to completion.
2. **Security-relevant behaviour changes for owner approval:** F-02 secret severities + waiver ban;
   F-03 the manual half of mixed controls (and each later reclassification); F-10 empty-catch
   recalibration; F-17 triage `accepted` and AUTHZ severity.
3. **Measured recall and precision — three numbers (A-3):** self-authored corpus
   (self-consistency), Appendix A (development), and the held-out corpus (accuracy), plus the
   external targets, per category, with the misses listed. The held-out corpus is supplied by the
   owner or independent auditor at each checkpoint — the implementer never authors it.
4. **Before and after `hardening audit` output** for Appendix A.
5. **Anything deferred, with the reason.** No deferral on an incorrect premise — check the
   blueprint and the plan first.

## 9. Owner decision register

| ID | Decision | Needed by | Recommendation |
| --- | --- | --- | --- |
| O-1 | F-02: are **high** secret findings also never-waivable? | Batch F1 | yes — a high secret is a credential someone must rotate; waiver is not rotation |
| O-2 | F-03: each automated-reclassification of a mixed method | Batches F2/F3, per case | reclassify only with complete tool coverage demonstrated on fixtures |
| O-3 | F-12: set recall/precision floors after first measured numbers | End of F2/F3 | floors on the held-out corpus only, never the self-authored or development one |
| O-4 | F-10: empty-catch severity recalibration | Batch F3 | as designed (low/medium/high ladder) |
| O-5 | F-16: adoption mechanism for private SecHard | Before F3's F-16 item | ask first; all five options in section 5, including "make it public" and "audit mode only" (C-3) |
| O-6 | F-17: `accepted` triage value | Batch F3 | **remove it entirely (A-4)** — acceptance goes through exceptions; false alarms go through `.hardening/triage.yaml` |
| O-7 | F-17: AUTHZ severity-bypass list scope | Batch F3 | AUTHZ-01/02/03 only, per the blueprint's wording |
| O-8 | F-10: approve exceptions for any own-code finding not fixed | Batch F3 | prefer fixing code; exceptions are per-finding, never rule narrowing |
| O-9 | ~~Supply `docs/audit/2026-10-10-follow-up-audit.md`~~ **Resolved 2026-10-11:** supplied by the owner and committed unchanged (SHA-256 recorded at checkpoint) | — | — |
| O-10 | F-03 stage behaviour of manual companions (A-5): how strict? | Batch F1, before F-03 lands | release blocking; PR "awaiting review" — not satisfied, not blocking unless the profile says so; audit mode a grouped checklist |
| O-11 | F-07/Knip: disable config-loading plugins, or require isolation (A-1) | Batch F2 | disable by default; isolation-only full mode later |
| O-12 | Who supplies the held-out corpus each checkpoint (A-3) | Batch F2 onward | the owner or an independent auditor — **never the implementer** |

## 10. After F1–F3

Continue with the 2026-10-08 plan's **Batch X** remainder (F-06 above starts X1: splinter, live
anon probe, more stacks, runtime AI profile), then **Batch D** — adoption and maintenance, the
update procedure, and the owner **re-approving every control against the final review sheet**. The
F-03 manual companions add evidence obligations that D's re-approval sheet must include; D's
schedule should account for reviewing manual evidence for the 24 mixed-only controls, at the
strictness the owner chose in O-10.
