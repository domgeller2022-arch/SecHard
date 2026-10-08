# Remediation plan — gap analysis (2026-10-08)

Review of `2026-10-08-remediation-plan.md` against `2026-10-08-external-audit.md`, the build pack
(`00`–`03`), the two owner-supplied reviews, `docs/implementation-progress.md`, and the code as it
stands at `331078e`. Finding IDs refer to the audit.

Everything the remediation plan covers is not repeated here. This document records only what it
**missed**, and what neither the audit nor the plan noticed. Items are split into:

- **A. Audit findings with no remediation task** — the plan's batch table claims them, but no task
  implements them.
- **B. Open findings the audit listed as "already recorded" that no batch owns.**
- **C. Defects found in the code that neither document names.**
- **D. Requirements gaps** — plan/blueprint/review requirements that the batch design does not
  satisfy or does not address.
- **E. Process and traceability.**

Priority markers: **[blocking]** = must be fixed in Batch R; **[before W/A/Q]**; **[before D]**.

---

## A. Audit findings with no remediation task

### A1. M5 — the example workspace drags heavy dependencies into consumer CI **[blocking]**
The audit: "`examples/*` is a workspace member, so installing SecHard in a consumer's trusted CI job
also installs Next.js, Playwright, and the 64 MB Supabase CLI." The batch table lists M5 under
Batch R, but no R task mentions it. R2.3 ("each CI job provisions exactly what its suite needs")
touches the symptom for this repository's own CI; the consumer workflows (`hardening-pr.yaml`,
`hardening-release.yaml`) still run a bare `pnpm install --frozen-lockfile`, which installs every
workspace member.

**Action (implemented in R2):** filtered installs (`pnpm install --frozen-lockfile --filter sechard`)
in consumer workflows and in CI jobs that do not exercise the example, plus a trust test asserting
no consumer workflow runs an unfiltered install.

### A2. Reference-app defects (M8) have no explicit fix task
The batch table assigns M8 to Q, but Q's tasks only build quality controls and the checkpoint says
"SecHard passes its own quality audit". Nothing says the reference app's own defects get fixed:
`updateNote` drops the body field, every insert/update/delete error is discarded, `X-Powered-By` and
the missing CSP remain. Since SecHard "audits, never fixes", the example is the one place where
fixing is legitimate (it is this project's own artefact). **Action:** add an explicit Q task "apply
QUAL-07/QUAL-13 findings to the reference app, or record each as an accepted, visible gap", and keep
the ZAP warnings (status-report finding 2) attached to it.

---

## B. Open findings no batch owns

### B1. LAN binding of the local development stack (status-report finding 1) **[before D]**
The audit lists "Development services reachable beyond loopback" as still open. The remediation plan
never mentions it. The firewall proves ad-hoc-signed `limactl` traffic is not filtered over the VM
network. Options remain: an explicit firewall add/block plus a `pf` rule, colima config with a
loopback-only forwarder, or a written accepted-risk record tied to the machine's network. A
remediation batch must own the closure or the acceptance; otherwise the release report will carry an
unowned medium.

### B2. AUTH-02 recovery isolation and genuine session expiry **[before D]**
Status-report finding 4, also listed by the audit as untested. No batch covers it (X1 covers
Supabase statics and the anon probe, not the recovery flow). Step 08's acceptance says "recovery
isolation" needs the email flow. Add to Batch X or W: a local mail-capture test proving a recovery
link for user B cannot complete user A's flow, and a short-lived-token expiry test.

### B3. TLS remains manual while a production release blocks on it **[already in X3]**
Covered by X3 (`testssl.sh` pinned), but note the current integration assertion deliberately requires
the release plan's TLS check to be `unsupported` so release blocks. When X3 lands, that assertion
must be **replaced**, not deleted — flipping it to require a real TLS result only when an HTTPS
target exists. Add a task note in X3; otherwise the test will be "fixed" by deletion, which is the
failure mode the pack forbids.

---

## C. Code defects neither document names

### C1. `policy/gate-policy.yaml` `control_categories` is dead data **[blocking]**
`never_exceptable` and `error_not_exceptable` are parsed into the `GatePolicy` type but read by no
code; the evaluator hardcodes `BLOCKING_SEVERITIES` and takes `never` only from profiles. The
gate-policy list (CI-03, REL-01, EXC-01, GOV-02, AUTHZ-01/02/03, AGT-03) and the profile lists
happen to agree today, so the defect is masked. R4 must enforce the union of both sources so the
policy file cannot silently stop applying.

### C2. `ControlEvaluation.required_checks` is always `[]`
`build()` in `evaluator.ts` sets `required_checks: []` unconditionally, while the type, blueprint and
report schema all expect the checks a control depends on. R5.2 (count controls, not checks) requires
per-control aggregation; the fix must populate `required_checks`/`satisfied_checks` correctly, not
just change the summary line.

### C3. `blocking_severities` in policy is dead; `BLOCKING_SEVERITIES` hardcoded
`risk.blocking_severities: [critical, high]` is ignored. R4's new "critical findings are never
waivable" rule makes this worse if it leaves a second hardcoded list in the evaluator. Read the
policy list.

### C4. `check` identity and manifest checks are skipped for manual-only expected checks
Not a defect today (manual checks produce no result), but when `check` starts exiting non-zero on
required unsupported work (R3.1), the set of "required" checks must exclude `mode: manual`
requirements. A required manual check has no result by design and must not make `check` exit 1.
State this in the implementation and test it.

### C5. Console output can carry finding titles unredacted
R5.1 names "Markdown, HTML, or console writer". The console path is `gateCommand`'s stdout lines and
`reportCommand`'s summary; both print `Reason.message`, and `finding.blocking` embeds
`finding.title`. The fix must cover stdout, not only `renderMarkdown`.

### C6. `hardening check` prints unsupported per result but exits 0 — the C2 root cause
R3.1 fixes the exit code. Note the second half: `check` must still write every result it did produce
and exit 1 *after* the report artefact is complete, or the consumer workflow loses the report when
work is unsupported. The plan does not state that ordering.

---

## D. Requirements gaps in the batch design

### D1. Audit mode runs untrusted application code with no isolation model **[before A]**
QUAL-01's method is "App's own scripts, detected" — `npm test`, lint, build. In `hardening audit
PATH`, that executes arbitrary code from the audited repository on the operator's machine. The
blueprint's CI-01/trust model requires untrusted code to be isolated from credentials and privileged
contexts, and `policy/dependency-policy.yaml` already has an `application_execution` operator-
isolation requirement that nothing consumes. A1–A4 never say how audit mode satisfies it. **Fix
before A ships:** define it (container/VM execution for `standard`/`deep`; `quick` never executes
app code), make it an operator requirement, and refuse execution when isolation is unavailable
rather than silently running it.

### D2. `hardening audit` accepts a Git URL in the goal but not in the command
Batch A's goal says "point it at a folder, a Git URL, or a deployed URL", but the A1 signature is
`hardening audit PATH [--url ...]`. Cloning an untrusted repository is a distinct operation with its
own trust rules (shallow clone, no submodule init, no hooks, no LFS smudge). Either add it as an
explicit flag with those rules or drop the claim. Also undefined: how `--policy` is resolved for
someone who has not cloned SecHard.

### D3. New control IDs vs "preserve the 35 controls" **[before Q/S]**
Q adds QUAL-02…QUAL-13 and X adds AI-01…AI-06 without any catalogue-versioning story. The catalogue
test hardcodes 35 IDs; profiles and the consumer template validate IDs against a pattern that
already admits `QUAL-` but not `AI-`. Define how new control IDs enter the catalogue (definition
version, migration note, per-release deltas), or D2/Step 16 will produce a release whose catalogue
number silently changed.

### D4. The remediation plan's own artefacts are not in the repository
The audit says the remediation plan lives at `docs/audit/2026-10-08-remediation-plan.md`; the files
are at the pack root outside the repo. A reader of the published repository cannot find the audit
that drove the work. Move (or copy) the audit, this gap analysis, and the remediation plan under
`docs/audit/`, and reference them from the changelog.

### D5. `report.sarif` has no escaping/validation requirement **[before A3]**
A3 adds `report.sarif` for GitHub code scanning. SARIF is machine-read and surfaced in review UIs;
finding titles/paths come from untrusted scanners and repositories. The plan says nothing about
schema-valid SARIF, snippet redaction, or URI sanitisation. Add it: validate the SARIF document
against the SARIF 2.1 schema, redact before emission, and never include raw snippets of secret
findings.

### D6. `--url` live checks need an SSRF statement
A1 generates the approved-target inventory from `--url`. Nothing prevents `--url
http://169.254.169.254/` or an internal hostname. The approved-target model exists precisely for
this; audit mode must refuse private/loopback/link-local targets (except explicitly flagged local
development) and resolve-and-pin the host, and the report must say what was contacted and why.

### D7. Review findings from the two pack reviews that the audit did not re-flag and R–Q do not
place
- Step 13.7's full text (base-policy evaluation, conservative treatment of newly enabled candidate
  features, bootstrap path, post-merge transition) is only partly addressed by W3.1–W3.4: the
  **"newly enabled candidate features are evaluated conservatively / an unreviewed declaration
  cannot remove a baseline obligation"** clause has no task. Add to W3.
- Step 13.6 (`record PR head and tested merge SHA when different; test merge queue if enabled`) is
  not addressed. Add to R3/W3, or record it explicitly as an unsupported claim with the reason.
- Step 13.9 (path filtering, cancelled jobs, forks without secrets, malicious artifact content,
  unsupported inputs) — only "missing artifact" is mentioned in R3.3. Add the other cases to R3's
  trust tests.
- Step 12 packaging remains fine as-is; no action needed.
- OSPS S2 says "check it in CI with OpenSSF Scorecard". Scorecard is an external GitHub Action; the
  audit's own warning about compromised actions (Trivy/KICS) and CI-02 mean the Scorecard action
  must be SHA-pinned like every other. State it in S2.

### D8. `--depth quick|standard|deep` semantics undefined
A1 invents the flag; nothing defines what changes. Define it (which checks run, whether app code is
executed, whether live checks run) and test each level's report/exit behaviour.

### D9. "SecHard never writes to the audited project" test needs a definition of "write"
Rule 6 says a test enforces it. Define what counts (no file creation/modification/deletion inside
the target tree, including caches; outputs to `--out` only; scanners run with cwd/tmp outside the
target), then implement the tree-digest test A1 acceptance already promises.

### D10. Unaddressed review verification cases
The vibe-security integration review lists nine prioritized verification cases. Most already exist
as fixtures, but two are not covered anywhere in R–D:
- **"A public health route or intentionally public dataset is not incorrectly classified as an auth
  bypass"** — a positive-case guard that no authorization check may flag an intentionally public
  resource. Add to the AUTHZ fixtures (W3/A2).
- **"Applicable limiter tests cannot obtain a new budget merely by spoofing a forwarding header"**
  — ABUSE-01's recipe correction; belongs with W4/X3 live checks.

### D11. Naming collision and record hygiene
The remediation plan reuses "Batch A" for audit mode while the pack uses A for Steps 00–05, and R,
W, Q, S, X, D have no mapping in `01-owner-decisions.md`'s decision-to-step table. Rename audit mode
(e.g. Batch U) or record a mapping table before work starts; otherwise `authorised_batch` becomes
ambiguous and resumption ("Resume") cannot tell which A is meant. **Fixed for R here:** owner sheet
records the goal list and batch map.

### D12. No plan for `documents that contradict each other` beyond status
R6.2 generates status from the progress record, but the progress record itself contains claims the
audit called misleading (Step 09 marked `verified` while nothing was wired; "465 tests" when a clean
checkout ran 446/450). R6 must reconcile the historical step states (a correction note per affected
step), not only generate a new summary from them.

---

## E. Process and traceability

### E1. The plan's R3.3 needs artefacts that do not exist yet
"Downloads the report artifact and re-runs `hardening gate` against the recomputed plan" requires the
plan and results in the artifact; today only `report.json` is uploaded. Implemented in R3 by
uploading `plan.json`, `results.json`, and the raw reports alongside `report.json`, and by making a
missing artifact a failure.

### E2. R1 cannot observe non-native platform versions locally
The plan requires per-platform entries with "expected version" for linux and macOS on x64/arm64.
Only the current platform's binary can be run to observe its version. Record the provenance
explicitly: native-platform versions observed by execution; other platforms carry the release tag's
declared version and are confirmed by `runTool`'s version check on the first CI run. Without that
distinction the record claims observations that did not happen.

### E3. Owner exposure while remediation runs
The repository is **public**, has no `LICENSE`, and no security contact (status-report findings 5 and
7). R7 marks these owner-blocked and defers. That is correct as a build decision, but it leaves an
active exposure during the whole remediation. Recommendation: either move the repository private
until R+W are merged, or add the security contact now. This is an owner action, flagged here so it
is not discovered at Batch D.

---

## Summary — what to add

| # | Item | Where |
| --- | --- | --- |
| A1 | M5 filtered installs (consumer workflows + CI) | R2 |
| A2 | Reference-app M8 fix or explicit accepted gaps | Q |
| B1 | LAN binding closure or accepted-risk record | new R8 or D1 |
| B2 | AUTH-02 recovery isolation + session expiry | W/X |
| C1 | Enforce policy `never_exceptable` union | R4 |
| C2 | Populate `required_checks` (per-control aggregation) | R5 |
| C3 | Read `risk.blocking_severities` from policy | R4 |
| C5 | Console redaction/escaping | R5 |
| C6 | `check` writes its report before non-zero exit | R3 |
| D1 | Untrusted-app execution isolation in audit mode | A1 |
| D2 | Git URL mode or drop the claim; policy resolution | A1 |
| D3 | Control-catalogue versioning for new IDs | Q/S |
| D4 | Audit/plan/gap docs inside `docs/audit/` | R6 |
| D5 | SARIF validation and redaction | A3 |
| D6 | `--url` SSRF/private-target refusal | A1 |
| D7 | Step 13.6/13.7/13.9 residual clauses; Scorecard pinned | R3/W3/S2 |
| D8 | `--depth` semantics | A1 |
| D9 | "Never writes" definition + tree-digest test | A1 |
| D10 | Public-resource and header-spoof verification cases | W3/X3 |
| D11 | Rename audit-mode batch; record batch map | owner sheet |
| D12 | Reconcile historic step states | R6 |
| E1 | Plan/results in gate artefacts | R3 |
| E2 | Platform version provenance honesty | R1 |
| E3 | Owner: repository exposure during remediation | owner action |

Items marked **[blocking]** (A1, C1–C3, C5, C6) are implemented in Batch R in this session, together
with the rest of R1–R7. The remainder are recorded for W, A, Q, S, X and D as their batches open.

---

## Post-R status (2026-10-08)

Batch R implemented and verified locally (`docs/checkpoints/batch-r.md`):

- **A1, C1–C3, C5, C6, E1, E2 — implemented in R.** M5 filtered installs; the gate-policy
  `never_exceptable`/`blocking_severities` now enforced; per-control aggregation with
  `required_checks` populated; console redaction; `check` writes its results before exiting nonzero;
  the final gate job receives `plan.json` + `results.json`; non-native platform versions carry
  `versionProvenance` honestly.
- **D4, D11, D12 — implemented in R.** Audit documents in `docs/audit/`; audit-mode batch renamed U
  and the batch map recorded in the owner sheet; the status document is generated from the progress
  record.
- **A2 (M8), D1–D3, D5–D10 — deferred to their batches as recorded above.**
- **B1 (LAN binding), B2 (AUTH-02 recovery/session), E3 (repository exposure) — still unowned by any
  batch and still open.** B3's warning stands: when X3 pins `testssl.sh`, replace the integration
  assertion that a release plan must carry an `unsupported` TLS check; do not delete it.

---

## Post-W status (2026-10-09)

- **C1 (no scanner wired) — fixed.** Seven recipes produce real results through the CLI; the
  audit's acceptance is a test that runs the compiled CLI against a vulnerable scratch app.
- **H5 — fixed.** Extended markers and JWT role decoding; the audit's probe values are detected.
- **H4 — fixed locally.** The PR workflow evaluates the base branch's records and fails
  review-required when the PR changes them; a real PR is still needed for platform verification.
- **W4 — done for the recipe;** the X3 exposure probes remain deferred as the plan allows.
- **Newly surfaced and fixed in W:** the evaluator required complete coverage for every pass, which
  made any `mixed` method impossible to satisfy; a pass is now judged against the check's own
  `required_coverage`. SEC-01's gitleaks recipes are reclassified `mixed` (definition v2), which
  deliberately invalidates its prior approval; Batch D re-approves.
- **Still open:** LAN binding, AUTH-02 recovery/session, audit-mode isolation and `--url` SSRF
  (Batch U), control-catalogue versioning for new QUAL/AI IDs, SARIF, step-13 residual clauses.
