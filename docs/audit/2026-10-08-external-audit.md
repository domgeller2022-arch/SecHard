# External audit — 2026-10-08 (revision 2)

Audited commit: `88df318` (`main`). Revision 2 adds the owner's clarified goals, a requirement-level
check of every standard listed in the blueprint, a review of the comparison projects, and external
research. The implementation plan that remediates everything here is in
`docs/audit/2026-10-08-remediation-plan.md`.

Every finding marked **Reproduced** was confirmed by running the code on a clean Linux machine
(Node 24.21.0, checksum-verified; pnpm 12.9.1), not by reading the progress record. Standards were
checked against their official machine-readable sources where the network allowed (ASVS CSV, OWASP
Top 10 repository, OSPS Baseline repository). Where it did not, this report says so.

---

## 0. The owner's goals, as clarified on 2026-10-08

These take precedence over the blueprint wherever they differ, under the pack's own precedence rule
(owner decisions first). They should be recorded in `01-owner-decisions.md`.

1. **SecHard audits; it does not fix.** Running an application, codebase, website, or service
   through it must produce a thorough report of what is wrong and what needs fixing. Suggestions
   (including example fixes and ready-to-use prompts for an AI assistant) are welcome. Changing the
   audited code is not SecHard's job.
2. **Quality is a first-class goal, equal to security.** The report must surface everything that
   makes a codebase look vibe-coded rather than engineered by a skilled team. The blueprint moved
   quality out of scope ("keep quality results separate … optional profile"). That is now overridden:
   quality stays a separate *section* of the report, but it is a required capability.
3. **Security coverage as deep as practical.** Anything SecHard cannot check must appear in the
   report as an explicit warning, never as silence.
4. **The standards listed in the blueprint must actually be incorporated**, not just linked.
5. **Steps 09–16 must be completed**, including the parts built but never connected.
6. **SecHard must be updatable** as standards, tools, and rules change.

---

## 1. Bottom line

The core is careful work. Input loading, the process runner, the evidence and freshness rules, the
reference application's database security, and the generated agent rules are all good.

**But as delivered, SecHard cannot audit anyone's application.**

- `hardening check` runs no scanners; 32 of 33 checks come back "not implemented in this build".
- The scanners are pinned to macOS binaries at a path on the original build machine.
- The repository's own CI has never passed.
- The PR workflow a consumer would use reports green when the gate says blocked.
- It requires a hand-written manifest and policy lock before it will look at an app, so you cannot
  simply point it at a folder.
- It has no code-quality analysis beyond running an app's own tests, lint, and type checks.
- The standards are cited by name only. No control maps to a single numbered requirement, and
  several cited names do not exist in the pinned editions.

---

## 2. Compared with what the owner asked for

| Goal | State | Evidence |
| --- | --- | --- |
| Point it at any app and get a thorough audit | **Not met** | C1 (no scanners run), C3 (Mac-only), D1 (manifest required), Step 15 not started |
| Find quality issues: "looks engineered, not vibe-coded" | **Not met** | Q1: no duplication, complexity, dead-code, architecture, error-handling, test-quality, or AI-tell analysis |
| Find security issues as deeply as possible | **Rules strong, execution missing** | 35 controls; C1, C2, H5, L1 |
| Warn about what it cannot check | **Met by design** | Unsupported, pending, unknown, and stale are always reported |
| Audit and suggest, never fix | **Met** | It never modifies an app. Suggestions are minimal: findings have no "how to fix" text |
| Incorporate the blueprint's standards | **Not met** | S1–S8 |
| Easy to keep up to date | **Not started** | Step 16 not started; no update procedure for standards or rules |

---

## 3. Conformance to the implementation plan

| Step | Plan says | Actual |
| --- | --- | --- |
| 00–02 | Decisions, repository, schemas, safe loading | Conforms. The loader is strong. |
| 03 | 35 draft controls with exact standards IDs reviewed, or visibly unverified | 35 controls exist. Mappings are honestly labelled `related_risk`, but are chapter-level prose, partly wrong (S1–S3). Approvals: see H6. |
| 04 | Pure decision engine | Mostly conforms. Three exception defects (H1–H3). |
| 05 | CLI; escaped and redacted reports | CLI and exit codes work. Report Markdown is not escaped or redacted (M1). |
| 06 | Pinned, verified tool execution | Process runner excellent. Pins are macOS-only and machine-specific (C3). |
| 07–08 | Reference app; authorization tests | Strong. |
| 09 | Scanner adapters; "the master and example receive real scans" | Adapters built and tested but **not wired into `check`** (C1). |
| 10 | Build and client-secret checks | Built, not wired; misses common keys (H5). |
| 11 | Live HTTP, ZAP, and TLS recipes | Built as a separate script, not wired; no exposure probing (L1). |
| 12 | Agent rules, curated from CodeGuard, OpenSSF, and OWASP | Generated and sensible. The named sources were **not curated in**; they are recorded as `planned` (S7). |
| 13 | Workflows; final job recomputes the plan; PRs cannot weaken their own checks | **Fails open** (C2). No plan recompute (M2). PR self-weakening not handled (H4). CI never passed (C4). |
| 14 | Manual evidence and runbooks | Conforms for local scope. |
| 15–16 | Independent adoption; maintenance and release | Not started (expected under batch C). |

Process rules (batches, checkpoints, progress record) were followed, and the detailed progress
record is candid. The headline documents (`README.md`, `docs/status-report.md`) disagree with each
other and overstate integration (M3).

---

## 4. Findings

### Critical

**C1. `hardening check` runs no scanners. Reproduced.**
`src/commands/run.ts` `checkCommand` runs only `policy/record-consistency`. Every other recipe is
recorded as `unsupported`, "not implemented in this build". `src/adapters/*` and
`src/build/client-assets.ts` are imported only by tests. Running the CLI on
`examples/nextjs-supabase` planned 33 checks: 1 pass, 32 unsupported, gate exit 1. No application
can pass, and none receives any analysis of its code. The progress record discloses this only in a
Step 09 limitation line, while marking Step 09 `verified`.

**C2. The consumer PR workflow fails open. Reproduced.**
`.github/workflows/hardening-pr.yaml` runs `hardening gate … || echo "gate blocked"`, which always
exits 0. `hardening check` exits 0 even when required checks are `unsupported`. `hardening-gate`
only checks `needs.hardening-pr.result == success`. Simulating the exact step script: CLI
**blocked**, required check **green**. `tests/workflows/trust.test.ts` checks the workflow's shape
only, so it cannot catch this.

**C3. Scanners only work on the original build Mac. Confirmed by reading; download blocked here by the network proxy.**
`tools/fetch-tools.mjs` downloads macOS assets only (`gitleaks_…_darwin_x64`,
`osv-scanner_darwin_amd64`, `opengrep_osx_x86`, `zizmor-x86_64-apple-darwin`).
`policy/toolchain.yaml` records each executable at `/Users/dd/Desktop/Security Hardening/...` with
Mac-binary digests. The registry correctly refuses missing or mismatched binaries, so everywhere
else every scanner is unavailable. The plan names Linux CI as the supported environment.

**C4. The repository's own CI has never passed. Confirmed on GitHub (run 37791502471: every job failed) and reproduced locally.**
- `typecheck` fails without `dist/` (`tools/generate-*.ts` import `../dist/...`), and CI runs it
  before `build`.
- `fetch:tools` also imports `../dist/...` and runs before `build`, then hits C3.
- `pnpm test` needs a built example app and fetched scanners, which the CI job does not provide.
- Clean checkout result: 446 pass, 4 fail, 450 total. The status report claims 465 passing.

**D1. It cannot be pointed at an arbitrary codebase.**
Every command needs a hand-written `.hardening/app.yaml` whose `policy_lock.commit` equals the
policy checkout's exact commit, plus selected profiles. There is no stack detection, no zero-config
mode, and no adoption guide (the README says "Not available yet"). For the owner's use case,
"run my vibe-coded app through it", this is the first wall a user hits.

**Q1. No code-quality analysis exists.**
QUAL-01 runs an application's own tests, lint, and type checks, and its thresholds are unconfigured.
Nothing measures:
- duplication;
- complexity or function and file size;
- dead code or unused dependencies;
- import cycles and layering;
- swallowed errors and debug leftovers;
- placeholder or stub code;
- test quality: skipped tests, assertion-free tests, mutation score;
- strict-mode adoption;
- formatting consistency;
- comment noise and other AI-authorship tells;
- README accuracy;
- accessibility and performance.

The owner's highest-priority goal therefore has no implementation. The reference app itself shows
why it matters: `updateNote` silently drops the body field and every database error is discarded.
That is exactly the kind of defect a quality audit should catch.

### High

**H1. A "never waivable" control can be waived. Reproduced.**
`exceptionBlockedBy` applies the profile's `never` rule only when the exception names
`scope.control`. An exception scoped by `rule_id` or `finding_id` alone turned a **critical**
AUTHZ-01 cross-user finding into `waived`. A `rule_id`-only scope also waives that rule across every
check, which is close to the blanket waiver the plan forbids. Today this is masked only by H2.

**H2. A valid exception can never let a gate pass. Reproduced.**
`waiver.applied` is added to `reasons`, and `satisfied` requires zero reasons. The test for valid
exceptions never asserts the decision.

**H3. A waiver is applied over a check that errored. Reproduced.**
A result with outcome `error` plus a waived finding becomes `waived`. Plan Step 04.4 forbids
exceptions over execution errors.

**H4. A pull request can weaken its own assessment.**
The PR head supplies `.hardening/app.yaml` (feature flags), `exceptions.yaml`, and
`manual-evidence.yaml`. A PR can switch a feature off, add a `pass` attestation, or add an
exception, and is then judged by those records. Plan Step 13.7 requires the base branch's records
for the decision. `docs/ci-trust.md` does not mention this gap.

**H5. The client-bundle secret check misses the commonest real leaks. Reproduced.**
A synthetic bundle containing values shaped like the following produced **0 findings with
`coverage: complete`**:
- a legacy Supabase `service_role` JWT;
- an OpenAI `sk-proj-` key;
- a Stripe `sk_live_` key;
- an Anthropic `sk-ant-` key.

Catching the legacy JWT requires decoding the token's `role` claim.

**H6. Control approvals must be redone.**
The owner says they approved the controls but may remember more than was recorded.
`controls/approvals.yaml` holds 35 identical-timestamp approvals written by the build agent, in the
same commit that changed 140 lines of the definitions. Regardless of what happened, the remediation
plan changes most definitions: new standards mappings, new quality controls, and corrected
acceptance criteria. Every approval will therefore be invalidated by digest anyway. Re-approve once,
against the remediated review sheet, using the explicit owner procedure already in
`01-owner-decisions.md`.

### Standards incorporation (owner request)

Method: compared `controls/mappings/standards.yaml` (42 references, all `related_risk`, all prose,
**no requirement IDs**) with each standard's official content.

| Standard (blueprint section 3) | Size of the standard | What the repository has | Verdict |
| --- | --- | --- | --- |
| **OWASP ASVS 5.0.0** | 345 requirements in 17 chapters (L1 70, L2 +183, L3 +92), from the official CSV at tag `v5.0.0` | 9 chapter-level phrases, 0 requirement IDs. At least 5 use ASVS 4.0-era or nonexistent names: "architecture and design", "static analysis verification chapter", "communication and cryptography", "injection and input validation", "data access control". No reference at all to V3 Web Frontend, V4 API, V5 File Handling, **V7 Session Management**, V9 Self-contained Tokens, V10 OAuth/OIDC (36 requirements), V11 Cryptography, V14 Data Protection, V15 Secure Coding and Architecture, or V17 WebRTC | **S1. Not incorporated** |
| **OWASP Top 10 2025** | A01–A10 (verified in the OWASP/Top10 repository) | 7 references. Only 2 valid categories (A01 Broken Access Control, A03 Software Supply Chain Failures). "Vulnerable and outdated components" is the 2021 name. "Secrets management" is not a category. A02, A04–A10 are absent, including **A10 Mishandling of Exceptional Conditions**, which is exactly the swallowed-error defect in the reference app | **S2. Mostly not incorporated; names wrong** |
| **OWASP API Security Top 10 2023** | API1–API10 | 6 prose references covering API1, API3, API4, API5, API6. "Injection" is not a 2023 category. Absent: API2 Broken Authentication, **API7 SSRF**, API8 Misconfiguration, API9 Inventory, API10 Unsafe Consumption of APIs | **S3. Half covered; one invalid name** |
| **OWASP Cheat Sheets and WSTG 4.2** | Per-page recipes; WSTG test IDs (for example `WSTG-ATHZ-02`) | Editions declared; **0 control mappings**; no recipe cites a WSTG test ID | **S4. Linked only** |
| **NIST SSDF 1.1** | 4 groups (PO, PS, PW, RV), 42 tasks | 1 generic reference ("secure software development practices") | **S5. Linked only** |
| **OpenSSF OSPS Baseline v2026.08.28** | 67 requirement IDs in 8 families (AC, BR, DO, GV, LE, QA, SA, VM), verified in the ossf/security-baseline repository | 12 prose references, 0 IDs. The blueprint says to apply OSPS **to SecHard itself**. That was not done: SecHard has no licence and no vulnerability-reporting contact, both basic Baseline expectations, and it is public | **S6. Not incorporated; not applied to itself** |
| **MVSP** | 25 controls in 4 areas | 7 prose references | Partial |
| **RFC 9700 (OAuth security BCP)** | PKCE, exact redirect matching, no implicit grant, and more; operationalised by ASVS V10 | Edition declared; **0 control mappings**; no OAuth test recipe | **Not incorporated** |
| **ASD Secure by Design** | Foundations | Edition declared; **0 mappings** | **Not incorporated** |
| **SLSA 1.2** | Build track levels | Recorded as roadmap | Acceptable per blueprint; recommend SLSA Build L2 for SecHard's own releases |
| **AISVS 1.0, LLM Top 10, Agentic Top 10, MCP Top 10** | Runtime-AI requirements and taxonomies | Recorded as out of scope | **Recommend reversing.** Vibe-coded apps very often call LLM APIs. At minimum, detect it, run the AI-specific checks (key exposure, spend limits, prompt-injection surfaces, output handling), and report the rest as gaps. MCP Top 10 stays link-only because of its non-commercial licence |
| **MASVS, Electron guidance** | Mobile and desktop | Recorded as out of scope | Acceptable for v1, but SecHard must **detect** mobile and desktop projects and print a loud coverage gap rather than auditing them as web apps |

**S7. Agent-guidance sources not curated.**
The blueprint says to curate CodeGuard (CC BY 4.0), the OpenSSF AI-instructions guide, and the
OWASP Secure Coding with AI cheat sheet into the rules. All three are recorded as `planned` and
`linking`. The generated rules are original text.

**S8. Comparison projects mostly unused.**
Only `raroque/vibe-security-skill` was adapted (12 patterns, each with `implemented: false`). The
other four were lumped into one entry with one licence checked. Ideas they contain that SecHard
lacks:
- a read-only live exposure probe for `.env`, `.git`, source maps, debug endpoints, CORS, and
  cookie flags (benavlabs/vibe-check, MIT);
- quality, accessibility, performance, SEO, compliance, and open-source-readiness audits, plus a
  go/no-go checklist (penguinboi/preflight-checks, MIT);
- error and uptime monitoring, cron single-source, and stack traces in client errors
  (gorrion-io production-readiness-checklist);
- infrastructure-as-code and RBAC areas (astoj/vibe-security, MIT).

### Medium

- **M1.** Report Markdown uses a local `escape()` covering only `|` and newlines. The existing
  `escapeMarkdown()` is never called in production code. Finding titles reach `report.md` unredacted.
- **M2.** Final gate jobs only read upstream job status. They do not recompute the plan or inspect
  reports (Step 13.5).
- **M3.** Documents disagree. The README says "No scanner is integrated. No reference application
  exists"; the status report says scanners are finished. `docs/ci-trust.md` says to install
  `CODEOWNERS.template` once `github_codeowners` is filled, but it is filled and installed.
- **M4.** `pnpm test` rewrites the tracked `examples/nextjs-supabase/.hardening/app.yaml`.
- **M5.** `examples/*` is a workspace member, so installing SecHard in a consumer's trusted CI job
  also installs Next.js, Playwright, and the 64 MB Supabase CLI.
- **M6.** `fetch-tools.mjs` uses the unauthenticated GitHub API (60 requests/hour, shared by CI
  runners).
- **M7.** "controls satisfied: 1/33" counts checks, not controls. Each outcome uses only
  `control_ids[0]`.
- **M8.** Reference app issues:
  - `updateNote` ignores the body field.
  - Every insert, update, and delete error is discarded.
  - `X-Powered-By` is still sent.
  - There is no CSP.
- **L1.** The live HTTP check only asserts headers, cache behaviour, and forbidden strings on
  pre-listed routes. It does not probe for exposed `.env`, `.git`, source maps, or debug endpoints,
  and it does not test cookie flags, CORS, or verbose errors. These are the most common
  live-deployment leaks in vibe-coded apps.

### Already recorded by the build (still open)

- No `LICENSE`, and no security contact on a **public** repository.
- Development services reachable beyond loopback.
- Recovery and real session expiry are untested.
- TLS assessment is manual (testssl.sh unpinned).
- A history-rewrite backup is still on the build machine.

---

## 5. What is genuinely good, and should be kept

- **Input loader** (`src/validation/loader.ts`): duplicate keys, tags, aliases, unsafe numbers,
  lone surrogates, and size and depth limits.
- **Process runner** (`src/execution/process.ts`): no shell, absolute paths, env allowlist, output
  caps, process-group kill.
- **Evaluator identity and freshness**: wrong commit, wrong run, stale advisory data, fixture
  evidence, empty scope, and future timestamps all block correctly.
- **Reference app database**: forced RLS, owner from `auth.uid()`, `WITH CHECK`, explicit grants,
  `getUser()`, configured redirect origin.
- **Authorization tests** that prove detection on a deliberately weakened policy.
- **Workflow hygiene**: SHA pins, no write permissions, no `pull_request_target`, no shell
  interpolation.
- **The honesty model**: unsupported, unknown, and stale are never silently passed. This is the
  right foundation for "warn me about what you could not check".

## 6. Does SecHard's own code read as engineered by a skilled team?

Mostly yes: the structure, strict typing, and module boundaries are professional. The vibe-coded
tells are in the prose:
- comments that argue for themselves ("deliberately" 32 times, "honest" 23 times);
- about 30,000 words of process documentation, including a 1,359-line progress log;
- documents that contradict each other.

SecHard should pass its own quality audit (plan Batch Q exit criterion): trim comments to the
non-obvious *why*, collapse process logs into a concise changelog and architecture document, and
keep one accurate README.

## 7. Research: what else would benefit SecHard

Licences were checked from each project's repository on 2026-10-08 and must be re-verified at
adoption. "Idea source" means read for ideas only: unvetted, never installed or copied.

**Code quality: the "engineered, not vibe-coded" goal**

| Need | Recommended | Licence | Note |
| --- | --- | --- | --- |
| Duplication, 150+ languages | jscpd | MIT | JSON output, CI exit codes |
| Dead code and unused dependencies (JS/TS) | Knip | ISC | Project-level, unlike ESLint |
| Dead code (Python) | Vulture | MIT | |
| Import cycles, layering rules | dependency-cruiser | MIT | |
| Complexity, function size, multi-language | Lizard | MIT | Cyclomatic complexity, length, parameter count |
| Strict linting | typescript-eslint `strict-type-checked`, Ruff | MIT | Run with SecHard's own pinned config, not the app's |
| Cognitive complexity rules | eslint-plugin-sonarjs | **SonarSource's repository is now under a source-available licence** | Verify the npm package licence before use; Lizard plus custom rules is the safe default |
| Mutation testing (test quality) | StrykerJS | Apache-2.0 | Expensive; run on security-critical modules |
| Accessibility | axe-core via Playwright | MPL-2.0 | |
| Performance | Lighthouse CI | Apache-2.0 | |
| All-in-one aggregators | MegaLinter (**AGPL-3.0**), Qlty CLI (**Fair Source**, not OSI) | | Do not bundle. Optional external runners at most |
| AI-authorship tells | **No mature open-source tool exists** (searched) | | Build as SecHard-owned Opengrep rules plus a small analyser (plan Q4) |

**Security**

| Need | Recommended | Licence | Note |
| --- | --- | --- | --- |
| Supabase database lints (RLS, `SECURITY DEFINER`, exposed `auth.users`, views) | **supabase/splinter**: Supabase's own Postgres linter, behind its Security Advisor | Licence file not found at the repository root; verify | Highest-value Supabase addition |
| Live anon-key exposure test | SecHard-owned read-only probe of each table, bucket, and RPC function | — | Owned targets only |
| Python, Go, Ruby SAST | Bandit, gosec, (Brakeman) | Apache-2.0, Apache-2.0 | |
| Malicious packages and typosquats | GuardDog (3.0 released June 2026); OSV `MAL-` advisories; registry existence check for hallucinated packages | Apache-2.0 | |
| Workflow linting | actionlint (beside zizmor) | MIT | |
| Template-based live checks (exposures, misconfig) | Nuclei | MIT | Curate a small reviewed template set |
| API contract fuzzing from OpenAPI | Schemathesis | MIT | Staging only |
| TLS | testssl.sh | GPL-2.0 | Invoke only; do not vendor |
| IaC and containers | Checkov | Apache-2.0 | Note **Trivy and KICS GitHub Actions were compromised in March 2026** (TeamPCP). If either is ever used, pin by digest and never use their actions |
| Repository posture | OpenSSF Scorecard | Apache-2.0 | Maps to OSPS |
| Deep secret verification | TruffleHog | **AGPL-3.0** | Optional, invoke only, owner licence decision |
| AI-assisted review (advisory) | anthropics/claude-code-security-review | MIT | Output labelled advisory; can never satisfy a control |
| Calibration targets | OWASP Juice Shop (MIT), NodeGoat (Apache-2.0) | | Measure detection rate against known flaws |

**Idea sources (unvetted, not dependencies):** rlsgate, vibesafe, whitehat-squad, and VibeScan
target Supabase RLS and key exposure in vibe-coded apps. Several produce "fix prompts" for AI
assistants, which matches the owner's "suggest, don't fix" goal. Public scans of thousands of
vibe-coded Supabase apps in 2026 report that roughly half expose at least one readable table, so
the live anon-key probe is high value.

---

## 8. How this audit was run

- Clean `pnpm install --frozen-lockfile` (Node 24.21.0): OK.
- `build`: OK. `lint`: OK. `typecheck`: OK with `dist/` present, **fails** without it.
- `pnpm test`: 446/450 pass; the 4 failures are preconditions. `test:integration`: 8/8 pass.
- Full CLI run against the example app: 1/33 pass, 32 unsupported; `check` exit 0, `gate` exit 1.
- PR workflow step script reproduced in a shell: gate blocked, job green.
- Temporary evaluator probe tests for H1–H3 (removed afterwards).
- Client-asset inspector run on a synthetic bundle (H5).
- GitHub Actions history read for C4.
- Standards source files:
  - ASVS 5.0.0 CSV (raw.githubusercontent.com, tag `v5.0.0`);
  - OWASP Top 10 2025 category files (OWASP/Top10 repository);
  - OSPS Baseline YAML (ossf/security-baseline repository).
- Not fetched (blocked by network policy): top10.owasp.org, baseline.openssf.org, csrc.nist.gov.
  MVSP and SSDF sizes are from search results and should be re-verified.
- Comparison-project READMEs read as data.
- Tool licences read from each repository.
- Not run here: the scanner binaries (GitHub API blocked), the Supabase stack, Playwright, ZAP.
