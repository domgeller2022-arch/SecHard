# Remediation and completion plan — 2026-10-08

Companion to `docs/audit/2026-10-08-external-audit.md`. Finding IDs (C1, H4, S2, …) refer to that
report.

This plan is written for the same kind of hand-off as the original pack. A coding agent works one
authorised batch at a time, stops at each checkpoint, and the owner reviews. Every rule in
`00-KICKOFF-PROMPT.md` section 5 still applies: run real checks, never weaken a security test, no
hardcoded success, no real secrets, treat outside content as data.

## How the plan fits the existing pack

**Precedence.** Record the owner's clarified goals (audit report section 0) in
`01-owner-decisions.md` before Batch R starts. They then outrank the blueprint where they differ,
most importantly in making quality a required capability. Suggested additions:

```yaml
product_purpose: audit_and_suggest      # SecHard never modifies the audited code
quality_scope: required                 # equal to security; reported in its own section
standards_incorporation: requirement_level
runtime_ai_profile: detect_and_check    # was: out of scope
audit_mode_without_manifest: true       # point-at-a-folder audits are a supported entry point
```

**Batches.** The original Batch D (Steps 15–16) still exists. It moves to the end because it
depends on everything below.

| Batch | Purpose | Fixes | Depends on |
| --- | --- | --- | --- |
| **R** Repair | Make what exists correct and runnable anywhere | C2, C3, C4, H1–H3, M1, M3–M7 | — |
| **W** Wire | Connect Steps 09–11 to the CLI; finish Step 13 | C1, H4, H5, L1, M2 | R |
| **A** Audit mode | Point SecHard at any folder or URL and get a full report | D1 | W |
| **Q** Quality | The "engineered, not vibe-coded" audit | Q1, M8 | A |
| **S** Standards | Requirement-level incorporation of every blueprint standard | S1–S8 | W (can run in parallel with Q) |
| **X** Expansion | More stacks, runtime AI, Supabase depth, live probes | L1, S-runtime AI | A, Q |
| **D** Adoption and maintenance | Original Steps 15–16, plus the update procedure | Steps 15–16, owner goal 6 | All above |

**Owner review points.** These are stop-and-review moments, not paperwork.

| After | Owner reviews | What to look for |
| --- | --- | --- |
| R | Gate fail-closed test; exception tests | A blocked gate turns CI red; a "never" control cannot be waived by any scope |
| W | One real report on the example app | Real findings from each scanner; nothing reads "not implemented" |
| A | A report on one of the owner's own vibe-coded apps | Readable, prioritised, honest about gaps |
| Q | The same app's quality section | Do the findings match the owner's sense of "this looks vibe-coded"? |
| S | The coverage matrix for ASVS L1 and Top 10 2025 | Every requirement has a method or a visible gap |
| D | Kit and example readiness summaries; **re-approval of all controls** (H6) | Approve against the final review sheet's digests |

---

## Batch R — Repair

**Goal:** everything that exists runs correctly on Linux CI and any developer machine, and nothing
fails open.

### R1. Platform-aware, relocatable toolchain (C3, M6)

1. Change `policy/toolchain.yaml` `executables` to a per-platform map:
   - keys `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`;
   - each with asset name, archive digest, executable digest, and expected version;
   - paths relative to the policy root (`tools/bin/<tool>/<version>/<platform>/<binary>`), resolved
     to absolute at runtime;
   - no PATH lookup, and still no home-directory paths.
2. `tools/fetch-tools.mjs`:
   - select the asset for `process.platform`/`process.arch`;
   - verify against the **reviewed digest in `toolchain.yaml`** first, not only against the GitHub
     API's current digest, which is trust-on-first-use;
   - send `GITHUB_TOKEN` when present, so CI is not rate-limited;
   - fail with `unsupported_platform` for anything unlisted.
3. Record platform-specific provenance (checksum file, cosign signature where published) per
   platform.

**Acceptance:**
- `pnpm run fetch:tools` succeeds on a clean Ubuntu runner and on macOS.
- The registry resolves all four tools on both.
- A tampered binary is refused.
- An unlisted platform yields `unsupported_platform`, not a crash.

### R2. CI ordering and a green `repo-checks` (C4)

1. Remove `dist/` imports from typechecked tools: have them import from `src/` via `tsx`/Node type
   stripping, or exclude them from `tsconfig.json` and typecheck them after `build`.
2. In every job, build before anything imports `dist/`.
3. Split the test suite:
   - `test` (unit, no external preconditions);
   - `test:scanners` (needs fetched tools);
   - `test:example` (needs the example built);
   - `test:integration`.
   Each CI job provisions exactly what its suite needs. Precondition tests keep failing loudly.
   Never skip them.
4. Stop tests mutating tracked files (M4). The relink step writes to a temporary copy, or the
   example's lock is generated into a gitignored path.

**Acceptance:**
- `repo-checks` passes on GitHub on a branch: every job green, and the hardening-gate green.
- A deliberately broken typecheck turns it red.
- `git status` is clean after `pnpm test`.

### R3. Fail-closed consumer workflows (C2, M2)

1. `hardening check` exits `1` when any **required** check is `unsupported`, `skipped`, or
   `pending`, and `2` on `error` (the plan's contract: "must still exit nonzero when required work
   fails").
2. In `hardening-pr.yaml` and `hardening-release.yaml`:
   - remove every `|| echo`;
   - report and upload steps keep `if: always()` but cannot change the job outcome;
   - the gate step's exit code decides.
3. The final `hardening-gate` job downloads the report artifact and re-runs `hardening gate` with
   trusted tooling against the recomputed plan (Step 13.5). A missing artifact is a failure.
4. Add trust tests:
   - no `hardening gate` invocation is followed by `||` or `continue-on-error`;
   - a simulated blocked gate produces a failing job, by executing the step scripts in a shell
     harness, not by reading YAML.

**Acceptance:** the reproduction from the audit (blocked gate, green job) now yields a red job, and
the new test fails if the `|| echo` is reintroduced.

### R4. Exception handling (H1, H2, H3)

1. Resolve the `never` policy from the **finding's or check's control**, not the exception's
   `scope.control`.
2. Require `control` or `check_id` alongside any `rule_id` scope. Reject `rule_id`-only scopes as
   not precise.
3. Only apply waivers when `result.outcome` is `pass` or `fail`. `error`, `unsupported`, `skipped`,
   and `pending` cannot be waived.
4. Decide H2 and record the decision in `policy/gate-policy.yaml`. Recommended:
   - a valid waiver on a **permitted** control lets the gate pass;
   - the waiver is listed in a "Waived" section of the report;
   - waivers of `critical` findings are never permitted;
   - waivers of `high` findings require a non-self `approver` at the `release` stage.
5. Tests:
   - each probe from the audit;
   - a valid waiver **asserts `decision.satisfied === true`**;
   - every `never` control is checked against every scope shape.

**Owner review:** the H2 decision and the severity rule.

### R5. Report safety (M1, M7)

1. Route every untrusted string (finding titles, details, paths, diagnostics) through
   `redactSecrets` and then `escapeMarkdown` before the Markdown, HTML, or console writer.
2. Count controls, not checks, in summaries: aggregate per control across all its checks.
3. Test:
   - a finding title containing `![x](https://attacker/p.png)`, a `<script>`, and a synthetic token
     is neutralised in every output format.

### R6. Documentation truth (M3)

1. Replace `README.md` with an accurate, short version: what works today, the exact commands, and
   what does not work.
2. Collapse `docs/status-report.md` and the checkpoint summaries into `docs/status.md`. It is
   generated from the progress record's step states, so it cannot drift.
3. Fix `docs/ci-trust.md` (CODEOWNERS is installed). Document the H4 gap until Batch W closes it.
4. Add a test that runs every command block in the README against a scratch consumer
   (plan Step 15.8, brought forward).

### R7. Owner hygiene items (blocked on owner)

- `security_contact_email` → `SECURITY.md` plus a `security.txt` example.
- `code_licence` and `docs_licence` → `LICENSE`, `NOTICE`.
- Remove the history-rewrite backup on the build machine.
- Leave controls approved-as-is until Batch D re-approval (H6). Mark the review sheet "pending
  re-approval" so nobody relies on the current approvals for a release claim.

**Batch R checkpoint:** CI green on GitHub; fail-closed proven; exception tests; no README claim
contradicts the code.

---

## Batch W — Wire (Steps 09–11 completed, Step 13 finished)

**Goal:** `hardening check` actually runs every implemented recipe and produces real, normalised
results.

### W1. Recipe dispatch

1. Introduce a recipe registry in `src/execution/recipes.ts`:
   `recipe id → { adapter, args builder, intended scope, required tools, mode }`.
2. `checkCommand` dispatches each planned check through it. Unknown recipes stay `unsupported` with
   the reason.
3. Wire:
   - `gitleaks/repository` and `gitleaks/history`;
   - `osv/lockfile`, with `advisory_mode` and provenance recorded;
   - `opengrep/rules`;
   - `zizmor/workflows`;
   - client assets (`build/client-assets`);
   - live HTTP (`live/http`), only when an approved target inventory exists;
   - ZAP baseline, only with an available container runtime.
4. Run independent checks concurrently, with a bounded pool. A failure in one never stops the
   others (plan contract).
5. Store raw reports in the run directory, with digests in each result.

**Acceptance:**
- The CLI on `examples/nextjs-supabase` produces real results for every recipe whose tool is
  available.
- Each scanner shows at least one real detection on its vulnerable fixture **through the CLI**,
  not only through the adapter test.
- A missing tool yields `error` with the registry's reason.

### W2. Client-secret coverage (H5)

1. Add markers for:
   - OpenAI (`sk-proj-`, `sk-`);
   - Anthropic (`sk-ant-`);
   - Stripe (`sk_live_`, `rk_live_`);
   - Google API keys (`AIza`);
   - GitHub tokens;
   - Slack;
   - Twilio, SendGrid, and Resend;
   - Firebase service-account JSON (`"type": "service_account"`);
   - generic PEM keys.
2. Decode JWT-shaped strings and classify by claim: `role: service_role` is privileged,
   `role: anon` is publishable.
3. Inspect server output and source maps as separate scopes, with coverage stated per scope.
4. Fixtures use clearly synthetic values only.

### W3. Pull-request trust (H4, Step 13.7)

1. The PR workflow checks out the **base** branch's `.hardening/` records into a separate
   directory and evaluates against those.
2. The PR's own `.hardening/` changes are diffed and reported as "proposed record changes requiring
   review".
3. A PR that adds exceptions or manual evidence, or turns a feature off, gets a review-required
   result, never a weaker evaluation.
4. Document the bootstrap path: the first adoption has no base records.

### W4. Live-check recipe completion (Step 11)

Fold `tools/run-live-checks.mjs` into a `live/http` recipe. Add the exposure probes in X3 here, or
mark them `unsupported` until X3.

**Batch W checkpoint:** a real report on the example app with real findings from every tool, plus a
PR-trust test showing a self-added exception is not honoured.

---

## Batch A — Audit mode: point it at anything

**Goal:** the owner runs one command against a folder, a Git URL, or a deployed URL, and gets a
complete, prioritised, plain-English audit, without writing a manifest first.

### A1. `hardening audit` command

```text
hardening audit PATH [--url https://deployed.example] [--out DIR] [--profile auto|...] [--depth quick|standard|deep]
```

1. Copies nothing into the audited repository and changes nothing there (`product_purpose:
   audit_and_suggest`). All output goes to `--out`, defaulting to `./sechard-audit-<timestamp>/`
   outside the target.
2. Runs inside the existing plan, check, and gate machinery. Audit mode generates an ephemeral
   manifest and plan; it does not bypass the evaluator.
3. `--url` enables live checks only against that origin. The approved-target inventory is
   generated from it and shown in the report.

### A2. Stack and feature detection

1. Detect languages, frameworks, and package managers from lockfiles, manifests, and config files:
   - Next.js, Vite/React, SvelteKit, Express/Fastify, Python (Flask, FastAPI, Django), Go;
   - Supabase (`supabase/`, client imports), Firebase (`firebase.json`, rules files);
   - Docker, Terraform, and GitHub workflows;
   - LLM SDK imports (`openai`, `@anthropic-ai/sdk`, LangChain, and similar);
   - Stripe and webhooks;
   - file uploads;
   - Expo/React Native, Flutter, Electron.
2. Each detection records its evidence (file and pattern). A detected feature becomes `enabled`
   with that evidence. Anything undetectable stays `unknown`, never `false` (existing rule).
3. Unsupported stacks (mobile, desktop, unknown languages) produce a **prominent coverage-gap
   banner** plus whatever generic checks still apply: secrets, dependencies, duplication.

### A3. The report (designed for a non-coder owner)

Formats: `report.md`, a self-contained `report.html`, `report.json`, and `report.sarif` (for GitHub
code scanning).

1. **Summary page:**
   - two scores, security and quality, each with a plain verdict;
   - "Fix these first" (the top 10 by severity × exposure);
   - a "What we could not check" box.
2. **Every finding includes:**
   - what was found;
   - where (file:line, or URL);
   - why it matters, in plain English;
   - how to fix it, as a suggested change with an example;
   - effort (S/M/L);
   - confidence (confirmed, likely, or signal);
   - standards references (ASVS ID, Top 10 2025 ID, API Top 10 ID, CWE);
   - **a ready-to-paste prompt** the owner can give their AI assistant to make the fix.

   SecHard suggests; it never edits.
3. **Sections:** Security, Quality, Supply chain, Live deployment, Standards coverage, and Gaps.
   Quality results never change the security verdict, and the reverse.
4. **Rendering:** the same evaluation drives every format (existing rule: formatting cannot change
   the decision).

### A4. Profiles become composable

Replace the two fixed profiles with:
- `core`, which always applies;
- stack profiles (`nextjs`, `react-spa`, `node-api`, `python-web`, `supabase`, `firebase-detect`);
- feature profiles (`payments`, `uploads`, `runtime-ai`, `multi-tenant`);
- `quality`.

Audit mode composes profiles from detection. The gate mode keeps explicit selection.

**Acceptance:**
- `hardening audit` on three different sample apps (the example, a Vite + Supabase app, a Python
  FastAPI app) produces complete reports with no manual setup.
- An Expo app produces a gap banner, not a clean report.
- The audited directory is byte-identical afterwards (test with a checksum of the tree).

---

## Batch Q — Quality: "engineered, not vibe-coded"

**Goal:** the quality section finds what an experienced reviewer would object to, measured where
possible and clearly labelled as a signal where judgement is involved.

### Q1. New quality controls

Each control follows the existing catalogue rules (draft status, acceptance criteria, methods,
limitations, applicability). Thresholds live in a reviewed `policy/quality-thresholds.yaml` and
are calibrated in Q6, not guessed.

| ID | Control | Automated method |
| --- | --- | --- |
| QUAL-01 | Build, tests, and type check pass (existing) | App's own scripts, detected |
| QUAL-02 | Strict static correctness | SecHard-owned strict configs: typescript-eslint `strict-type-checked`, `tsc --strict` probe, Ruff broad rule set, mypy/pyright; counts of `any`, `@ts-ignore`, `# type: ignore` |
| QUAL-03 | No significant duplication | jscpd: duplicated-line percentage plus a list of clones |
| QUAL-04 | Bounded complexity and size | Lizard: cyclomatic complexity, function length, parameter count, file length per language |
| QUAL-05 | No dead code or unused dependencies | Knip (JS/TS), Vulture (Python) |
| QUAL-06 | Sound module structure | dependency-cruiser: cycles, layer violations (UI importing DB clients, server-only code imported client-side) |
| QUAL-07 | Errors are handled, not swallowed | Opengrep rules: empty catch, ignored Supabase `{ error }`, unawaited promises, `console.log` in production paths, generic `catch (e) {}`. Maps to **Top 10 2025 A10** |
| QUAL-08 | Tests that test something | Skipped/focused tests, assertion-free tests, test-to-code ratio, coverage when available, optional Stryker mutation score on security-critical files |
| QUAL-09 | No AI-authorship tells (signal) | SecHard-owned analyser; see Q4 |
| QUAL-10 | Consistent formatting and naming | Prettier/Biome/Ruff format check in check-only mode; naming-convention consistency per language |
| QUAL-11 | Repository hygiene and documentation truth | README commands exist and are runnable; LICENSE; CHANGELOG; `.gitignore` covers secrets and build output; lockfile committed; CI present. Maps to OSPS DO/LE/QA |
| QUAL-12 | Dependency health | Outdated majors, deprecated or abandoned packages, duplicate libraries for one job (two date libraries, two HTTP clients) |
| QUAL-13 | Frontend quality (when a UI is detected) | axe-core (WCAG 2.2 AA) via Playwright; Lighthouse CI performance budgets; bundle size |

### Q2. Run analysers with SecHard's configuration, not the app's

A vibe-coded app's own lint config is usually weak or absent. SecHard runs each tool with its own
pinned, reviewed config. The app's config is reported separately ("your project lints clean
under your own rules; under SecHard's rules: 214 issues").

### Q3. Tool provisioning

Add the quality tools to the toolchain under the same rules as scanners:
- npm-based tools in an isolated, lockfile-pinned `tools/quality/` package, installed with the
  release-age policy;
- binaries digest-pinned per platform;
- Python tools in a pinned, hashed `requirements.txt` under `tools/quality/python/`.

### Q4. The "vibe-coded tells" analyser (QUAL-09)

No mature open-source tool exists for this, so SecHard owns it. Each rule is an Opengrep rule or a
small TypeScript analyser with fixtures. Each is reported as a **signal with an explanation**, never
as proof of AI authorship.

1. **Comment noise:**
   - comments that restate the next line;
   - "Step 1:" narration;
   - emoji in code or logs;
   - banner comments;
   - comment density far above the project median;
   - self-justifying phrases ("deliberately", "this ensures", "robust", "comprehensive").
2. **Placeholders and stubs:**
   - "In a real implementation", "TODO: implement", "for now";
   - mock data in production paths;
   - functions that return constants where logic is implied;
   - hardcoded `localhost` or example URLs.
3. **Over-defensive or cargo-cult code:**
   - try/catch around non-throwing code;
   - redundant null checks after a type guarantees a value;
   - `as any` to silence errors;
   - double validation that disagrees.
4. **Structural tells:**
   - near-duplicate helper functions with different names;
   - several utility files doing the same job;
   - mixed paradigms for the same task (fetch and axios both);
   - inconsistent file naming;
   - very large page or component files mixing data access, logic, and UI.
5. **Hallucination tells:**
   - imports of packages that do not exist in the registry, or were published days ago;
   - calls to APIs that do not exist in the installed version (TypeScript reports these when strict
     typing is on; QUAL-02);
   - env vars read but never documented.
6. **Leftovers:**
   - commented-out blocks;
   - `debugger`;
   - unused feature flags;
   - `.only` in tests;
   - generated files committed by accident.

**Acceptance:** each rule has a vulnerable fixture and a clean fixture. A precision check on the
calibration corpus (Q6) shows a false-positive rate the owner accepts.

### Q5. Advisory AI review (optional, clearly labelled)

An optional `--ai-review` runs an LLM review over the highest-risk files: auth, data access, and
payment paths.
- Results are **advisory**: shown in their own section, never satisfying or failing a control
  (blueprint rule).
- Cost, data handling (code is sent to a provider), and provider are stated in the report, and the
  run needs an explicit owner opt-in.
- Candidates: anthropics/claude-code-security-review (MIT) for security, plus a SecHard-owned review
  prompt for design and readability.

### Q6. Calibration corpus

1. Build `tests/corpus/`: small apps written the way vibe-coded apps are, each with a documented
   list of seeded issues (security and quality) and a clean twin.
2. Also use OWASP Juice Shop (MIT) and NodeGoat (Apache-2.0) as external targets, run in disposable
   containers.
3. Report per release:
   - recall: seeded issues found;
   - precision: findings that are real;
   - per category.

This is how "finds every issue" becomes a measured claim instead of a promise. The report states the
measured rate.

**Batch Q checkpoint:**
- The quality section of a report on the owner's own app.
- Corpus recall and precision numbers.
- **SecHard passes its own quality audit.** That means trimming its comments and collapsing its
  process documentation (audit section 6).

---

## Batch S — Standards incorporated at requirement level

**Goal:** for every standard in blueprint section 3, each requirement is mapped to a control and a
verification method, or listed as a visible gap with a reason. The report can then say exactly which
requirements an audit covered.

### S1. Data model

1. Add `controls/mappings/<standard>.yaml` per standard. Each entry records:
   - the requirement ID;
   - SecHard's own one-line summary (do not copy CC BY-SA text wholesale);
   - level;
   - applicability predicate;
   - the control IDs;
   - the recipe IDs;
   - method (`automated`, `manual`, `advisory`, `not_applicable`, or `gap`);
   - relationship (`related_risk` or `verified_coverage`);
   - reviewer and date.
2. Keep the existing rule: nothing is `verified_coverage` until assessed. A precise ID with
   `related_risk` is allowed and now required.
3. A generator produces `controls/coverage/<standard>.md`: a requirement-by-requirement matrix
   showing automated, manual, and gap counts.
4. Audit reports include a per-standard coverage summary for the actual audited app, for example:
   "ASVS L1: 41 of 70 checked automatically, 18 manual, 11 not checked."

### S2. Per-standard work

| Standard | Work | Done when |
| --- | --- | --- |
| ASVS 5.0.0 | Import the official CSV (tag `v5.0.0`) as data: IDs, levels, and SecHard summaries, with licence notice. Map all 345 requirements. **L1 (70) must each have a method or a justified gap**; L2 mapped; L3 recorded. Add controls where ASVS reveals missing areas: **V7 Session Management**, **V10 OAuth/OIDC**, V3 Web Frontend (CSP, cookies), V5 File Handling, V11 Cryptography, V14 Data Protection, V15 Secure Coding | A test fails if any ASVS ID is unmapped or any chapter name is invalid |
| OWASP Top 10 2025 | Fix names. Map all ten categories, A01–A10, to controls and recipes. A10 maps to QUAL-07 and WEB rules | All 10 present; a test rejects names not in the 2025 list |
| API Security Top 10 2023 | Map API1–API10. Add API7 SSRF and API10 unsafe consumption checks (Opengrep rules for user-controlled fetch URLs; validation of third-party API responses). Remove "injection" | All 10 present; SSRF fixture detected |
| WSTG 4.2 and Cheat Sheets | Every test recipe cites the WSTG test ID(s) it implements (for example `WSTG-ATHZ-02` for IDOR) and the cheat sheet it follows | A test fails if a test recipe lacks a WSTG ID |
| NIST SSDF 1.1 | Map 42 tasks: PW and RV tasks to controls; PO and PS tasks to governance and manual evidence | Matrix generated; unmapped tasks listed as gaps |
| OSPS Baseline v2026.08.28 | Map 67 requirements. **Apply Level 1 to SecHard itself** and check it in CI with OpenSSF Scorecard plus SecHard's own GOV recipes. Offer the same as a consumer `repo-posture` recipe | SecHard meets OSPS L1, or each miss is an owner-blocked item |
| MVSP | Map 25 controls; business and operational ones become manual-evidence recipes | Matrix generated |
| RFC 9700 | New AUTH-03 "OAuth/OIDC flow security": PKCE, exact redirect URI, no implicit grant, state/nonce, token storage. Static rules plus a manual recipe; ties to ASVS V10 | Fixture with implicit grant detected |
| ASD Secure by Design | Map foundations to CTX, GOV, and OPS controls and manual evidence | Matrix generated |
| SLSA 1.2 | SecHard's own releases get Build L2 via GitHub artifact attestations; verification documented | Release artifact has verifiable provenance |
| AISVS 1.0, LLM Top 10, Agentic Top 10 | New `runtime-ai` profile (X2) with AI-* controls mapped to these | See X2 |
| MCP Top 10 | Link-only (non-commercial licence). Map IDs by reference only, with no adapted text | Licence note in sources |
| MASVS, Electron | Detection plus gap banner (A2). Electron checks for `nodeIntegration`, `contextIsolation`, and `sandbox` as a small first step | Electron fixture flagged |

### S3. Curate the agent-guidance sources (S7)

Adapt CodeGuard (CC BY 4.0), the OpenSSF AI-instructions guide, and the OWASP Secure Coding with AI
cheat sheet into `agent-rules/core/` with attribution. In SecHard's role these rules are
**suggestions included in the audit output** ("add this `CLAUDE.md` to your project"). They are
not something SecHard writes into the app.

### S4. Comparison projects (S8)

Record each of the five projects separately in `upstream/sources.yaml`, with its own licence check.
Port their ideas, not their text:
- live exposure probes (X3);
- preflight's quality, accessibility, performance, SEO, compliance, and open-source-readiness
  audits (Q1, QUAL-11, QUAL-13, PRIV-01);
- gorrion's monitoring, cron, and stack-trace items (OPS-01, WEB-02);
- astoj's IaC area (X4).

**Batch S checkpoint:** coverage matrices for every standard; the owner reviews ASVS L1 and Top 10
2025 line by line.

---

## Batch X — Expansion

### X1. Supabase depth

1. Run **supabase/splinter** (Supabase's own lints) against the local stack, or against a database
   URL the owner supplies. Verify the licence first.
2. Static migration analysis (SecHard rules):
   - tables in exposed schemas without RLS;
   - policies using `true` or only `auth.role() = 'authenticated'`;
   - `SECURITY DEFINER` functions without a fixed `search_path`;
   - views without `security_invoker`;
   - public storage buckets;
   - grants to `anon`.
3. **Live anon-key probe** (read-only, owned targets only): with the app's publishable key, try
   `select` on every table, `list` on every bucket, and calling every RPC function. Report anything
   readable. This catches the most common real-world vibe-coded breach.

### X2. Runtime-AI profile

Controls AI-01 to AI-06, mapped to AISVS, the LLM Top 10, and the Agentic Top 10:
1. Model API keys are server-side only (W2 markers).
2. Spend and rate limits per user (existing PAT-SPEND-01 becomes a recipe).
3. Prompt-injection surfaces: user content concatenated into system prompts, retrieved content
   unlabelled.
4. Model output is never rendered as HTML or executed unescaped.
5. Tool and function-calling permissions are enforced server-side.
6. Per-user isolation of conversation history and caches.

Static rules first; live and adversarial evaluation (for example promptfoo or garak) is an optional
later recipe.

### X3. Live exposure probes (L1)

Read-only and owned targets only; the scope is shown in the report:
- `/.env`, `/.git/HEAD`, `/.DS_Store`, backup files;
- source maps;
- debug and admin routes (`/api/debug`, `/_next/…`, framework-specific);
- directory listing;
- verbose error pages and stack traces;
- cookie flags (`Secure`, `HttpOnly`, `SameSite`);
- CORS (reflected origin with credentials);
- `security.txt`;
- HSTS on HTTPS.

Optional curated **Nuclei** templates (MIT), pinned by digest, for known exposures. Optional
**Schemathesis** (MIT) when an OpenAPI spec is found, against staging only. testssl.sh pinned for
TLS.

### X4. More stacks and artefacts

- Python: Bandit plus Ruff security rules.
- Go: gosec.
- Firebase: Firestore and Storage rules static checks, with emulator tests as a later step.
- Containers: hadolint (GPL-3.0, invoke only) and Checkov (Apache-2.0).
- Malicious and typosquatted packages: GuardDog plus OSV `MAL-`, plus a registry existence and age
  check for every direct dependency (catches hallucinated packages).
- Workflows: actionlint beside zizmor.

**Do not adopt Trivy or KICS GitHub Actions.** Both were compromised in March 2026. If the Trivy
binary is ever wanted, pin it by digest from a verified release and never use the action.

---

## Batch D — Adoption, maintenance, release (original Steps 15–16, extended)

### D1. Independent adoption (Step 15, unchanged in intent)

Prove both modes from a separate repository:
- audit mode (`hardening audit`, zero setup);
- gate mode (`.hardening/` records plus the pinned workflow).

Every README command runs against the packed tarball. Paths with spaces, a missing optional tool,
and a missing required tool are tested.

### D2. Keeping SecHard current (owner goal 6)

1. A scheduled workflow, `scheduled-checks.yaml`, runs weekly and monthly:
   - new releases of every pinned tool and rule pack;
   - new standard editions (ASVS 5.0.1, OSPS releases, Top 10);
   - advisory freshness;
   - expiring exceptions;
   - licence changes in upstream sources.
2. Output is **a draft PR or issue for review**. It never activates a new policy, tool, or mapping
   by itself (blueprint rule). Updates to digests and mappings go through the same review boundary.
3. `docs/maintenance.md` holds:
   - a monthly checklist;
   - an urgent path for a compromised tool, modelled on the Trivy incident: revoke the pin, re-verify
     the digest, publish an advisory;
   - how to add a new tool or standard.
4. One updater (Renovate or Dependabot) with an explicit 7-day delay, tested with pnpm 12.

### D3. Release verification (Step 16)

1. Run the corpus, recording recall and precision.
2. Run all acceptance cases.
3. Publish separate kit-readiness and example-readiness summaries, plus release notes listing
   measured coverage and known gaps.
4. **Owner re-approves all controls** against the final review sheet (H6), recorded with the
   existing digest procedure.

**Batch D checkpoint:** first release `0.1.0` candidate. Publication remains a separate owner action.

---

## Things to keep from the current build

Do not rewrite these; extend them:
- `src/validation/loader.ts`;
- `src/execution/process.ts`;
- the evaluator's identity and freshness logic;
- the evidence store;
- the adapters' parsers;
- the reference app's migration and authorization tests;
- workflow hygiene tests;
- the honest-gap reporting model.

## Rules for the implementing agent, additional to the pack

1. A recipe is "done" only when the **CLI** produces a real result for it on a real target. Adapter
   unit tests alone do not count. This is the C1 lesson.
2. Every workflow claim is tested by **executing** step scripts in a harness, not by reading YAML.
   This is the C2 lesson.
3. Nothing in policy may contain an absolute path from one machine. This is the C3 lesson.
4. A status or README claim must be backed by a command the reader can run. Status documents are
   generated, not written by hand. This is the M3 lesson.
5. Quality findings are suggestions with explanations. Label them signal, likely, or confirmed, and
   never present a heuristic as proof.
6. SecHard never writes to the audited project. A test enforces this.

## Rough sizing

Indicative only, for one agent working under checkpoints:
- R: small to medium.
- W: medium.
- A: medium to large.
- Q: large; the AI-tells analyser and calibration corpus are the bulk.
- S: large; mostly careful mapping work, with ASVS the biggest piece.
- X: medium.
- D: medium.

R and W should come first: until they are done, nothing else can be demonstrated on a real app.
