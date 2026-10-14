# Follow-up audit — 2026-10-10

Audited commit: `f3c9727` (`main`, 13 commits after the first audit's `88df318`). The audit checks
whether the remediation plan was carried out (Batches R, W, U, Q, S) and looks for new defects.

**Method.**
- Clean clone, Node 24.21.0, pnpm 12.9.1, pinned scanners fetched and verified on linux-x64.
- Every suite run; GitHub Actions history read.
- Evaluator attack probes written as temporary tests and removed afterwards.
- `hardening audit` run against:
  - an **independently written vibe-coded test app** with about 60 planted issues, which neither
    SecHard nor its build agent had seen (Appendix A);
  - SecHard itself.

**Environment limit.** This sandbox blocks `api.osv.dev`, so dependency-advisory scanning could not
be exercised here. The 9 scanner-suite failures seen locally all trace to that block (osv-scanner
exit 127, "Forbidden"), not to the code. GitHub CI, which has open egress, runs that suite green.

---

## 1. Bottom line

The repair work is real. Every critical defect from the first audit is fixed, and I verified each
fix by running it, not by reading the changelog:
- the scanners run on Linux;
- the CLI runs them;
- CI is green;
- the PR gate fails closed;
- the waiver bypasses are closed;
- `hardening audit PATH` works with zero setup and never touches the audited project.

**However, measured on an app it had never seen, SecHard currently finds about 1 in 5 planted
security problems and about half of the planted quality problems.**

| Area | Claimed | Measured here |
| --- | --- | --- |
| Quality corpus | recall 1.0 (on the build agent's own corpus) | about 0.57 (17 of 30) |
| Security | not stated | about 0.21 (7 of 33) |
| Default Next.js audit | — | 40 of 51 planned checks are "not implemented in this build" |

The "could not check" list is honest about this, but the owner's goal (a thorough audit that finds
everything, including "looks vibe-coded" quality problems) is not yet met.

---

## 2. Verification of the first audit's findings

| Finding | Status | How verified |
| --- | --- | --- |
| C1 scanners not wired | **Fixed** | `audit` on the test app produced real gitleaks, opengrep, and zizmor findings |
| C2 PR gate fails open | **Fixed** | No `\|\| echo`; the gate step decides; trust test executes the step script |
| C3 macOS-only tools | **Fixed** | `fetch:tools` verified 4/4 tools on linux-x64 against reviewed digests |
| C4 CI never passed | **Fixed** | Runs 10–13 green (`8ff7cc6` … `f3c9727`); the changelog's account of the red period matches the run history |
| D1 cannot point at a folder | **Fixed** | `hardening audit PATH`; tree checksum identical before and after |
| Q1 no quality analysis | **Partly fixed** | 6 recipes wired; duplication, complexity, dead code, structure, formatting, frontend, and test-suite execution still unbuilt (N11) |
| H1 never-control waivable | **Fixed** | Probes P1, P2c, P3: blocked or `exception.invalid` |
| H2 waivers can never pass | **Fixed, owner-approved** | Probe P4: satisfied, visible as `waived` |
| H3 waiver over error | **Fixed** | Probe P5 |
| H4 PR edits own records | **Mostly fixed** | Base records used; see N13 |
| H5 client-secret markers | **Fixed for build output** | Markers added; source files rely on gitleaks (see N1, N2) |
| H6 approvals | **Pending by design** | 20 of 35 v1 approvals resolve; full re-approval is Batch D |
| S1–S8 standards | **Partly fixed** | Requirement-level data exists; coverage thin and partly overstated (N9, N10); S3 deferred again; astoj skipped wrongly (N17) |
| M1, M3, M4, M5, M7, M8, L1 | **Fixed** (L1 partly) | Escaping and redaction; truthful README; tests do not dirty the tree; filtered installs; per-control counts; example app fixes confirmed in source |

These changelog claims checked out:
- the test counts (535 unit, 8 integration);
- the CI history;
- the reason for the environment-branching tests. Both branches still assert a nonzero, fail-closed
  exit, and the scanner job separately requires real findings, so this was **not** a weakened test.

---

## 3. New findings

### High

**N1. Low detection rate on an unseen app. Measured.**
Planted problems that the audit did **not** report:

| Area | Missed |
| --- | --- |
| Injection and code execution | SQL injection (2), `dangerouslySetInnerHTML` XSS (2), path traversal |
| Request handling | SSRF via a variable (see N5), open redirect, CORS `*` with credentials |
| Authentication and sessions | MD5 password hashing, hardcoded JWT secret, `alg: none`, insecure cookie flags, `Math.random` reset tokens |
| Logging and secrets | Password written to logs; OpenAI key hardcoded in a client component |
| Payments | Stripe webhook with no signature check that upgrades a plan from client-controlled input |
| Supabase | Table without RLS, `using (true)` policy, `grant all … to anon`, a `SECURITY DEFINER` admin function without `search_path`, a public storage bucket |
| Workflows | `permissions: write-all` |
| Configuration | `productionBrowserSourceMaps: true`, `ignoreBuildErrors: true` |

The rule packs are the cause. SecHard ships **9 security code rules** (eval, exec, innerHTML,
regex-shaped SSRF, API response consumption, implicit grant, three Electron rules), and Supabase
migration analysis is Batch X work. The build agent's corpus (recall 1.0) was written by the same
agent that wrote the rules, so it measures self-consistency, not detection.

**N2. Leaked secrets are mis-ranked and can be waived. Reproduced.**
- Gitleaks findings arrive with severity `unknown` and a generic title ("Uncovered a JSON Web Token").
- The same secret is reported twice, once by the repository scan and once by the history scan.
- On the test app, the leaked Supabase **service-role** key (which bypasses all database security)
  ranked #9–10 in "Fix these first" as `unknown`, four duplicate rows filled the top-10 slots, and
  the live Stripe key did not appear in the top 10. An unpinned GitHub Action ranked #5.
- Because the severity is `unknown`, the "critical can never be waived" rule does not apply: probe
  P7 waived a leaked JWT on SEC-01 and the gate passed.

Fix:
- classify secret findings (privileged and live keys are `critical`, decoding JWT `role` as the
  client-asset check already does);
- de-duplicate across the repository and history scans;
- never allow a waiver on a secret finding of unknown or critical class.

**N3. "Mixed" controls now pass on partial scanner output alone. Reproduced.**
Batch W made a `mixed` method require only `partial` coverage. 24 controls rely solely on mixed
methods, and none plans the manual half.

With every tool check returning `partial` and **no manual evidence**, these come out `satisfied`:
- SEC-01, secret scanning;
- CI-01, isolated untrusted execution, satisfied by zizmor alone;
- GOV-01, repository protections;
- WEB-01, input and output boundaries;
- AGT-01, agent permissions.

The implementation plan defines mixed as "tool/test evidence **plus** reviewed manual/configuration
evidence; it does not mean partial work can be silently accepted." This is a security-relevant
loosening, and it was made without owner review.

Fix: plan a manual-evidence check for every mixed method (or split the definitions), and keep
`partial` acceptable only when that manual record is present and current.

**N4. The `console.log` rule never fires in audit mode. Reproduced.**
`src/execution/recipes.ts` keeps a finding only if the first path segment is `src`, `app`, `lib`,
and so on. Audit mode reports absolute paths, whose first segment is empty, so every match is
discarded. The test app's run recorded "2 console.log finding(s) … were held back". One of them
logs a password.

Fix: relativise to the audit root before filtering, and add a regression test with an absolute
target.

### Medium

**N5. The SSRF rule is a text match.** It fires only when request data appears inside the `fetch(...)`
call. The normal shape (`const target = …searchParams.get('url'); fetch(target)`) is missed. The
changelog records this limitation. Opengrep's taint mode exists for exactly this and should be used
for SSRF, SQL injection, XSS, path traversal, open redirect, and command injection.

**N6. "SecHard passes its own quality audit" is overstated.**
- `tests/quality/self-audit.test.ts` runs 5 of the 6 quality recipes and omits the opengrep
  error-handling pack.
- A real `hardening audit` of SecHard reports 4 **high** empty-catch findings
  (`src/execution/process.ts:115`, `src/quality/common.ts:55`, `tools/generate-status.mjs:97`, and
  the example app), 1 medium, and a quality score of 0.
- Several of those catches are intentional and commented, which is itself a calibration defect: an
  explained, intentional empty catch should not rank with SQL injection.
- The narration-comment rule was narrowed during the self-audit. It now needs two identical
  identifiers shared between the comment and the next line, and catches 1 of about 12 typical AI
  narration comments in the test app (N12).
- Detection classifies SecHard itself as a "React SPA with Supabase and payments" because of its
  fixtures.

**N7. Detection misses the dangerous cases.**
- Payments are detected only from an `import … 'stripe'` line. A webhook that handles
  `checkout.session.completed` without importing Stripe (meaning no signature verification, which
  is the actual vulnerability) leaves `payments: unknown`, so BIZ-01 is never planned. The `stripe`
  dependency in `package.json` is ignored.
- `runtime_ai` is detected as `enabled` (OpenAI SDK, `dangerouslyAllowBrowser: true`), but the
  report never says that AI-specific risks were not checked. No gap banner, no "could not check" row.

**N8. Gate mode breaks for other repositories while SecHard is private.**
The consumer workflows check out `domgeller2022-arch/SecHard` with the consumer's default token. A
private repository cannot be read that way, and the owner's recorded decision is
`repo_visibility: private`. Every adopting repository's `hardening-pr` job would fail at checkout.

Fix: decide which way to go:
- a read-only deploy key or GitHub App token for SecHard;
- a public release artefact;
- vendoring a pinned copy;

and document it in `docs/adoption.md`.

**N9. The coverage matrices for owner review were never committed.**
`.gitignore` contains `coverage/` (intended for test-coverage output), which also matches
`controls/coverage/`. The Batch S checkpoint asks the owner to review `controls/coverage/asvs.md`
and `owasp-top-10.md` "line by line". Neither file exists in the repository.

**N10. Standards coverage is thin, and 13 entries overstate it.**
- ASVS 5.0.0: 22 automated, 54 manual, **257 gaps**, 12 not applicable.
- 13 mapping entries are marked `automated` although none of their recipes run in this build:

  | Standard | Entries |
  | --- | --- |
  | ASVS | V10.4.4, V10.6.1 |
  | OSPS | AC-04.01, BR-05.01, QA-02.01, QA-03.01, QA-06.01 |
  | SSDF | PO.3.3, PO.4.2, PW.1.2 |
  | MVSP | 2.5, 3.1 |
  | ASD SBD | 5 |

Add a test that an `automated` entry must name at least one wired recipe.

**N11. Most of a default audit is still "not implemented".**
40 of 51 planned checks on a Next.js app report "not implemented in this build". That covers
authorization, sessions, OAuth flow, Supabase grants and policies, abuse limits, and all the
structural quality checks: duplication (jscpd), complexity (Lizard), dead code (Knip), module
structure (dependency-cruiser), formatting, frontend quality, and running the app's own tests and
types. Those structural checks are the core of the "engineered, not vibe-coded" goal.

### Low

- **N12.** The narration rule's recall is poor; see N6.
- **N13.** PR workflow:
  - when a PR changes `.hardening/` records, the job fails as intended, but the evaluation steps do
    not run afterwards (they lack `if: always()`). The changelog says "the evaluation still runs on
    the base records";
  - a legitimate record change can never pass, which pushes the owner towards overriding the
    required check. Document the reviewed-merge path.
- **N14.** `hardening audit` exits 0 whatever it finds (documented). Add `--fail-on high` so it can be
  a CI gate without parsing JSON.
- **N15.** Markdown and JSON reports print absolute machine paths for opengrep and zizmor findings
  (`/tmp/…/blindapp/utils/admin.ts`), while gitleaks findings are relative. The SARIF fix was not
  applied to the other formats.
- **N16.** `pnpm run typecheck` fails on a fresh checkout (`tests/domain/standards-coverage.test.ts`
  imports `../../dist/…`). CI passes only because it builds first. Import from `src/`.
- **N17.** S3 (curating CodeGuard, the OpenSSF guide, and the OWASP AI cheat sheet into the agent
  rules) is deferred for the second time. The astoj comparison project was skipped because "the plan
  names it without a URL", but the blueprint links `https://github.com/astoj/vibe-security`.
- **N18.** The `--url` guard resolves DNS once and the HTTP check resolves again later: a small
  DNS-rebinding window. Low risk because the owner supplies their own URL; pin the resolved address
  if it matters.
- **N19.** The reference app's new CSP allows `script-src 'unsafe-inline'`, which removes most of its
  XSS protection. A nonce-based CSP is the known fix.
- **N20.** Dependency health reads only the lockfile. With no lockfile, duplicate and unused
  libraries in `package.json` are not reported.
- **N21 (latent).** A finding with `triage: accepted` passes with no exception record, expiry, or
  approver (probe P10). Today only SecHard's own adapters set triage (always `unresolved`), so it is
  not reachable from consumer input. Require an exception reference for `accepted`.
- **N22 (latent).** A *medium* finding on AUTHZ-01 does not block (probe B1). The blueprint says
  unauthorized data access blocks "regardless of scanner label". This becomes live when the
  authorization recipes are wired.
- **N23.** Process: `authorised_batch` still reads `U` while Q and S were done on verbal instruction.
  The owner should confirm the W, U, Q, and S checkpoints were reviewed.

---

## 4. Recommended next work, in order

1. **N4, N2, N3** (small, high value):
   - fix the console.log path bug;
   - classify, de-duplicate, and never-waive secrets;
   - restore the manual half of mixed controls.
2. **N1/N5, security depth.** Add a taint-mode rule pack covering SQL injection, XSS
   (`dangerouslySetInnerHTML`, `innerHTML`), SSRF, path traversal, open redirect, and command
   injection. Add pattern rules for weak hashing, JWT `none` and hardcoded secrets, insecure cookie
   flags, CORS wildcard with credentials, `Math.random` for tokens, logging secrets,
   `dangerouslyAllowBrowser`, and dangerous Next.js config. Each rule needs a vulnerable and a clean
   fixture.
3. **Batch X1, Supabase.** Static migration rules (RLS off, `using (true)`, grants to anon,
   `SECURITY DEFINER` without `search_path`, public buckets), then splinter and the live anon-key
   probe.
4. **N11, structural quality.** Wire jscpd, Lizard, Knip, and dependency-cruiser. They are the
   heart of the "10x engineer" goal.
5. **Use Appendix A as an external calibration corpus,** plus OWASP Juice Shop and NodeGoat. Report
   recall from apps the rule author did not write.
6. **N7, N8, N9, N10, N6, and the low items.**
7. Then Batch X (the rest) and Batch D, including owner re-approval of the controls.

---

## Appendix A — the independent test app

Built in a scratch directory, never committed. All secrets were synthetic and non-functional. It
had 18 files: a Next.js app router app with Supabase, Stripe, and OpenAI dependencies.

Re-create it from this list for future calibration. ✔ = reported, ✘ = missed.

**Security (7 of 33 reported):**
- ✘ OpenAI key in a client component
- ✘ `dangerouslyAllowBrowser`
- ✘ `dangerouslySetInnerHTML` ×2
- ✔ Supabase service-role JWT in a client-imported file (as `unknown`)
- ✘ SQL injection ×2
- ✘ unauthenticated delete route (expected: not statically checkable; listed as not run)
- ✘ SSRF via a variable
- ✘ MD5 password hash
- ✘ hardcoded JWT secret
- ✘ `alg: none`
- ✘ insecure cookie flags
- ✘ `Math.random` reset token
- ✘ open redirect
- ✘ CORS `*` with credentials
- ✘ password logged
- ✘ unsigned Stripe webhook granting a plan
- ✘ table without RLS
- ✘ `using (true)` policy
- ✘ `grant all to anon`
- ✘ `SECURITY DEFINER` admin function without `search_path`
- ✘ public bucket
- ✔ committed `.env` (Stripe key and JWT found; database password missed)
- ✔ `pull_request_target` with head checkout and secrets
- ✔ template injection
- ✘ `permissions: write-all`
- ✔ unpinned action
- ✔ `eval`
- ✔ command injection
- ✘ path traversal
- ✘ production source maps enabled

Vulnerable dependency versions were not checked: there was no lockfile, and this is correctly
listed under "could not check".

**Quality (17 of 30 reported):**
- ✘ duplicated helper in two files
- ✘ high-complexity function
- ✘ dead export
- ✔ TODO placeholder
- ✔ "In a real implementation"
- ✘ mock data in production code
- ✔ `any` ×9
- ✔ `@ts-ignore`
- ✔ commented-out code
- ✔ empty catch
- ✔ floating promises ×2
- ✘ narration comments (1 of about 12 reported)
- ✔ emoji
- ✔ `debugger`
- ✘ `console.log` ×2 (dropped by N4)
- ✔ hardcoded localhost URL
- ✘ moment + dayjs
- ✘ axios + node-fetch
- ✘ unused dependency
- ✘ swallowed Supabase `{ error }`
- ✘ `ignoreBuildErrors` and `ignoreDuringBuilds`
- ✘ README commands that do not exist
- ✘ data access mixed into a UI component
- ✔ `.only`
- ✔ `.skip`
- ✔ tautological assertion
- ✔ assertion-free test
- ✔ no lockfile
- ✔ no CHANGELOG or licence
- ✔ `.gitignore` without `.env`
