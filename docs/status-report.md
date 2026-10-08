# Consolidated status report

Generated 2026-10-08 by a full audit: every claim below was checked by running the thing it
describes, not recalled. Audit corrections are recorded in `docs/implementation-progress.md`
("Full audit") and in this repository's history.

## Bottom line

**Batches A and B are complete. Batch C is three-quarters done.** The kit works: it validates
records, derives the expected checks before anything runs, blocks on missing, stale, wrong-identity,
empty-scope, and fixture-origin evidence, and produces honest reports. The reference application is
real, runs on a real Supabase stack, and its authorization boundary is proven in a database, in a
browser, and with a mutation test that shows the assertions can actually fail.

**Nothing is deployed and nothing is published.** The remaining work is Step 13's platform half
(waiting on the throwaway GitHub account the owner is creating at the end), Steps 15–16, and a short
list of open findings below.

## Verified state, by step

| Step | State | Evidence, and what is not covered |
| --- | --- | --- |
| 00 Build decisions | ✅ verified | Preflight, Node LTS recheck, dependency identities and licences, trust model |
| 01 Minimal repository | ✅ verified | `pnpm install --frozen-lockfile` builds the CLI; the acceptance check blocked in Batch A is now done |
| 02 Schemas and input loading | ✅ verified | 14 schemas; RFC 8785 tested against the RFC's own vectors; duplicate keys, traversal, and oversized input rejected |
| 03 35 controls, two profiles | ✅ verified | All 35 `owner_reviewed` with 35 approval records against content digests |
| 04 Planning and decision engine | ✅ verified | 85 gate and failure-mode tests; a pure evaluator with an injected clock |
| 05 CLI and report | ✅ verified | 0/1/2 exit codes demonstrated; reports and gate share one evaluation |
| 06 Tool execution and dependency policy | ✅ verified | Release-age delay and install-script default-deny proven against pnpm; digests checked before every run |
| 07 Reference application | ✅ verified except one criterion | 7 browser tests; **the "bind dev services to local interfaces" criterion is not met** (open finding 1) |
| 08 Authorization verification | ✅ verified except two cases | 14 API cases + 4 inventory checks, denial verified against stored state, **detection proven** on a weakened policy. Recovery isolation and genuine session expiry are untested |
| 09 Scanner adapters | ✅ verified | Four tools pinned and digest-verified; real detections: Gitleaks 3/0, zizmor 4/0, OSV advisories, Opengrep 3/0 |
| 10 Build and client secrets | ✅ verified except thresholds | Leak fixture detected, real build clean; **QUAL-01 thresholds are unconfigured** (open finding 3) |
| 11 Live recipes | ✅ verified | Approved-target inventory, HTTP requirements asserted, TLS blocked by design, ZAP baseline pinned and run |
| 12 Agent guidance | ✅ verified for opencode | Single rules source generating both formats, merge protection, review manifest, change report; Claude Code and Codex compatibility is recorded as unchecked |
| 13 GitHub workflows | 🟡 local half done | Workflows, trust tests, and `docs/ci-trust.md` complete; **platform verification awaits the owner's test account** |
| 14 Manual evidence and operations | ✅ verified, hosted evidence pending | Per-control intervals, scope-bound reuse, profile `never` enforced, restore drill passing, four runbooks |
| 15 Independent adoption | ⬜ not started | — |
| 16 Maintenance and release verification | ⬜ not started | — |

## Checks that ran in this audit

| Check | Result |
| --- | --- |
| `typecheck` / `build` / `lint` | 0 errors / succeeds / clean |
| Unit tests | **465 passing, 24 files** |
| Integration tests | **8 passing** |
| Scanner adapter suite (real pinned tools) | **15 passing** |
| Live HTTP suite | **17 passing** |
| Client-asset suite | **12 passing** |
| Example application build | `next build` succeeds |
| Browser suite (Playwright, production build, no retries) | **7 passing** (last run; needs the stack) |
| Authorization matrix (real API) | **14 cases + 4 inventory checks, 0 failures** |
| Weak-policy detection proof | Detection confirmed, then correctness re-confirmed |
| Restore drill | **PASS** — backup, loss, restore, per-owner distribution verified |
| CLI `validate` / `approvals` / release `gate` | passes / 35 approved / **blocks with 55 reasons** |
| Scanner registry | 4 tools resolve with digests matching; testssl refused; ZAP `container_executed` |
| Generated artifacts | current; regeneration produces no diff |
| Self-scan: zizmor | 0 findings |
| Self-scan: gitleaks (committed content and history) | **0 findings** |
| Unfinished-work markers in engineered files | none |

**Two audit findings, both fixed.** The product secret scan had been scoped with `dir`, so it scanned
build output, the gitignored `.env.local`, and the build fixture that deliberately holds a publishable
key — 14 findings nobody could act on. The product scan is now `gitleaks git` (committed content and
history) with the build fixture in the reviewed exclusions; re-run is 0 findings while adapter
verification still detects every fixture. Separately, `gitleaks dir` accepts only one path; passing
several silently scanned the whole tree and produced the misleading counts in the first place.

## Open findings

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 1 | **Development services are reachable beyond loopback.** The firewall is enabled with stealth mode, but the colima VM reaches the forwarded ports and no loopback-only switch exists in the versions tested | Medium, contained by practice | Open. The stack runs only while testing and is stopped afterwards. Closing it hard needs an explicit firewall block plus possibly a `pf` rule |
| 2 | **Six ZAP warnings on the reference application**: missing CSP (4 instances), absent anti-CSRF tokens, missing COEP/COOP/CORP headers, `X-Powered-By` disclosure | Medium | Open, recorded. A CSP needs script nonces; the CSRF result reflects Server Actions, which is a design fact to assess |
| 3 | **QUAL-01 quality thresholds unconfigured** for the example | Low | Open. `next build` type-checks and the root lint checks hygiene; no linter or duplication threshold exists |
| 4 | **Recovery isolation (AUTH-02) and genuine session expiry untested**; only a malformed token is covered | Medium | Open. Recovery needs the email flow |
| 5 | **OPS-03 has no security contact**, so there is no vulnerability report channel | High for a public repository | Blocked on `security_contact_email` |
| 6 | **The two callable workflows contain `REPLACE_WITH_HARDENING_REPOSITORY`** and are not runnable as shipped | Low | Blocked on `repo_name` and `github_owner` |
| 7 | **`LICENSE` absent.** `code_licence`, `docs_licence`, and `owner_legal_name` are unfilled | Blocker for publication | Blocked on owner decisions |
| 8 | **Deeper TLS assessment is manual.** `testssl.sh` is unpinned; Node's TLS validation covers chain and expiry only | Medium | Open by design; a production release blocks without TLS evidence |
| 9 | **The history-rewrite backup remains in the temp directory** | Housekeeping | Owner may delete `/var/folders/.../T/opencode/git-backup-prehistory-20261008024854` |

## Owner decisions outstanding

| Field | Blocks | Note |
| --- | --- | --- |
| `security_contact_email` | `SECURITY.md`, OPS-03, public visibility | Highest priority of the unfilled fields |
| `owner_legal_name` | `LICENSE`, `NOTICE`, release artifacts | Recommended to be the same as `github_owner` unless a company holds the copyright |
| `code_licence`, `docs_licence` | `LICENSE`, publication | Apache-2.0 or MIT; CC-BY-4.0 or same-as-code |
| `repo_name` | Package name, the two callable workflows, distribution | |
| `owner_handle` | README attribution, CODEOWNERS display | |
| `build_os` | Support statements, Step 16 readiness | |
| `github_test_owner`, `github_test_repos` | Step 13 platform verification | **Deferred by the owner to the final step** |

## What is genuinely finished versus running

- **Finished and verified:** the kit, the rules and profiles, the gate, the CLI, tool pinning,
  scanners, the reference application, its authorization evidence, build and client-secret checking,
  live HTTP checks, the ZAP baseline, agent guidance, the manual-evidence rules, and the runbooks.
- **Finished but unverifiable here:** Step 13's platform behaviour. Required checks, CODEOWNERS
  resolution, fork pull requests, and merge queues are unverified until the test environment exists.
  `docs/ci-trust.md` states this and lists the settings.
- **Not started:** Steps 15 (independent consumer adoption) and 16 (maintenance, scheduled checks,
  release notes, readiness summaries).
- **Pending by nature:** hosted operational evidence for OPS-01/02/03, SEC-03, and PRIV-01. These
  cannot pass until a person performs the runbooks and records it. The records stay `pending`, which
  is the correct state and not a defect.

## Honest limits of the whole build

- **No independent review.** Every control approval in this repository is self-review by a sole
  maintainer, recorded as such. The design assumes an independent human checkpoint at each batch and
  that has not happened.
- **No platform enforcement.** Adding workflows does not create required checks. A maintainer who can
  replace workflows or policy, or bypass protections, can defeat the gate.
- **Coverage is bounded by what was exercised:** one reference stack, four scanners, a local stack, no
  deployment. Features outside the profile (payments, uploads, tenancy, runtime AI) are declared
  exclusions with visible gaps, not silent passes.
- **Scanner claims are narrow:** Opengrep is syntactic, OSV covers known advisories only, ZAP is
  passive baseline only, and none of them is an authorization proof.
- **The example's own approval status:** its assessments are fixtures; no claim is made that the
  example application is production-ready. Kit readiness and application readiness are reported
  separately, and the application readiness is `pending` because no deployment exists.

## Proposed next steps, in order

1. **Batch D, Step 15** — prove an independent consumer can adopt the kit: pack or check out the
   reviewed commit, adopt into a separate repository, run the documented sequence, and verify that
   every advertised command works without hidden master-workspace dependencies. This is the most
   valuable remaining step because it tests the kit the way an adopter will use it.
2. **Step 16** — updater configuration, scheduled advisory and expiry checks, maintenance checklist,
   release notes, and the two readiness summaries at `first_release_version` 0.1.0.
3. **Step 13 platform half** — once the owner provides the throwaway account and token.
4. **Address open findings 1–4 and 8** as capacity allows; findings 5–7 need owner decisions first.
