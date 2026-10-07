# Batch C checkpoint (partial)

Steps 11–14. Generated 2026-10-06. Authorised batch: **C**.

**This batch is not complete, and it cannot be on this machine.** Batch C was authorised on the
owner's instruction after Batch B reached its environmental limit. Step 12 and the local half of
Step 13 were executable; Steps 11 and 14 are blocked behind the container runtime and the reference
application, and Step 13's platform half needs a GitHub test environment that does not exist.

## Status

| Step | State | Reason |
| --- | --- | --- |
| 11 — Guarded live application recipes | `blocked` | Depends on Step 10, which needs the reference application. HTTP recipes need a running target, TLS needs a deployed host, and the guarded passive ZAP adapter needs Docker. Nothing was stubbed in their place. |
| 12 — Generate and protect agent guidance | `verified` | 15-rule source generating `AGENTS.md`/`CLAUDE.md` deterministically with merge protection; review manifest; security-test change report; operator requirements document; 33 tests. Tool-compatibility check `blocked` on `coding_tool` being unfilled. |
| 13 — GitHub workflows and the trusted final gate | `awaiting_external_verification` | Workflows, trust tests, and documentation are implemented and locally verified, including a real zizmor run. **No platform behaviour has been observed**: `github_test_owner` and `github_test_repos` are unfilled and no token is available. `.github/CODEOWNERS` is deliberately absent. |
| 14 — Manual evidence and operational recipes | `blocked` | Depends on Steps 10–13 for the operational half; its record structures and validation exist from Steps 02–04, but the disposable restore/rollback exercises need the reference application and a database. |

## What now works

```bash
cd "/Users/dd/Desktop/Security Hardening/hardening"

# Agent guidance from the single reviewed source.
pnpm run generate:agent-rules      # writes agent-rules/generated/{AGENTS.md,CLAUDE.md}
node tools/review-changes.mjs <base> [head]   # security-test and sensitive-path change report

# The workflows that will run in CI, inspected locally.
npx vitest run tests/workflows     # 23 trust tests, including a real zizmor run
./tools/bin/zizmor/v1.30.1/zizmor .github/workflows
```

What the local checks actually establish: every action is pinned to a full commit SHA; no workflow
grants a write permission; nothing interpolates an expression into a shell script; `pull_request_target`
is unused; every checkout disables credential persistence; and every workflow has a
`hardening-gate` job that depends on all other jobs and runs `if: always()`, failing unless each
dependency result is exactly `success`.

## Checks actually run

| Command | Outcome | Notes |
| --- | --- | --- |
| `npx vitest run tests/agent` | **33 tests pass** | Generation determinism, merge protection, permissive-wording denylist, manifest validation, change report against a real temporary git repository |
| `npx vitest run tests/workflows` | **23 tests pass** | Includes a real zizmor run over the pinned workflows |
| `pnpm test` / `pnpm run test:integration` | **413 unit + 8 integration, all pass** | On Node 24.21.0 with pnpm 12.9.1 |
| zizmor over `.github/workflows` | **3 high findings → 0 after fix** | `template-injection`: `${{ }}` written into `run:` scripts; values moved to `env:` |
| `node tools/review-changes.mjs 8ea01a0 c914316` | exit 1 with a full report | Real range, real findings across tests, policy, scanner configs, and lockfiles |
| Action pins resolved via GitHub API | Real SHAs | `actions/checkout@v7.0.1`, `pnpm/action-setup@v6.1.0`, `actions/setup-node@v7.0.0`, `actions/upload-artifact@v4.6.2` |

Defects found and fixed in this batch: the rules generator assumed its output directory existed; the
review manifest referenced a control I invented (`AGT-CTX-01`), caught by its own validation; the
mock-detection pattern missed `mockDatabase`-style helpers; the generated headers asserted tool
loading behaviour as fact and now state it as unverified; and the three template-injection findings.

## Controls

Unchanged in count: **35 controls, all `draft`, zero approvals.** This batch added capability under
AGT-01 (operator requirements), AGT-02 (rules for untrusted context), AGT-03 (security-test change
report), GOV-01 (sensitive-path manifest), CI-01/CI-02/CI-03 (workflows and the always-running gate),
and SEC-01 (scanner self-scan configuration).

## Deviations from the plan

| Deviation | Reason |
| --- | --- |
| Step 13 completed only in its local half | Platform verification needs a GitHub test environment the owner has not created. The plan anticipates this: "complete local work and mark platform verification `awaiting_external_verification`". |
| Step 12 executed before Step 11 | Step 11 is blocked behind Step 10 and the container runtime. Step 12's stated dependency is Steps 03–06, all complete, so it was the one step whose prerequisites were satisfied. Recorded in `01-owner-decisions.md`. |
| `.github/CODEOWNERS` not created | `github_codeowners` is unfilled. A file naming a display name matches nobody and GitHub skips invalid lines, so a fabricated file would look like protection while providing none. |
| Workflows pin Node 24.21.0 rather than a range | The supported runtime is one exact tested patch; a range would silently move the runtime under the checks. |

## Blockers and owner actions needed

| # | Blocker | Affects | What the owner must do |
| --- | --- | --- | --- |
| **E3 / B12** | **Docker is absent** — no binary, no app, no socket, no alternative runtime | Steps 07, 08, 10, 11, 14 | Install and start a container runtime and set `docker_available: true`. Nearly everything remaining is behind this. |
| **B9 / B10** | GitHub test environment unfilled | Step 13 platform verification | Create a throwaway organisation and repositories, fill `github_test_owner`/`github_test_repos`, and provide the token named by `github_test_token_env_var` when platform testing is authorised |
| **B15** | `coding_tool` is `TODO` | Step 12's compatibility check | Name the coding tool(s) so the generated files can be checked against their documented loading and precedence behaviour |
| **B8 / `github_codeowners`** | Owner identity unfilled | CODEOWNERS, required reviews | Provide real GitHub usernames or teams with write access |
| — | 35 control definitions are `draft`; zero approvals | Release evaluation | `node dist/cli.js approvals --policy .` prints the digests; record approvals in `controls/approvals.yaml` |
| — | One synthetic placeholder token remains in **git history** | Master repo history scan | Choose: rewrite the local history, or accept a narrow documented allowlist. Left visible deliberately |

## Owner review list

| File / section | What to look for |
| --- | --- |
| **`agent-rules/core/rules.yaml`** | The 15 rules. This is what every generated instruction file says, so this review is the substantive one. Check that nothing is missing and nothing is overstated. |
| **`agent-rules/generated/AGENTS.md`** and **`CLAUDE.md`** | That the generated wording is what you want an agent to read, and that the loading note is correctly labelled unverified. |
| **`agent-rules/review-manifest.yaml`** | Whether the paths listed are the right ones, and whether any entry's `requires` should be stronger. |
| **`agent-rules/operator-requirements.md`** | That the runtime restrictions are requirements you are prepared to enforce. A prompt is not a boundary; these are the actual controls. |
| **`src/agent/change-report.ts`** and **`tests/agent/change-report.test.ts`** | That the report notices what matters and does not imply it can judge intent. |
| **`.github/workflows/repo-checks.yaml`** | The `hardening-gate` job: it must fail when a dependency is skipped, cancelled, or failed. Check the shell logic rather than trusting the comment. |
| **`.github/workflows/hardening-pr.yaml`**, **`hardening-release.yaml`** | Permissions, the separate tooling checkout, and that a pull request cannot influence the tooling it is assessed by. |
| **`docs/ci-trust.md`** | The platform settings list and the trust limit. Confirm you agree with what is claimed and what is explicitly not claimed. |
| **`tests/workflows/trust.test.ts`** | That each assertion would actually fail if the property were removed. Try deleting a pin and confirm the suite notices. |
| **`docs/checkpoints/batch-c.md`** (this file) | Whether the status of each step matches your understanding. |

## Known limitations and risks

- **No platform verification at all.** Required checks, CODEOWNERS resolution, fork pull requests,
  bypass permissions, and merge queues are unverified. Do not read the green local suite as
  enforcement.
- **The trust limit is inherent.** A maintainer who can replace workflows or policy, or who can
  bypass checks, can defeat the gate. Documented, not fixed.
- **Steps 07–11 and 14 do not exist yet.** There is no reference application, no authorization test,
  no live HTTP or TLS check, no ZAP adapter, and no restore/rollback exercise.
- **The generated compliance of agent rules is unverified** for any specific tool: the loading and
  precedence behaviour is stated as an expectation, not a tested fact.
- **The change report is mechanical.** It notices removals and additions; it cannot tell whether a
  change was legitimate.
- **The master repository's own history** still contains one synthetic placeholder token, left
  visible by choice.
- **All 35 controls remain `draft`** with zero approvals, so release evaluation blocks on that in
  addition to any missing coverage.

## Proposed next batch

Nothing further can be done on this machine without the container runtime. When one is installed and
`docker_available: true`:

1. **Step 07** — the Next.js + Supabase reference app: sign-in/out, recovery, private notes with
   owner IDs and RLS migrations.
2. **Step 08** — the authorization matrix: anonymous, owner A, unrelated B, direct-provider access,
   denied writes verified against stored state, owner-field tampering, positive cases.
3. **Step 10** — production build, client-asset inspection, and the synthetic privileged-credential
   leak fixture.
4. **Step 11** — guarded live recipes: HTTP requirements, TLS, passive ZAP.
5. **Step 14** — manual evidence hardening: per-control intervals, restore and response exercises.
6. **Step 13 platform half** — real pull requests, forks, and queue behaviour, once the GitHub test
   environment and token exist.

**What the owner must prepare:** install a container runtime (the single largest unblocker); create
the GitHub test environment and fill B9/B10 when platform verification is wanted; fill `coding_tool`
to complete Step 12's compatibility check; fill `github_codeowners` before CODEOWNERS can exist;
decide the fate of the token in history; and approve the 35 control definitions when ready.
