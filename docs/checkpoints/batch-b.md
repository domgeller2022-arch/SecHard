# Batch B checkpoint

Steps 06–10. Generated 2026-10-07 (superseding the partial checkpoint of the same batch). Authorised
batch at the time of completion: **B** (returned from C once the container runtime existed, so the
blocked Steps 07, 08, and 10 could be finished).

**This batch is complete.** Every step reached a verifiable end state; the limitations listed below
are recorded rather than left implied.

## Status

| Step | State | Summary |
| --- | --- | --- |
| 06 — Control dependency and tool execution | `verified` | Release-age enforcement and install-script default-deny verified against pnpm 12.9.1; bounded process execution with digests checked before every run; provisioning separated from checking. |
| 07 — Secure local reference app | `verified` | Next.js application with cookie-based SSR sessions, Server Actions, and RLS migrations; 7 Playwright tests against a production build. One criterion — binding dev services to local interfaces — remains **open** (below). |
| 08 — Authorization and session verification | `verified` | 14-case machine-readable matrix against the unprivileged data API, denials verified against stored state, inventory checks, and **detection proven** on a weakened policy. |
| 09 — Scanner adapters | `verified` | Four tools pinned and digest-verified, with real positive detections and clean fixed fixtures for each. App-integrated scan deferred with Step 08's matrix covering the boundary directly. |
| 10 — Build verification and client secret boundary | `verified` | Browser output inspected; leaking and clean fixtures prove detection; the real build is clean and contains no Supabase key at all. |

## What now works

```bash
cd "/Users/dd/Desktop/Security Hardening/hardening"
export PATH="$HOME/.local/opt/node-v24.21.0/bin:/usr/local/bin:$PATH"

# The kit
pnpm install --frozen-lockfile && pnpm run build
pnpm run typecheck && pnpm run lint
pnpm test && pnpm run test:integration          # 440 unit + 8 integration
pnpm run fetch:tools                            # digest-verified scanners
node dist/cli.js validate --app tests/fixtures/consumer --policy .
node dist/cli.js approvals --policy .           # the 35 recorded approvals
node tools/review-changes.mjs <base> [head]     # security-test change report
pnpm run generate:agent-rules                   # AGENTS.md + CLAUDE.md from one source
pnpm run inspect:build                          # build evidence + client-asset inspection

# The reference application (the local stack must be running)
cd examples/nextjs-supabase
pnpm exec supabase start
pnpm run env:sync
pnpm run build && pnpm run test:e2e             # 7 browser tests, no retries
pnpm run test:authorization                     # 14 API cases + 4 inventory checks
pnpm run test:authorization:weakened            # proves the matrix detects a weakened policy
pnpm exec supabase stop                         # do this when finished
```

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` / `pnpm run test:integration` | **440 unit + 8 integration tests pass** on Node 24.21.0 |
| `pnpm exec playwright test` | **7 browser tests pass** against `next start`, one worker, no retries |
| `pnpm run test:authorization` | **14 cases, 0 failures**, plus 4 inventory checks |
| `pnpm run test:authorization:weakened` | Detection proven on a permissive policy; correctness re-proven after reset |
| `node tools/inspect-build.mjs` | 11 files, 575 574 bytes, digest `8037be58…`, 0 findings, 0 source maps |
| `npx vitest run tests/scanners` | Real detections: Gitleaks 3/0, zizmor 4/0, OSV advisories, Opengrep 3/0 |
| zizmor over this repository's workflows | 0 findings (after fixing 3 template-injection issues it found) |
| `gitleaks git .` over full history | **0 findings** after the authorised history rewrite |

Failures encountered and fixed during the batch — recorded because a checkpoint that lists only
successes hides the useful part: three template-injection findings in my own workflows; archive
digests recorded where executable digests were required; a raw report retained in an adapter outcome
that could have carried a secret; four synthetic tokens committed as literals in tests (found by the
first real scan of this repository); two comparison bugs in my own authorization runner; and a
percent-encoded path.

## Controls

**35 controls, all `owner_reviewed`, 35 approval records.** A release gate reports **0** approval
reasons (it previously reported one per applicable control) and still blocks on genuine gaps.

This batch exercised: DEP-01, DEP-02, DEP-03 (advisory scan), SEC-01 (repository and history),
SEC-02 (client assets), CI-02, CI-03, CODE-01, QUAL-01 (partially — see limitations), AUTH-01
(partially), AUTHZ-01, AUTHZ-03, DATA-01, WEB-01 (negative inputs via the matrix), ABUSE-01
(partially), REL-01 (build evidence), REL-02 (database-level), EXC-01, AGT-03, GOV-02, CTX-01.

No control acceptance criterion was weakened. Two expectations were **corrected to match verified,
stronger behaviour**: anonymous access is refused at the grant layer (`42501`) rather than shown an
empty result, and the browser bundle contains no Supabase key at all because all access is
server-side.

## Deviations from the plan

| Deviation | Reason |
| --- | --- |
| Steps 12 and 13 (Batch C) partly completed first | Batch B was blocked on the container runtime; Step 12's stated dependencies (Steps 03–06) were satisfied, and the plan requires continuing with work that does not depend on the missing item. |
| colima/lima instead of Docker Desktop | Docker Desktop is proprietary and carries a licence decision belonging to the owner. colima is a Docker-compatible open-source runtime. |
| Scanner tools downloaded to `tools/bin/` (gitignored) rather than a container or system install | Keeps the pinned digests authoritative, avoids modifying the machine, and lets the registry verify the binary before each run. |
| The authorization matrix runs against the data API rather than only through the UI | The interface is one caller among many; the provider boundary is what every path depends on. The UI path is covered by the Playwright suite. |
| The example is a workspace package | So the reviewed dependency policy, including the release-age delay, applies to it as it does to the core. |

## Blockers and owner actions

| # | Item | Affects | Owner action |
| --- | --- | --- | --- |
| 1 | **Binding finding is open**: the local stack is reachable from the VM network and could not be verifiably contained; `limactl` has no explicit firewall block and is ad-hoc signed | Step 07's binding criterion; Step 11's assumptions | Either add the explicit block (`--add` then `--blockapp`) and accept that the VM path may remain unfiltered, or record local-network trust as an accepted risk |
| 2 | GitHub test environment deferred to the final step | Step 13 platform verification | Create the throwaway account and repositories at the end, as agreed |
| 3 | QUAL-01 thresholds not configured | Step 10's "configured quality thresholds" | Decide whether to add a linter and calibrated thresholds for the example |
| 4 | `owner_legal_name` still unfilled | Licence, NOTICE, release artifacts | Provide it before publication |
| 5 | History-rewrite backup left outside the repository | Housekeeping | Delete `/var/folders/.../T/opencode/git-backup-prehistory-20261008024854` when satisfied |

## Owner review list

| File / section | What to look for |
| --- | --- |
| `src/execution/process.ts`, `registry.ts` | The only place a process starts, and the digest check that precedes every run |
| `policy/dependency-policy.yaml`, `pnpm-workspace.yaml` | The seven-day delay, the empty install-hook allowlist, and the settings that were actually verified |
| `examples/nextjs-supabase/supabase/migrations/` | `owner_id` defaulting to `auth.uid()`, `force row level security`, and grants revoked from `anon` |
| `tests/authorization/matrix.yaml`, `run-authorization.mjs` | That the cases are the ones you care about, and that denials are checked against stored state |
| `tests/authorization/weakened-detection.sh` | That the detection proof would fail if the assertions were weak |
| `src/build/client-assets.ts`, `tests/build/client-assets.test.ts` | That classification versus finding is right, and that coverage is stated honestly |
| `tools/inspect-build.mjs` | Source-change detection and the separation of quality from security |
| `docs/implementation-progress.md` | The per-step account, including every failure found |

## Known limitations and risks

- **The binding finding is open.** Development services are reachable beyond loopback; the operating
  rule is to run the stack only while testing and stop it afterwards.
- **Recovery isolation (AUTH-02) is untested**; it needs the email flow and belongs with Step 14.
- **Genuine session expiry is untested**; only a malformed token is.
- **QUAL-01 thresholds are unconfigured.**
- **No live HTTP, TLS, or ZAP coverage yet** — Step 11, which needs a target; the manifest currently
  declares hosting disabled, so production evidence is not applicable to this example.
- **Scanner coverage is syntactic** (Opengrep) and advisory-only (OSV); neither establishes runtime
  behaviour.
- **No independent review.** Every approval in this repository is self-review by a sole maintainer,
  recorded as such.
- **No platform verification**: required checks, CODEOWNERS resolution, forks, and merge queues are
  unverified until the test environment exists.

## Proposed next batch

**Batch C remainder, then D.** In order:

1. **Step 11** — guarded live recipes: route-appropriate HTTP checks, separate TLS verification, and
   a guarded passive ZAP adapter with bounded crawling. Needs an explicit approved target inventory;
   for the local example that means `http://127.0.0.1` staging routes, with production evidence
   correctly blocked because hosting is disabled.
2. **Step 12 remainder** — complete the tool-compatibility record for Claude Code and Codex alongside
   opencode; optionally add QUAL-01 thresholds.
3. **Step 13 platform half** — real pull requests, forks, and queue behaviour once the owner supplies
   the test environment.
4. **Step 14** — manual evidence intervals, restore and response exercises, credential lifecycle.

**What the owner must prepare:** nothing blocks local work. The GitHub test environment is needed for
Step 13's platform half and has been deferred to the final step by agreement.
