# Batch B checkpoint (partial)

Steps 06–10. Generated 2026-10-06. Authorised batch: **B**.

> **Update (same day, after owner grants).** The owner granted `agent_may_install_runtimes: true`
> and `network_access_to_registries: true`. **Step 06 is now verified in full** (environment blockers
> E1 and E2 resolved; Node 24.21.0 installed with a verified digest; pnpm 12.9.1 installed;
> `pnpm install --frozen-lockfile` builds the CLI), and **Step 09 is verified** (four scanners
> downloaded, digest-pinned, and run against real vulnerable and fixed fixtures).
> **Steps 07, 08, and 10 remain blocked** on the absent container runtime (E3), as does Step 09's
> app-integrated scan. The status table below is superseded by this paragraph; the blockers and
> owner actions remain accurate.

**This batch is not complete.** Step 06 was implemented and verified as far as this machine permits.
Steps 07–10 are blocked and were deliberately not started. The batch stops here per the kickoff
rule: continue with what does not depend on the missing items, and mark dependent work blocked.

## Status

| Step | State | Reason |
| --- | --- | --- |
| 06 — Control dependency and tool execution | **`verified` (complete)** | Execution layer, provisioning policy, digest-gated downloads, install-script policy, release-age enforcement, and pinned pnpm all verified on Node 24.21.0. E1 and E2 resolved. |
| 07 — Secure local reference app | `blocked` | Requires a container runtime for local Supabase. **Docker is absent** (E3), and `docker_available` is unfilled (**B12**). |
| 08 — Authorization and session verification | `blocked` | Depends on Step 07. There is no application and no database to test against. |
| 09 — Scanner adapters | **`verified`** (app-integrated scan `blocked`) | Four scanners pinned and digest-verified; real positive detections and clean fixed negatives for all four. The app-integrated scan needs Step 08. |
| 10 — Build and client-secret checks | `blocked` | Depends on Steps 08–09. There is no application and no build to inspect. |

## What now works

```bash
cd "/Users/dd/Desktop/Security Hardening/hardening"
npm run build

# The reviewed dependency and provisioning policy, validated on load.
node dist/cli.js validate --app tests/fixtures/consumer --policy .   # still passes

# Every scanner is refused, because no identity has been verified yet.
# (exercised by tests/execution/registry.test.ts)
npm test        # 345 tests, 17 files
```

Inside the library — and through the tests — the following are real, not illustrative:

- **Bounded process execution.** Arguments are arrays with no shell; the executable must be an
  absolute path; the environment is an allowlist; output is capped; a deadline terminates the child
  and its process group. The process tests spawn real children and verify the child never ran.
- **Reviewed-executable registry.** A tool runs only with an absolute path, a recorded version, and
  a digest verified against the binary on disk. Every scanner is currently refused as
  `identity_unverified` — the honest state.
- **Provisioning validated before execution.** Exact version, reviewed registry, release-age
  confirmation, reviewed install hooks, and download digests are checked first; a refused plan runs
  nothing.
- **Digest-gated downloads.** HTTPS-only, registry-matched, digest-verified, size-capped, and
  redirect-refusing, tested against a real local HTTP server.

## Checks actually run

| Command | Outcome | Where |
| --- | --- | --- |
| `npx vitest run tests/execution` | **65 tests, 5 files, pass** (real processes, real HTTP server, real digests) | session log |
| `npx vitest run` | **345 tests, 17 files, pass** | session log |
| `npx tsc --noEmit` | exit 0 | session log |
| `npm run build` | exit 0 | session log |
| `npm run lint` | exit 0 | session log |
| Dependency hook scan (53 installed package dirs) | 4 packages have hooks; **none is an install-time hook**; build and suite pass with `ignore-scripts=true` | session log; guarded by `tests/execution/install-policy.test.ts` |
| `docker` recheck | **absent** — symlink target removed, no socket, no alternative runtime | session log; E3 |
| `node dist/cli.js validate` | exit 0 — the Batch A consumer still validates | session log |

Failures found and fixed during the step: the registry ran the version check after the requested
arguments in the first draft (it now checks first); a download test asserted an insecure-origin case
that needed an explicit loopback exemption to be testable; the registry initially declared a
`reuse`-shaped policy field it never read, which was removed.

## Controls

Unchanged in count: **35 controls, all `draft`.** This batch added execution capability under
existing controls: DEP-01, DEP-02, CI-02, and the execution half of AGT-02.

## Deviations from the plan

| Deviation | Reason |
| --- | --- |
| Step 06 sub-items left blocked rather than worked around | pnpm is not installed (B14) and the registry permission is unfilled (B13). The policy explicitly blocks a provisioning plan while the release-age enforcement is unverified, instead of assuming it applied. |
| Scanner tools recorded as `identity: unverified` rather than pinned | Pinning requires downloading and verifying the tool, which needs B13. Recording an unverified identity and refusing to run it is the honest alternative to inventing a digest. |
| Steps 07–10 not started | No container runtime exists on this machine. A reference application that cannot start its database is not a reference application. |

## Blockers and owner actions needed

| # | Blocker | Affects | What the owner must do |
| --- | --- | --- | --- |
| **E3 / B12** | **Docker is absent** (not merely stopped; the app and socket are gone) | Steps 07–11 | Install Docker Desktop or an equivalent (`colima`, `podman`), start it, and set `docker_available: true`. Nothing in Batch B beyond Step 06 can proceed without this. |
| **B14** | `agent_may_install_runtimes` is `TODO`; pnpm is not installed | Step 06's release-age and install-script verification; the pinned-package-manager acceptance check from Step 01 | Grant or deny runtime installation. If granted, install Node 24.21.0 and pnpm 12.9.1, then the pnpm behaviour can be tested. |
| **B13** | `network_access_to_registries` is `TODO` | Step 06's live provisioning path; Step 09's scanner downloads | Confirm whether provisioning may reach registries, then a real tool can be downloaded, digested, and pinned. |
| B4/B5 | Licences unfilled | `LICENSE`/`NOTICE` | Choose `Apache-2.0` or `MIT`, and `CC-BY-4.0` or `same-as-code`. |
| — | 35 control definitions are `draft` | Release evaluation | Run `node dist/cli.js approvals --policy .` and record approvals. Release blocks without them. |

## Owner review list

| File / section | What to look for |
| --- | --- |
| **`src/execution/process.ts`** | The only place a process is started. Check the refusal on a non-absolute path, the allowlist environment, the output cap, and the SIGTERM→SIGKILL sequence that signals the process group. |
| **`tests/execution/process.test.ts`** | That the timeout test genuinely proves the child was killed: it waits past the point the marker file would have been written. That the malicious-argument tests use real shell metacharacters. |
| **`src/execution/registry.ts`**, `policy/toolchain.yaml` | That every scanner is `identity: unverified` and refused, and that a recorded digest is verified against the binary before execution. Confirm you agree that refusing to run is better than an unverified pin. |
| **`policy/dependency-policy.yaml`** | The 10080-minute delay, empty install-hook allowlist, exact-version exception rules, and the provisioning/application-execution separation. This file is authority. |
| **`src/execution/provision.ts`**, `tests/execution/policy.test.ts` | That a refused plan executes nothing, and that an expired or wildcard exception is rejected. |
| **`src/execution/download.ts`**, `tests/execution/download.test.ts` | Digest gating, HTTPS-only, redirect refusal, and size cap. Note the loopback exemption exists for tests and local mirrors. |
| **`tests/execution/install-policy.test.ts`** | The guard that fails if a future dependency adds a real install-time hook. This is the mechanism that stops the allowlist from silently growing. |
| **`docs/checkpoints/batch-b.md`** (this file) | Whether you agree the batch should stop here rather than scaffolding an application that cannot run. |

## Known limitations and risks

- **The release-age delay is configured, not verified.** The number is enforced in policy validation;
  the package manager that would enforce it at install time has not been tested.
- **The install-script guarantee is only as strong as our own toolchain today.** Verified: our
  dependency set needs no hook and builds with scripts disabled. Unverified: that pnpm keeps an
  unapproved hook disabled.
- **Four real tools are pinned and have been run** against fixtures; the app-integrated scan is not
  performed. **One synthetic placeholder token remains in git history** (see the progress record) and
  is deliberately left visible.
- **Nothing has been executed against an application**, because there is no application.
- **`application_execution` isolation is a policy statement**, not an enforced environment.
- **All 35 controls remain `draft`** with zero approvals, and no scanner coverage exists, so release
  evaluation blocks for multiple independent reasons.

## Proposed next batch

**Finish Step 07 first.** Once a container runtime is installed and `docker_available` is true:

1. **Step 07** — the Next.js + Supabase reference app: sign-in/out, recovery, private notes with
   owner IDs and RLS migrations, explicit feature declarations, and a minimal UI.
2. **Step 08** — the authorization matrix: anonymous, owner A, unrelated B, direct-provider access,
   denied writes verified against stored state, owner-field tampering, and positive cases.
3. **Step 09** — the four scanner adapters with real positive and negative fixtures, downloaded and
   digest-pinned tools (requires **B13**).
4. **Step 10** — production build, client-asset inspection, and a synthetic privileged-credential
   leak fixture.

**What the owner must prepare:** install and start a container runtime and set `docker_available:
true` (the only remaining environment blocker); optionally approve the 35 control definitions
(`node dist/cli.js approvals --policy .` prints the digests); and decide what to do about the one
synthetic placeholder token still present in this repository's **git history** (left visible rather
than allowlisted — either rewrite the local history or accept a narrow documented allowlist).
