# Implementation progress

Single append-only record for the hardening repository build. Updated at the end of every step.
States: `not_started` | `in_progress` | `verified` | `blocked` | `awaiting_external_verification`.

`verified` is used only when the step's stated acceptance checks actually ran and passed.
Authority for this batch: `authorised_batch: A` (Steps 00–05) in `01-owner-decisions.md`.

## Repository location

The build pack (`00-KICKOFF-PROMPT.md`, `01-owner-decisions.md`, `02-implementation-plan.md`,
`03-blueprint.md`, pack `README.md`) lives one directory above this repository. The repository root
is `Security Hardening/hardening/`. The pack was left in place and not modified; the pack's own
`README.md` would otherwise collide with this repository's `README.md`.

- Layout decision recorded in Step 00. `repo_name` is still `TODO`, so the directory name is a
  placeholder. Rename before any publication step.

---

## Step 00 — Establish the build decisions

- **State:** `verified` with recorded blockers (see Blockers below and the four documents).
- **Files changed:** `docs/implementation-progress.md`, `docs/architecture.md`,
  `docs/supported-versions.md`, `docs/trust-model.md`, `policy/toolchain.yaml`, `CHANGELOG.md`.
- **Actual checks run:** see "Preflight" below. All commands are recorded with their observed output.

### Preflight (kickoff prompt section 4)

Recorded 2026-10-06 from the build host.

| Item | Observed | Source of truth |
| --- | --- | --- |
| Operating system | macOS 26.3.1, build 25D771280a, Darwin 25.3.0, `x86_64` | `sw_vers`, `uname -a` |
| Shell | `/bin/zsh`, zsh 5.9 (x86_64-apple-darwin25.0) | `echo $SHELL`, `zsh --version` |
| Git | 2.55.0 | `git --version` |
| Git repo state | The build folder was **not** a Git repository and had no uncommitted work to preserve | `git rev-parse --is-inside-work-tree` → `fatal: not a git repository` |
| Node present | `v25.8.2` at `/usr/local/node` (via `/usr/local/bin/node`), npm `11.11.1` | `node --version`, `npm --version` |
| Node version managers | none present (`~/.nvm`, `~/.fnm`, `~/.volta` all absent) | `ls -d ~/.nvm ~/.fnm ~/.volta` |
| Corepack | **not bundled** in Node 25 (`process.versions.corepack === undefined`), so `corepack enable pnpm` is unavailable on this host | `node -e "process.versions.corepack"` |
| pnpm | **not installed** | `command -v pnpm` → not found |
| Docker | CLI 29.6.2 installed at `/usr/local/bin/docker`, but the **daemon is not running**: `failed to connect to the docker API at unix:///Users/dd/.docker/run/docker.sock ... No such file or directory` | `docker info --format '{{.ServerVersion}}'` |
| npm registry | reachable; `npm view ajv version` → `8.20.0` | `npm view` |
| github.com | reachable, HTTP 200 | `curl -o /dev/null -w '%{http_code}'` |
| nodejs.org | reachable, HTTP 200 for `/dist/index.json` | `curl` |

Docker being unavailable does not block Batch A. It is required from Step 07 (local Supabase) and
Step 11 (ZAP), both in later batches. Recorded here so those steps start from a known state.

### Node LTS status (rechecked against official sources)

Sources: `https://nodejs.org/dist/index.json` and the Node.js release schedule
(`https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`).

| Line | Newest patch | LTS codename | LTS since | Maintenance | End of life |
| --- | --- | --- | --- | --- | --- |
| v26 | v26.10.0 | not yet in LTS | — | — | 2029-04-30 |
| v25 | v25.9.0 | current (odd line, never LTS) | — | — | — |
| **v24** | **v24.21.0** | **Krypton** | **2025-10-28** | 2026-10-20 | **2028-04-30** |
| v22 | v22.23.3 | Jod | 2024-10-29 | 2025-10-21 | 2027-04-30 |

**Decision: keep Node 24 LTS.** `node_major: 24` in `01-owner-decisions.md` matches the only
currently active LTS line that has not entered maintenance-only status. Node 26 does not enter LTS
until 2026-10-28, so switching now would move to a non-LTS line. No switch recorded. Pinned tested
target is **Node 24.21.0**; the host actually running the build is Node 25.8.2 (see Blockers).

### Tool and package identities verified

Registry metadata read with `npm view <pkg> version license engines` on 2026-10-06. Exact pins are
in `policy/toolchain.yaml`; licences are recorded per component in `docs/supported-versions.md`.

| Package | Verified version | Licence | Notes |
| --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | Ships `Ajv2020` for JSON Schema draft 2020-12 |
| `ajv-formats` | 3.0.1 | MIT | Format validation for Ajv |
| `yaml` | 2.9.1 | ISC | `engines: node >= 14.6`; supports unique-key and tag/alias control |
| `typescript` | 7.0.2 | Apache-2.0 | `engines: node >=16.20.0` |
| `vitest` | 5.0.3 | MIT | `engines: ^22.12.0 \|\| ^24.0.0 \|\| >=26.0.0` |
| `@types/node` | 26.6.4 | MIT | — |
| `pnpm` | 12.9.1 | MIT | pinned as the project package manager; not installed on this host |

Integrity verification method used for v1: the package manager verifies the registry-published
`dist.integrity` (sha512) on install, and the lockfile records the resolved integrity for each
package. Per-package digest pinning of every transitive dependency is Step 06 work
(`policy/dependency-policy.yaml`), not Step 00.

**Recorded toolchain conflict:** `vitest@5.0.3` declares engines `^22.12.0 || ^24.0.0 || >=26.0.0`,
which **excludes the Node 25.8.2 runtime installed on this host**. Node 24.21.0 is inside the
supported range. Installing Node 24 on this machine requires `agent_may_install_runtimes`, which is
`TODO`. See Blockers.

**Not selected for v1:** no CLI argument-parsing library (Node's `node:util` `parseArgs` is used),
no canonical-JSON library (RFC 8785 is implemented in `src/evidence/canonical.ts` and tested against
the RFC test vectors), no schema-generation or policy-language dependency.

### Deferred tool selections (recorded, verified when their step begins)

These are needed in later batches only. Versions are recorded as *planned* and are **not** treated
as verified selections: Gitleaks, Opengrep, OSV-Scanner, zizmor (Step 09), Supabase CLI and Playwright
(Step 07), ZAP baseline image and testssl.sh (Step 11), GitHub Actions (Step 13).

### Trust boundary recorded

`docs/trust-model.md` separates: (a) operations that only read files and compute digests, and
(b) operations that execute untrusted application code or external binaries. A separate directory
and an environment-variable allowlist are explicitly **not** a sandbox, and are not described as one
anywhere in this repository.

### Decisions taken under the plan's defaults

1. Single core package, no workspace split, no second implementation under top-level `tools/`.
2. Repository root is `Security Hardening/hardening/` (pack files preserved unmodified).
3. Node 24.21.0 / pnpm 12.9.1 are the pinned toolchain targets.
4. `LICENSE` is **absent**, per plan Step 00 task 6, because `code_licence` and `docs_licence` are
   still `TODO`. This is a recorded blocker, not an oversight.
5. No git remote was configured and nothing was pushed. `agent_may_commit_locally: true` was used
   for local commits only.

- **Control coverage added:** none directly; this step fixes the toolchain and scope that later
  steps implement.
- **Limitations and unresolved findings:** no scanner has been integrated or run; no application
  exists; no external verification performed. `toolchain.yaml` lists later-batch tools as planned,
  not verified.
- **Owner decisions or external setup still needed:** all 15 `TODO` fields listed under Blockers.
- **Next step:** Step 01.

---

## Blockers

A blocker stops only the work that depends on it. Nothing here is worked around silently.

### Owner-decision blockers (from `01-owner-decisions.md`)

| # | Field | Value | Blocks | What the owner must do |
| --- | --- | --- | --- | --- |
| B1 | `owner_legal_name` | `TODO` | Step 00 (`NOTICE`), Step 01 (`LICENSE`), Step 16 (release artifacts) | Provide the legal name for copyright and notice lines |
| B2 | `owner_handle` | `TODO` | Step 01 (`README`), Step 13 (`CODEOWNERS`) | Provide the public handle/display name |
| B3 | `security_contact_email` | `TODO` | Step 01 (`SECURITY.md`), Step 14 (OPS-03 triage) | Provide a vulnerability-reporting address, ideally dedicated |
| B4 | `code_licence` | `TODO` | Step 01 (`LICENSE`), Step 16 (publication) | Choose `Apache-2.0` or `MIT` |
| B5 | `docs_licence` | `TODO` | Step 01 (docs licence statement), Step 16 | Choose `CC-BY-4.0` or `same-as-code` |
| B6 | `repo_name` | `TODO` | Step 01 (package name), Step 15 (consumer adoption), Step 16 (distribution) | Provide the lowercase hyphenated name |
| B7 | `repo_visibility` | `TODO` | Step 16 (publication) | Decide `public` or `private` |
| B8 | `github_owner` | `TODO` | Step 13 (`CODEOWNERS`, workflows), Step 16 | Provide the owning account or organisation |
| B9 | `github_test_owner` | `TODO` | Step 13 platform verification (Batch C) | Create a throwaway account/organisation and name it |
| B10 | `github_test_repos` | `TODO` | Step 13 platform verification (Batch C) | Name the disposable test repositories |
| B11 | `build_os` | `TODO` | Support statements in `docs/supported-versions.md`, Step 16 readiness | State the intended build/CI operating system |
| B12 | `docker_available` | `TODO` | Step 07 (local Supabase), Step 11 (ZAP) — Batch B/C | Confirm Docker works on the build host (observed: CLI present, **daemon not running**) |
| B13 | `network_access_to_registries` | `TODO` | Step 06 provisioning, Step 09 tool downloads | Confirm whether provisioning may reach registries; observed reachable, but the permission decision is unfilled |
| B14 | `agent_may_install_runtimes` | `TODO` | Step 01 clean-install acceptance, Step 06 pnpm policy test, Step 09 tool install | Grant or deny installing Node 24 and pnpm on this machine |
| B15 | `coding_tool` | `TODO` | Step 12 (which agent instruction formats are generated and verified) | Name the coding tool(s) in use |

### Environment blockers observed, not owner decisions

| # | Blocker | Evidence | Effect | Handling |
| --- | --- | --- | --- | --- |
| E1 | pnpm 12.9.1 not installed and may not be installed (B14) | `command -v pnpm` → not found; corepack not bundled in Node 25 | Step 01 "clean install with the pinned package manager builds the CLI" cannot be executed | Dependency graph built and verified with npm in `--no-package-lock` mode; **no npm lockfile is committed**; pnpm acceptance left explicitly unverified |
| E2 | Host runtime is Node 25.8.2, outside the supported Node 24 line, and excluded by `vitest@5` engines | `node --version`, `npm view vitest engines` | Checks run on an unsupported host runtime | All results recorded as "verified on Node 25.8.2; re-verification on Node 24.21.0 required". `engines` in `package.json` restricts to `>=24 <25` so the mismatch fails loudly rather than silently |
| E3 | Docker daemon not running | `docker info` failure text | Steps 07 and 11 (later batches) | Not in Batch A; recorded for Batch B |

---

## Progress log

### Step 01 — Create the minimal repository

- **State:** see the entry added at the end of the step.

### Step 02 — Schemas and safe input loading

- **State:** `not_started`.

### Step 03 — Author the 35 controls and two profiles

- **State:** `not_started`.

### Step 04 — Planning and the decision engine

- **State:** `not_started`.

### Step 05 — First working CLI and report

- **State:** `not_started`.
