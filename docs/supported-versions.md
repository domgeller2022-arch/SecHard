# Supported versions

Verified 2026-10-06. Every entry states how it was verified and what is still only planned.
Nothing here is verified because a document says so.

## Node.js

| Item | Value |
| --- | --- |
| Supported line | Node 24 LTS (codename Krypton) |
| Tested patch target | 24.21.0 |
| `engines` in `package.json` | `>=24 <25` |
| LTS start / maintenance / EOL | 2025-10-28 / 2026-10-20 / 2028-04-30 |
| Installed for verification | `~/.local/opt/node-v24.21.0/bin/node` |

Node 24.21.0 was installed on 2026-10-06 by downloading the official `darwin-x64` tarball and
verifying its SHA-256 against `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt`
(`1462cb3b3046b815cf8ea436d3da450ec1a9f11dac7e5a46b0ada5305d7e8097`). **All verification results for
this repository are now produced on the supported runtime.** The host also carries Node v25.8.2,
which is outside the supported line and is no longer used.

Verification: `https://nodejs.org/dist/index.json` and the Node.js release schedule at
`https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`, read 2026-10-06.

Node 26 exists but does not enter LTS until 2026-10-28, so it is not the supported line. When Node 26
becomes the active LTS, this file and `policy/toolchain.yaml` must be updated together.

**Host caveat resolved.** Earlier results were produced on Node 25.8.2, which is outside the
supported line. Node 24.21.0 is now installed and the full suite runs on it.

## Package manager

| Item | Value |
| --- | --- |
| Package manager | pnpm 12.9.1 (pinned via `packageManager` in `package.json`) |
| Install mode | frozen lockfile |
| Install-time minimum release age | **10080 minutes (7 days) — enforced and verified** |
| Settings location | `pnpm-workspace.yaml` (pnpm 12 does not read pnpm settings from `.npmrc`) |

Verification on 2026-10-06 with pnpm 12.9.1 installed on this host:

| Behaviour | Result |
| --- | --- |
| `minimumReleaseAge: 10080` | **Enforced.** `nanoid@6.0.2` (published 18.5h earlier) was refused with `ERR_PNPM_NO_MATURE_MATCHING_VERSION`, naming the publish time and cutoff, exit 1. Minutes are the unit. In `.npmrc` the same setting was silently ignored; it works in `pnpm-workspace.yaml`. |
| `allowBuilds: {}` | **Default deny.** An unapproved install script failed the install with `ERR_PNPM_IGNORED_BUILDS` and did not run (verified with `core-js@3.37.1` and a local tarball fixture). `pkg: true` ran the reviewed hook; `pkg: false` recorded a denial without running it. |
| `engineStrict: true` | Enforced: `ERR_PNPM_UNSUPPORTED_ENGINE` under Node 25, accepted under Node 24.21.0. `engine-strict` in `.npmrc` was ignored. |
| `saveExact: true` | Honoured: exact versions saved rather than caret ranges. |
| `strictPeerDependencies: true` | Honoured: the install failed when `vitest`'s peer `vite` was undeclared; `vite` was added explicitly rather than relaxing the setting. |
| Supply-chain lockfile check | `pnpm install --frozen-lockfile` reports "Lockfile passes supply-chain policies" by default. `--trust-lockfile` skips it and is not used. |

`ignore-scripts=true` in `.npmrc` is **ignored by pnpm** and is not the mechanism that blocks
dependency hooks. The real control is `allowBuilds` default-deny, which fails the install loudly.
`.npmrc` is retained only so a stray `npm install` behaves safely.

## Core dependencies

| Package | Pinned version | Licence | Verified how | Use |
| --- | --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | `npm view ajv version license` | JSON Schema draft 2020-12 validation via `Ajv2020` |
| `ajv-formats` | 3.0.1 | MIT | `npm view ajv-formats version license` | `format` keywords |
| `yaml` | 2.9.1 | ISC | `npm view yaml version license engines` | Bounded YAML parsing with duplicate-key and tag control |
| `typescript` | 7.0.2 | Apache-2.0 | `npm view typescript version license engines` | Strict type checking and build |
| `vitest` | 5.0.2 | MIT | `npm view vitest version license engines` | Test runner |
| `vite` | 8.3.1 | MIT | `npm view vite version license` | Vitest's peer, declared explicitly |
| `@types/node` | 24.19.0 | MIT | `npm view @types/node version license` | Node type definitions, matching the supported runtime |

**Two pins changed on 2026-10-06 when the release-age policy was first enforced against this
repository's own dependencies.** `vitest@5.0.3` and `@types/node@26.6.4` were younger than 7 days, so
the install was refused. Instead of adding a package-wide age exemption — which
`policy/dependency-policy.yaml` forbids — they were moved to the newest **mature** versions:
`vitest@5.0.2` and `@types/node@24.19.0`. The latter is also a better match for the Node 24 runtime.
`vite` was added because strict peer resolution requires the peer to be declared.

No CLI framework, no canonical-JSON library, and no policy-language dependency: Node's `parseArgs`
covers argument handling, and RFC 8785 canonicalization is implemented in-repo and tested against the
RFC's test vectors.

Integrity: the package manager verifies each package's registry-published `dist.integrity` (sha512)
at install time and the lockfile records it. Per-dependency digest pinning of the full transitive
graph is Step 06 (`policy/dependency-policy.yaml`).

## Supported platforms

| Platform | Status |
| --- | --- |
| Linux CI | The supported execution environment |
| macOS | Partial. The documented supported subset may be run locally, but support is claimed only after that subset has actually been run on macOS |

This build's host is macOS 26.3.1 (`x86_64`), so local results come from a platform that is not the
supported execution environment. They are useful feedback, not release evidence for Linux CI.

## Reference stack (planned)

Not selected yet. Selection and verification belong to Step 07.

| Component | Status |
| --- | --- |
| Next.js (App Router) | Planned — Step 07 |
| Supabase CLI, local development | Planned — Step 07, requires Docker |
| Playwright | Planned — Step 07 |
| Gitleaks | Planned — Step 09 |
| Opengrep | Planned — Step 09 |
| OSV-Scanner | Planned — Step 09 |
| zizmor | Planned — Step 09 |
| ZAP baseline image | Planned — Step 11, requires Docker |
| testssl.sh | Planned — Step 11 |

A planned entry is a selection intent only. Each becomes a verified version with a recorded source
URL, licence, immutable reference or digest, and integrity method when its step begins.

## Licence status of this repository

Unresolved. `code_licence` and `docs_licence` in `01-owner-decisions.md` are still `TODO`, so
`LICENSE` is deliberately absent. Copied or adapted upstream material keeps its own licence and
notice regardless of that setting; per-component licences for reused material are tracked
individually rather than covered by one repository-wide label.

## Standards references

Linked as `related_risk` unless a reviewed mapping says otherwise. A linked category is not a claim
of conformance. Exact requirement IDs are reviewed against the pinned source edition before
publication; unreviewed mappings stay visibly unverified rather than being invented.
