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

Verification: `https://nodejs.org/dist/index.json` and the Node.js release schedule at
`https://raw.githubusercontent.com/nodejs/Release/main/schedule.json`, read 2026-10-06.

Node 26 exists but does not enter LTS until 2026-10-28, so it is not the supported line. When Node 26
becomes the active LTS, this file and `policy/toolchain.yaml` must be updated together.

**Host caveat:** the machine used for this build runs Node 25.8.2, which is not the supported line and
is excluded by `vitest@5`'s declared `engines`. Results in this batch were produced on Node 25.8.2
and must be re-verified on Node 24.21.0. `engines` makes the mismatch fail loudly rather than
silently.

## Package manager

| Item | Value |
| --- | --- |
| Package manager | pnpm 12.9.1 (pinned via `packageManager` in `package.json`) |
| Install mode | frozen lockfile |
| Planned install-time minimum release age | 10080 minutes (7 days), tested in Step 06 |

Verification: `npm view pnpm version` → 12.9.1, MIT. Not yet installed or behaviour-tested on this
host — `agent_may_install_runtimes` is still `TODO`. The seven-day delay and the install-script
allowlist are Step 06 work and are **not** claimed as enforced anywhere yet.

## Core dependencies

| Package | Pinned version | Licence | Verified how | Use |
| --- | --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | `npm view ajv version license` | JSON Schema draft 2020-12 validation via `Ajv2020` |
| `ajv-formats` | 3.0.1 | MIT | `npm view ajv-formats version license` | `format` keywords |
| `yaml` | 2.9.1 | ISC | `npm view yaml version license engines` | Bounded YAML parsing with duplicate-key and tag control |
| `typescript` | 7.0.2 | Apache-2.0 | `npm view typescript version license engines` | Strict type checking and build |
| `vitest` | 5.0.3 | MIT | `npm view vitest version license engines` | Test runner |
| `@types/node` | 26.6.4 | MIT | `npm view @types/node version license` | Node type definitions |

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
