# SecHard (`sechard`)

A versioned security **control catalogue**, real **verification checks**, and honest **release
evidence** for applications built with AI coding tools. The CLI is `hardening`.

Guidance, checklists, and scanner output usually live apart from any particular application's actual
state, so an AI-assisted build can look checked without being checked. SecHard connects the two: a
shared catalogue of control definitions lives here; each application keeps its own applicability
decisions, evidence, and exceptions.

The owner's goal, recorded 2026-10-08: point SecHard at an application and get a thorough audit that
**audits and suggests, never fixes** — with quality a first-class section of the report, every check
it could not run stated as a warning, and nothing claimed that was not executed. Audit mode
(Batch U) is not built yet; this README says what exists today.

## Status

**Batch R (repair) of the remediation plan is implemented; Batch W (wiring the scanners into the
CLI) has not started.** The gate, evaluator, tool pinning, adapters, reference application, and live
checks exist and are tested, but `hardening check` still runs only the built-in record-consistency
recipe.

Read before trusting anything:

| File | Why it matters |
| --- | --- |
| `docs/status.md` | Generated from the progress record: each step's actual state |
| `docs/implementation-progress.md` | The full record: checks run, failures, blockers |
| `CHANGELOG.md` | What changed, with blocked and unverified work stated |
| `docs/trust-model.md` | What this repository trusts and refuses to trust |
| `docs/supported-versions.md` | What is verified versus merely planned |
| `docs/ci-trust.md` | What the workflows establish, their trust limit, and the H4 gap |

## Requirements

| Component | Version | Status |
| --- | --- | --- |
| Node.js | 24 LTS (Krypton), tested target 24.21.0 | Pinned in `package.json` `engines` |
| pnpm | 12.9.1 | Pinned via `packageManager` |

Linux is the supported CI execution environment. The per-platform toolchain record pins assets for
`linux-x64`, `linux-arm64`, `darwin-x64`, and `darwin-arm64`; a platform with no pinned asset is
refused, never guessed. On macOS, only the checks actually run on that host are claimed.

## Build and test

```bash
pnpm install --frozen-lockfile --filter sechard   # only this package; not the example workspace
pnpm run build                                    # dist/; must precede anything that imports it
pnpm run typecheck                                # sources and tests
pnpm run typecheck:tools                          # tool scripts, against the built dist/
pnpm run lint
pnpm test                                         # unit tests: no fetched tools, no example build
pnpm run test:scanners                            # needs `pnpm run fetch:tools`; real scanner runs
pnpm run test:example                             # needs the example built (`next build`)
pnpm run test:integration                         # the compiled CLI from outside the repository
```

`fetch:tools` downloads the pinned scanner binaries for the current platform and verifies each
against the digest reviewed in `policy/toolchain.yaml` before anything is written. When a platform
is not pinned it exits with `unsupported_platform`. A `GITHUB_TOKEN` is used when present.

## CLI

```bash
export APP=/path/to/your/application
export POLICY=/path/to/SecHard
export RUNS="$APP/.hardening/runs"

hardening validate --app "$APP" --policy "$POLICY"
hardening plan --app "$APP" --policy "$POLICY" --stage pr --environment local --out "$RUNS"
export RUN_DIR="$(ls -d "$RUNS"/*/ | tail -1)"
hardening check --app "$APP" --policy "$POLICY" --plan "$RUN_DIR/plan.json" --out "$RUN_DIR"
hardening gate --app "$APP" --policy "$POLICY" --run "$RUN_DIR"
hardening report --app "$APP" --policy "$POLICY" --run "$RUN_DIR"
hardening approvals --policy "$POLICY"
```

| Exit code | Meaning |
| --- | --- |
| `0` | Decision satisfied |
| `1` | Valid execution with a blocking finding or unmet requirement; `check` also exits 1 when a required check did not run |
| `2` | Invalid inputs, or execution/evidence errors |

Both nonzero results fail a required CI check. `report` uses the same evaluation as `gate`, so
formatting can never change the decision. Evidence is bound to the run and attempt it records, not
just the commit.

## What works today

- The loader, planning, and pure evaluation engine (identity, freshness, scope, fixtures, approvals,
  exceptions, manual evidence).
- Four scanner adapters with pinned, digest-verified tools, exercised against vulnerable and fixed
  fixtures (`test:scanners`).
- The reference Next.js + Supabase application: forced RLS, an authorization matrix with proven
  detection on a weakened policy, a browser suite, build/client-asset inspection, and a ZAP passive
  baseline.
- Guarded live HTTP checks against an approved-target inventory; TLS is deliberately separate and
  blocks a production release until evidence exists.
- Generated agent guidance, a review manifest, and a security-test change report.
- Workflows with a fail-closed final gate; the final job re-runs the gate against the uploaded plan
  and results.

## What does not work yet

- **`hardening check` runs no scanner.** Except for the record-consistency recipe, every planned
  check reports `unsupported`, and the gate blocks. Wiring the adapters into the CLI is Batch W
  (audit finding C1).
- **A pull request supplies its own `.hardening/` records**, so it can weaken its own assessment
  until Batch W3 (audit finding H4).
- **No audit mode.** Pointing SecHard at an arbitrary folder or URL without a manifest is Batch U.
- **No quality section.** Duplication, complexity, dead code, test quality, and AI-authorship tells
  are Batch Q.
- **Standards are mapped at chapter level only** (`related_risk`), with no requirement IDs; that is
  Batch S.
- **Platform verification has not been performed.** Required checks, CODEOWNERS resolution, forks,
  and merge queues are unverified until the owner's throwaway GitHub account exists.
- **No licence and no security contact.** `code_licence`, `docs_licence`, `owner_legal_name`, and
  `security_contact_email` are unfilled owner decisions; the package is private and `UNLICENSED`.

## Adoption and audit mode

Independent consumer adoption is not available yet; it is Batch D (original Step 15). Do not start
from this repository as a workspace dependency. The reference application under
`examples/nextjs-supabase/` is a demonstration, not a template.

## Security-sensitive paths

Control definitions, schemas, policy, profiles, gate logic, security tests, scanner configurations,
and workflows are security-sensitive. `agent-rules/review-manifest.yaml` says why each requires
review. `agent-rules/core/rules.yaml` is the single source for the generated `AGENTS.md`/`CLAUDE.md`
guidance. Prompt text is not a permission boundary; `agent-rules/operator-requirements.md` states
the runtime restrictions an operator has to configure.

## Licence

**Unresolved.** `docs_licence` and `code_licence` in `01-owner-decisions.md` are `TODO`, so there is
no `LICENSE` file and the package is marked `private` and `UNLICENSED`. Copied or adapted upstream
material keeps its own licence and notice. See `docs/supported-versions.md`.
