# SecHard (`sechard`)

A versioned security **control catalogue**, real **verification checks**, and honest **release
evidence** for applications built with AI coding tools. The CLI is `hardening`.

Guidance, checklists, and scanner output usually live apart from any particular application's actual
state, so an AI-assisted build can look checked without being checked. SecHard connects the two: a
shared catalogue of control definitions lives here; each application keeps its own applicability
decisions, evidence, and exceptions.

The owner's goal, recorded 2026-10-08: point SecHard at an application and get a thorough audit that
**audits and suggests, never fixes** — with quality a first-class section of the report, every check
it could not run stated as a warning, and nothing claimed that was not executed. Batch U (audit
mode) implements the pointing-at-a-folder half of that goal; the quality section is Batch Q.

## Status

**Batches R, W, U (audit mode), Q (quality), and S (standards) of the remediation plan are
implemented.** `hardening check` runs the secret, dependency, static-analysis, workflow,
client-asset, and live-HTTP recipes through the reviewed toolchain; `hardening audit` produces a
prioritised, plain-English report on any folder — no manifest required — with the profile set
composed from what detection finds; and every audit now carries a **quality section** (Batch Q)
reported separately from security: error handling, test quality, AI-authorship tells, strict
correctness, repository hygiene, and dependency health are measured by six wired recipes, with
measured recall and precision (1.0/1.0 on the calibration corpus) and the remaining analysers
(jscpd, Lizard, Knip, dependency-cruiser, formatters, axe-core) honestly `unsupported` with their
reasons. The authorization, functional, dependency-policy, agent, and release recipes still report
`unsupported` with their reasons. Standards are mapped at requirement level (Batch S): 518 entries across ASVS 5.0.0, Top 10 2025,
API Top 10 2023, SSDF 1.1, OSPS, MVSP, ASD SBD, and MCP (link-only), with generated coverage
matrices under `controls/coverage/` and a per-application standards statement in every audit
report.

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

Audit mode, no manifest needed — it never modifies the audited project:

```bash
hardening audit /path/to/any/folder --out /path/outside/that/folder
hardening audit . --depth quick --out ../sechard-audit     # static scanners only, fast
hardening audit . --url https://deployed.example.com --out ../sechard-audit
```

See `docs/audit-mode.md` for the full contract: depths, the `--url` guard, and what an audit
deliberately refuses to do.

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
- **`hardening check` runs real recipes**: gitleaks (current files, repository, and history),
  osv-scanner, opengrep, zizmor, the client-bundle secret classifier, and the guarded live HTTP
  checks. Each raw
  report is stored with a digest, a missing tool is an error with the registry's reason, and a
  recipe that does not apply is `unsupported` with its reason — never a pass.
- Four scanner adapters with pinned, digest-verified tools, exercised against vulnerable and fixed
  fixtures (`test:scanners`), plus a CLI-level test that proves a real detection through each recipe.
- The reference Next.js + Supabase application: forced RLS, an authorization matrix with proven
  detection on a weakened policy, a browser suite, build/client-asset inspection, and a ZAP passive
  baseline.
- Guarded live HTTP checks against an approved-target inventory; TLS is deliberately separate and
  blocks a production release until evidence exists.
- **Audit mode (Batch U).** `hardening audit PATH` detects the stack and features from evidence,
  composes the profile set, generates an ephemeral manifest outside the target, and runs the same
  plan/check/gate machinery. It produces `report.md` (prioritised "fix these first", plain-English
  findings with effort, confidence, standards references, and a ready-to-paste prompt), a
  self-contained `report.html`, `report.json`, and schema-valid `report.sarif`. The audited tree is
  byte-identical afterwards (enforced by a tree-digest test). `--url` runs live checks against one
  operator-approved origin, refusing private/loopback/link-local targets unless `--allow-local`
  explicitly opts in. No recipe executes application code; deeper audit needs an isolation model
  that does not exist yet and is refused rather than faked.
- Composable profiles (Batch U): `nextjs`, `react-spa`, `node-api`, `python-web` stack profiles,
  `supabase` and `payments` feature profiles, composed from detection in audit mode and selectable
  explicitly in gate mode.
- Generated agent guidance, a review manifest, and a security-test change report.
- Workflows with a fail-closed final gate; the final job re-runs the gate against the uploaded plan
  and results.

## What does not work yet

- **Most of the catalogue is still unimplemented.** The authorization matrix, functional tests,
  dependency-policy, agent, and release recipes report `unsupported`; an application therefore
  cannot fully pass yet, and the gate blocks honestly.
- **TLS is still manual.** `testssl.sh` is unpinned, so a production release blocks on missing TLS
  evidence (Batch X). ZAP remains a standalone Step 11 tool, not a control recipe.
- **Pull requests now evaluate the base branch's records** (Batch W3): a PR that changes them fails
  as review-required, and the first adoption has a documented bootstrap path.
- **Standards at requirement level (Batch S).** ASVS L1 reviewable line by line against the
  vendored official CSV; AUTH-03 (OAuth/OIDC flow security, RFC 9700) at catalogue v3; six new
  static rules (SSRF, unsafe external-response consumption, implicit grant, and the Electron
  trio); WSTG citations on every test recipe; OSPS Level 1 applied to this repository with every
  miss recorded as met, owner-blocked, or release-pending.
- **Quality (Batch Q).** Six SecHard-owned quality recipes are wired (`quality/error-handling` via
  the reviewed opengrep pack, `quality/vibe-tells`, `quality/test-quality`,
  `quality/strict-correctness`, `quality/repo-hygiene`, `quality/dependency-health`), calibrated
  on `tests/corpus/` (a deliberately vibe-coded app with 18 seeded issues and a clean twin) and on
  this repository's own self-audit, which reports exactly one accepted finding (the deliberately
  absent licence, a recorded owner decision). The catalogue is at version 2 (47 controls: the 35
  v1 IDs unchanged plus QUAL-02…13) with a migration note; the duplication, complexity, dead-code,
  module-structure, formatting, and frontend-quality recipes need external analysers that are not
  provisioned yet and report `unsupported` with the reason rather than a fabricated pass.
- **Audit mode has boundaries, stated rather than implied.** It audits a local folder only (clone a
  Git URL yourself first — the trust rules for cloning untrusted repositories are deliberately not
  built); `--depth deep` adds nothing over `standard` in this build because executing an
  application's own build and tests needs the audit isolation model (gap D1) and is refused;
  Python static analysis is not run because the reviewed rule pack is JavaScript/TypeScript only;
  unsupported stacks (Expo, React Native, Flutter, Electron, unknown) produce a gap banner, not a
  clean report.
- **No quality section.** Duplication, complexity, dead code, test quality, and AI-authorship tells
  are Batch Q.
- **Standards are mapped at chapter level only** (`related_risk`), with no requirement IDs; that is
  Batch S.
- **Platform verification has not been performed.** Required checks, CODEOWNERS resolution, forks,
  and merge queues are unverified until the owner's throwaway GitHub account exists.
- **No licence and no security contact, by decision.** The repository is private, maintained and
  used by one person, and not released (`release_scope: private-sole-maintainer` in
  `01-owner-decisions.md`). The package is `private` and `UNLICENSED`; OPS-03 stays unmet and a
  release evaluation blocks, which is correct while no release is planned.

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

**None, deliberately.** The owner's decision of 2026-10-09: this repository is private, maintained
and used by the owner alone, and not distributed, so no `LICENSE` file exists and the package is
marked `private` and `UNLICENSED` to prevent accidental publication under a default licence. Copied
or adapted upstream material keeps its own licence and notice. See `docs/supported-versions.md`.
