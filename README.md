# hardening

A versioned security **control catalogue**, real **verification checks**, and honest **release
evidence** for applications built with AI coding tools.

The problem this addresses: guidance, checklists, and scanner output all exist separately from any
particular application's actual state, so an AI-assisted build can look checked without being
checked. This repository connects the two. A shared catalogue of control definitions lives here; each
application keeps its own applicability decisions, implementation records, evidence, and exceptions.

## Status

**Under active construction.** This is a Step-by-step build against
`02-implementation-plan.md`. What exists today is the first batch: schemas, 35 draft control
definitions, two profiles, the planning and decision engine, and a working CLI.

Read these before trusting anything here:

| File | Why it matters |
| --- | --- |
| `docs/implementation-progress.md` | Exactly which steps are verified, blocked, or not started, and every blocker |
| `CHANGELOG.md` | What changed at each step, with blocked work stated |
| `docs/supported-versions.md` | What is actually verified versus merely planned |
| `docs/trust-model.md` | What this repository trusts and refuses to trust |

No scanner is integrated. No reference application exists. No external platform verification has been
performed. Nothing here claims a control is satisfied.

## What it does not claim

- A passing test suite is not a security assessment.
- A linked standards category (`related_risk`) is not conformance. Mappings must be reviewed.
- A stored `status: pass` in an application is a claim. The evaluator recomputes outcomes.
- A digest proves a file did not change. It does not prove who produced it.
- Zero scanner findings is meaningful only when expected scope was actually covered.
- Fixture output never satisfies a real release requirement.
- Required-check enforcement is a platform setting. Adding YAML does not create it.
- A reviewed pattern or a generated agent rule is guidance, not verification. It cannot satisfy a
  control or produce release evidence.
- An approval recorded by an agent is not proof of human review. Only an owner action creates a
  valid approval, and the `kind` field distinguishes self-review from independent review.

## Requirements

| Component | Version | Status |
| --- | --- | --- |
| Node.js | 24 LTS (codename Krypton), tested target 24.21.0 | Pinned in `package.json` `engines` |
| pnpm | 12.9.1 | Pinned via `packageManager` |

Linux CI is the supported execution environment. macOS support is claimed only after the documented
subset has actually been run there.

## Build

```bash
pnpm install --frozen-lockfile
pnpm run build
pnpm run typecheck
pnpm run lint
pnpm test
pnpm run test:integration
```

`pnpm install --frozen-lockfile` is the required install command. `--frozen-lockfile` alone is not the
whole policy: the install-time minimum-release-age delay and the install-script allowlist are Step 06
work and are not enforced yet.

## CLI

```text
hardening validate  --app APP_ROOT --policy POLICY_ROOT
hardening plan      --app APP_ROOT --policy POLICY_ROOT --stage pr --environment local --out RUN_DIR
hardening check     --app APP_ROOT --policy POLICY_ROOT --plan RUN_DIR/plan.json --out RUN_DIR
hardening gate      --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
hardening report    --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
hardening approvals --policy POLICY_ROOT
```

Repository tooling (run from this repository):

```bash
pnpm run generate:matrix        # regenerate controls/matrix.md and the owner review sheet
pnpm run generate:agent-rules   # regenerate agent-rules/generated/{AGENTS.md,CLAUDE.md}
pnpm run review:changes <base> [head]   # report security-test and sensitive-path changes
pnpm run fetch:tools            # fetch and digest-verify the pinned scanner binaries (provisioning)
```

`approvals` prints the reviewed-content digest of every control definition and whether a valid owner
approval is on record. Approval names that digest, so an edited definition loses its approval even
without a version bump. Release evaluation requires a valid approval for every applicable control;
development and PR stages may exercise draft definitions and their reports say the policy is draft.

| Exit code | Meaning |
| --- | --- |
| `0` | Decision satisfied |
| `1` | Valid execution with a blocking finding or unmet requirement |
| `2` | Invalid inputs, or execution/evidence errors |

Both nonzero results fail a required CI check. `report` uses the same evaluation as `gate`, so
formatting can never change the decision.

**Implementation status of the commands:** see `docs/implementation-progress.md`. As of Batch A only
`validate`, `plan`, `check` (one built-in recipe), `gate`, and `report` exist, and they cover policy
and record consistency only — no scanner, no application test, and no deployment check.

## Adopting it in an application

Not available yet. Adoption of an independent consumer repository is Step 15. Do not start from this
repository as a workspace dependency: the plan requires proving that adoption works without hidden
master-workspace dependencies.

## Agent guidance

`agent-rules/core/rules.yaml` is the single reviewed source; `agent-rules/generated/AGENTS.md` and
`CLAUDE.md` are generated from it so the two formats cannot drift. The generator refuses to overwrite
a file it did not generate. `agent-rules/review-manifest.yaml` lists the paths whose changes require
human review, and `agent-rules/operator-requirements.md` states the runtime restrictions an operator
must configure, because prompt text is not a permission boundary.

## Patterns and agent guidance

`controls/patterns/patterns.yaml` holds reviewed security patterns adapted from external guidance.
Each records its related controls, corrected rationale, limitations, a vulnerable and a permitted
example, verification methods, and provenance with the corrections applied. They are supporting
records: they cannot override applicability, approve an exception, or produce execution success, and
their IDs cannot be mistaken for control IDs.

## Contributing

See `CONTRIBUTING.md`. Changes to control definitions, schemas, policy, security-test assertions, and
gate logic are security-sensitive and need review. Control definitions written by the build agent
carry `review_status: draft` until the owner records approval.

## Licence

**Unresolved.** `code_licence` and `docs_licence` in `01-owner-decisions.md` are still `TODO`, so no
`LICENSE` file exists and the package is marked `private` and `UNLICENSED`. Copied or adapted
upstream material keeps its own licence and notice regardless of that decision. See
`docs/supported-versions.md` for per-component licences.
