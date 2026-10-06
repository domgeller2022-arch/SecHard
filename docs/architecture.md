# Architecture

## Purpose

This repository owns **reusable security policy**. A consuming application repository owns its own
**assessment**: what applies to it, how it is implemented, what evidence exists, and what exceptions
it has accepted. Nothing in this repository ever holds an adopter's private records.

```
master repository (this one)          consuming application repository
----------------------------          ---------------------------------
controls/controls.yaml                .hardening/app.yaml
controls/mappings/                    .hardening/assessments.yaml
schemas/*.schema.json                 .hardening/exceptions.yaml
profiles/*.yaml                       .hardening/manual-evidence.yaml
policy/*.yaml                         .hardening/policy-lock.json
src/            (runner, adapters)   .hardening/evidence/
agent-rules/    (generated)          .github/workflows/hardening.yaml
docs/, controls/matrix.md            tests/security/
```

The consumer pins an immutable master-release commit in `policy-lock.json`. `policy/toolchain.yaml`,
`controls/controls.yaml`, and the profiles are all hashed; a changed policy produces a different
identity and invalidates results that were produced under the previous one.

## v1 scope

One core package, one reference stack (`nextjs-supabase`), 35 control definitions, and a local CLI.
Deliberately **not** built in v1: a dashboard, a plugin marketplace, a general policy language, a
custom authentication framework, container/IaC adapters, signed attestations, Firebase, mobile,
desktop, runtime-AI profiles. Each of those needs a supported-version matrix, ownership, real
fixtures, and stated limitations before it is added.

## Layers

| Layer | Location | Responsibility |
| --- | --- | --- |
| CLI | `src/cli.ts`, `src/commands/` | Argument handling, exit codes, diagnostics |
| Domain | `src/domain/` | Types, applicability, planning, evaluation. Pure functions |
| Validation | `src/validation/` | Bounded parsing, JSON Schema, semantic checks |
| Execution | `src/execution/` | Adapter registry, process launch, result capture (Step 06) |
| Adapters | `src/adapters/` | Scanner and reference-stack implementations (Steps 06–11) |
| Evidence | `src/evidence/` | Identities, canonical hashing, digests, freshness, reports |

The domain layer does not import from execution or adapters. The decision engine is a pure function
over validated records so it can be tested independently of any tool.

## CLI contract

```text
hardening validate --app APP_ROOT --policy POLICY_ROOT
hardening plan    --app APP_ROOT --policy POLICY_ROOT --stage pr --environment local --out RUN_DIR
hardening check   --app APP_ROOT --policy POLICY_ROOT --plan RUN_DIR/plan.json --out RUN_DIR
hardening gate    --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
hardening report  --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
```

Stages: `pr`, `release`, `operations` (plus adoption-time stages recorded in policy).

| Exit code | Meaning |
| --- | --- |
| `0` | Decision satisfied |
| `1` | Valid execution with a blocking finding or unmet requirement |
| `2` | Invalid inputs, or execution/evidence errors |

Both nonzero results fail a required CI check. `report` uses the same evaluation as `gate`, so
formatting can never change the decision.

## Data flow

```text
app + policy roots
      |
      v
  validate      bounded parse -> JSON Schema (draft 2020-12) -> semantic checks -> path confinement
      |
      v
  plan          manifest + profile + control catalogue -> expected check list, each with a unique ID,
                source/policy identity, target scope, permitted executable, freshness requirement
      |
      v
  check         run independent checks, normalize results, never downgrade a required check
      |
      v
  gate/report   derive control outcomes from results + manual evidence + exceptions -> decision + reasons
```

`plan` runs before anything executes, so the required work is fixed before results exist. An altered
plan cannot remove a required check: the plan's own identity is recomputed and compared with the
policy it claims to implement.

## Data and trust boundaries

1. Every record type carries a schema version. Unknown fields are rejected except inside a single
   designated `extensions` object.
2. Reference integrity is checked, not just local shapes: referenced control IDs, profile IDs,
   versions, and evidence paths must resolve.
3. Paths resolve inside declared roots. Traversal, escaping symlinks, and evidence references that
   point outside approved roots are rejected. Remote evidence URLs are treated as references;
   validation never fetches them.
4. A consumer's stored `status: pass` is a claim, never proof. The evaluator derives current
   outcomes from required check results and valid manual evidence.
5. A valid exception produces a visible waiver. It never converts a failure into a pass.

## Evidence and hashing

- SHA-256 over raw bytes for original files and reports.
- SHA-256 over RFC 8785 (JSON Canonicalization Scheme) output for structured records, so the same
  record always yields the same digest.
- Original-file digests are retained even when the source was YAML.
- A digest detects that a file changed. It does not prove who produced it. Nothing in this repository
  presents a digest as an attestation of origin.

## Freshness

| Evidence | Valid for |
| --- | --- |
| Scanner / test result | The exact source commit, policy commit, and target it records |
| Advisory snapshot | ≤ 7 days for `pr`, ≤ 24 hours for `release` |
| Manual evidence | Per-control interval in policy (Step 14; defaults 30 days external access/configuration, 90 days restore/response) |

Evidence outside its window is `stale` and cannot pass. Implausible future evidence is rejected
rather than treated as fresh.

## Document precedence

`01-owner-decisions.md` → `00-KICKOFF-PROMPT.md` → `02-implementation-plan.md` →
`03-blueprint.md`. Blueprint sections 2 and 3 are research background, not tasks. An unsettled
conflict resolves to the more restrictive security behaviour, is recorded in
`docs/implementation-progress.md`, and is raised at the next checkpoint.
