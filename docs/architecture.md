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
| Execution | `src/execution/` | Reviewed-executable registry, provisioning policy, verified downloads, bounded process launch |
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

## Control approval

A control definition is `draft` until the owner approves it. Approval is recorded in
`controls/approvals.yaml`, not in the definition itself, and it names three things:

- the control ID and definition version
- a SHA-256 digest of the definition's **reviewed content** (RFC 8785 canonical form, with
  `review_status`, `reviewed_by`, and `reviewed_at` excluded so recording an approval does not
  invalidate itself)
- the reviewer, review time, and whether the review was `owner` acceptance or `independent`

The digest is what makes an edit invalidate an approval. Editing acceptance criteria without bumping
`definition_version` produces a different digest, so the old approval no longer resolves — a version
number alone cannot catch that.

Enforcement is stage-scoped: development, PR, and operations stages may exercise draft definitions;
**release evaluation requires a valid approval for every applicable control**. A recorded
`review_status: owner_reviewed` in the definition is an assertion the evaluator cannot verify, and
it is not accepted as proof — the approval record is what the gate reads. For a sole maintainer,
`kind: owner` is self-review and is reported as such, never as independent assurance.

`hardening approvals --policy .` prints the exact digest the owner must approve and the current
state of every definition.

## Reviewed pattern library

`controls/patterns/patterns.yaml` holds reviewed security patterns imported and corrected from
external guidance. A pattern records its related control IDs, applicability, corrected rationale,
limitations, a vulnerable example, a permitted example, verification methods (with
`implemented: false` until a fixture or recipe actually exists), and provenance including every
factual correction applied before reuse.

A pattern is a **supporting record, not a control**. It cannot override applicability, approve an
exception, produce execution success, or add a top-level control ID — and its ID shape
(`PAT-...`) deliberately cannot be mistaken for one. Patterns feed agent guidance (Step 12) and
fixtures (Steps 07–11). Pattern verification that is `implemented: false` is not evidence of
anything, and the gate never reads a pattern as a result.

## Tool execution and provisioning

`src/execution/` is the only place this repository starts an external process, and it is built around
refusals:

- **An unidentified tool does not run.** A tool needs an absolute executable path, a recorded
  version, and — when it is fetched rather than provided by the platform — a verified SHA-256. Every
  scanner is currently recorded with `identity: unverified`, so the registry refuses all of them.
  That refusal is the honest state, not a gap to work around.
- **A recorded digest is checked against the binary on disk before it runs.** A pin nobody verifies
  detects nothing.
- **The installed version must match the record.** A tool that reports a different version is not the
  reviewed tool.
- **Arguments are an array and there is no shell.** `;`, backticks, and `$(...)` in an argument are
  data. Only an absolute path is accepted, so `PATH` cannot redirect execution.
- **The environment is an allowlist.** The parent environment is never inherited wholesale.
- **Output is bounded and deadlines are enforced** with SIGTERM then SIGKILL, signalling the whole
  process group so grandchildren do not survive.
- **Provisioning is separate from checking.** `check` never installs a missing tool as a side effect;
  a missing tool is reported as unavailable. A provisioning plan is validated — exact version,
  reviewed registry, release-age policy, reviewed install hooks, digest for downloads — before
  anything executes, and refuses entirely when any item fails.
- **Downloads are digest-gated, size-capped, HTTPS-only** (loopback excepted for tests and local
  mirrors), and redirects are refused by default, because a redirect is an origin that reviewed
  policy did not approve.

The release-age delay lives in `policy/dependency-policy.yaml` (`10080` minutes). Its enforcement by
the package manager is a separate, testable behaviour; until that behaviour has been verified on a
machine, provisioning plans are blocked rather than assumed to have applied.

**Nothing here is a sandbox.** A spawned process is not isolated. Recipes that execute application
code must state the environment the operator has to provide, and that requirement is recorded in
`policy/dependency-policy.yaml`.

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
| Scanner / test result | The exact source commit, policy commit, target, **run, and attempt** it records. Matching commits alone is not enough: a result is evidence only for the run it belongs to, so an old report for the same commit cannot be replayed. Cross-run reuse is disabled in `policy/gate-policy.yaml` (`allow_cross_run_reuse: false`) |
| Advisory snapshot | ≤ 7 days for `pr`, ≤ 24 hours for `release`. Measured by mode: an online query by its query time; an offline database by its retrieval time and, when the interface supplies one, its upstream update time — a freshly executed scan over an old cached database is stale |
| Manual evidence | Per-control interval in policy (Step 14; defaults 30 days external access/configuration, 90 days restore/response) |

Evidence outside its window is `stale` and cannot pass. Implausible future evidence is rejected
rather than treated as fresh.

## Document precedence

`01-owner-decisions.md` → `00-KICKOFF-PROMPT.md` → `02-implementation-plan.md` →
`03-blueprint.md`. Blueprint sections 2 and 3 are research background, not tasks. An unsettled
conflict resolves to the more restrictive security behaviour, is recorded in
`docs/implementation-progress.md`, and is raised at the next checkpoint.
