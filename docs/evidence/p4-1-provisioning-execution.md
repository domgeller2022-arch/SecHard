# P4.1 evidence — provisioning must really execute and enforce policy (observed 2026-10-16)

The audit's provisioning finding (remediation plan implementation-shape line 108): the dormant
`executeProvisionPlan` reported `executed:true` on package-command failure, silently skipped
download steps, never matched the observed package-manager version against a reviewed exact
version, and never passed the approved registry to the manager. All four are fixed here, before
the P4.2 analysers wire into it — the remediation plan's own ordering.

## What changed

1. **Per-step real outcomes** (`src/execution/provision.ts`): the result carries a
   `ProvisionStepResult` per step — the process outcome and the exact arguments run for package
   steps, the verified-download outcome for download steps — and `executed` is true only when
   every step ran and succeeded. The first failed step stops the plan; remaining steps are
   recorded as `notRun`, because a failed or omitted install cannot claim completion.
2. **Download steps execute, never skip**: a download step runs through the existing
   verified-download primitive (`src/execution/download.ts` — approved origin, recorded SHA-256,
   byte bound, atomic 0600 write), and a digest mismatch stops the plan exactly like a failed
   install, writing nothing. Validation now refuses download steps with no URL or no absolute
   destination (`missing_url`, `missing_destination`).
3. **The manager's observed version must match the reviewed exact version** (plan item 2,
   reusing the existing `extractVersion`): a mismatch refuses the plan before any step runs and
   is recorded as `managerVersion { expected, observed, matched }`.
4. **The approved registry is passed to the manager explicitly** (`--registry`, plan item 2), and
   a package step that names no registry while `provisioning.require_reviewed_registry` is set is
   blocked at validation (`missing_registry`) — "approve whatever the manager defaults to" is not
   a reviewed decision.
5. **`check` never provisions** (Done criterion): verified — no production caller of
   `executeProvisionPlan` exists, and the registry refuses unavailable tools without provisioning
   ("refusing to run an unidentified binary is the control").

## Observed (2026-10-16)

- `tests/execution/policy.test.ts`: 8 new P4.1 tests — a failed package command stops the plan
  with the remaining steps recorded as `notRun`; the approved registry appears in the recorded
  arguments; a manager whose observed version mismatches the reviewed exact version refuses
  before any step; a version-matched manager proceeds to its steps; a download executes, verifies
  its digest, and writes the artifact; a digest-mismatched download stops the plan and writes
  nothing; and the missing-registry, missing-URL, and missing-destination validation blocks.
  Execution suite 79/79.
- Fast suite 610/610 (42 files); lint clean; build clean; preflight OK (181 open); scanners
  suite 76/76 (8 files).
- The existing provision tests (validation blocks, spawn refusal, age policy, exceptions) pass
  unchanged against the new result shape.

## Scope notes (honest)

- The isolated npm-quality-package route (plan item 3 — committed lockfile, frozen install,
  seven-day policy, `allowBuilds: {}`) and the Python venv/wheel-pinning route (plan item 4) are
  the concrete provisioning plans the P4.2 analyser wiring will build and hand to this executor;
  the execution contract they rely on — per-step real outcomes, exact manager version, explicit
  registry, digest-verified downloads, and the failure semantics — is what this subphase made
  real. Which packages and wheels those routes pin is decided with the analyser selection in
  P4.2, and the frozen-install/allowBuilds specifics belong to those routes' plan builders.
- Real-network provisioning remains exercised through the P7/P8 live checks as before; the
  download execution path itself is proven here with an in-process fetch stub, and the
  verified-download primitive carries its own loopback-server suite.
