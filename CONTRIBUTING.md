# Contributing

## Ground rules

Read `SECURITY.md` first. Its hardening rules are not optional and they apply to every change,
including AI-assisted ones.

The central expectation: **a change is not done because it compiles or because the suite is green.**
It is done when the behaviour it claims actually holds, the checks that verify it really ran, and any
failure encountered is recorded rather than hidden.

## Setup

```bash
pnpm install --frozen-lockfile
pnpm run build
pnpm run typecheck
pnpm run lint
pnpm test
```

Linux CI is the supported execution environment. `pnpm` is the pinned package manager; do not commit
an npm or yarn lockfile alongside it. The install-time minimum-release-age policy and the
install-script allowlist arrive in Step 06 and are not enforced yet, so review `pnpm-lock.yaml` diffs
carefully until they are.

## What requires review, and why

These paths change what the gate accepts. A change to any of them is security-sensitive even when it
looks like a one-line fix.

| Path | What to check |
| --- | --- |
| `controls/controls.yaml` | Acceptance criteria still describe behaviour that could actually be tested; `review_status` was not set to `owner_reviewed` by the author |
| `controls/mappings/` | The mapping was checked against the pinned source edition and is labelled `related_risk` rather than verified coverage |
| `schemas/*.schema.json`, `controls/control.schema.json` | No loosening: `additionalProperties`, `required`, patterns, and bounds must not be relaxed without a recorded reason |
| `policy/gate-policy.yaml` | No threshold, freshness window, or required-recipe reduction. These decide what blocks |
| `src/domain/` | Decision logic. This is the security-critical core; a change can turn a block into a pass |
| `tests/gate/`, `tests/failure-modes/` | The test still fails when the behaviour it guards is removed. Removing a case is a finding, not a cleanup |
| `controls/approvals.yaml` | An agent must never write an approval. Verify each digest resolves and that `kind` is honest about self-review versus independent review |
| `controls/patterns/` | Corrected rationale is present, provenance is recorded, and no pattern claims `implemented: true` verification that does not exist |
| `upstream/sources.yaml`, `upstream/notices/` | Licence, use type, attribution, and notice for each imported component; `planned` is not `verified` |
| `agent-rules/core/rules.yaml` | A rule was not weakened into a soft preference, and nothing now permits a skipped test or a simulated scan. Regenerate the outputs in the same change |
| `agent-rules/review-manifest.yaml` | New sensitive paths are covered and no pattern was widened to match everything |
| `.github/workflows/` | Permissions, pinned references, and whether a job executes untrusted code with privileged access |
| `.npmrc`, `package.json` | `engines`, `packageManager`, dependency additions, and any relaxation of the install policy |
| `docs/` claims | Every "verified" or "supported" statement still matches `docs/implementation-progress.md` |

## Generated files

`controls/matrix.md`, `docs/checkpoints/control-review-sheet.md`, and everything under
`agent-rules/generated/` are generated. Do not hand-edit them: edit the source and run the generator
in the same commit. The generator refuses to overwrite a file that lacks its generated marker, so a
hand-edited copy will fail generation rather than be silently replaced.

Before opening a pull request that touches security tests, policy, scanner configuration, or
workflows, run `pnpm run review:changes <base>` and include the report. It does not judge intent; it
makes the change visible so a reviewer can.

## Approvals and imported guidance

- A control definition is `draft` until the owner records an approval in `controls/approvals.yaml`
  against the exact content digest. Do not edit that file unless you are the owner. Do not mark a
  draft `owner_reviewed` in the definition and call it approved: the gate reads the approval record,
  and the digest is what makes an edit invalidate the previous approval.
- Adapted external material goes in `controls/patterns/patterns.yaml`, with the corrections that were
  applied recorded in `provenance.corrections`, and the component's licence and notice recorded in
  `upstream/`. Never copy upstream text or examples without applying the review's corrections and
  recording provenance.
- `implemented: false` on a pattern verification is honest and expected until the fixture exists.
  Setting it to `true` without a working, executed check is a false claim.

## Draft control definitions

A control definition written by the build agent carries `review_status: draft`. **Only the owner
changes it to `owner_reviewed`, with a reviewer name and date.** Do not mark your own draft as
reviewed. `docs/checkpoints/control-review-sheet.md` is the efficient way to review all 35 at once.

## Adding a dependency

1. Confirm the package actually exists and is what it claims. Hallucinated package names spread
   through AI instructions; verify identity, publisher, and source before installing anything.
2. Check the licence and record it per component.
3. Prefer the standard library or a native platform feature. This project deliberately avoids
   dependencies for argument parsing, canonical JSON, and policy expression.
4. Install only what the current step needs.
5. Do not run an installer or install script you have not inspected.

Existence, age, download count, and signature are complementary signals. None alone establishes that
a package is safe.

## Tests

```bash
pnpm test                  # unit, domain, validation, CLI
pnpm run test:integration  # end-to-end runs against the built CLI
```

- Label fixture and mock data as `fixture` in the test name and in any emitted record.
- Do not write a test that asserts a hardcoded value in place of real behaviour.
- Do not add a test merely so a test command has something to run; an empty or trivial test hides a
  missing check.
- Never retry a failing security assertion until it passes. Investigate flakiness and record it.

## Reporting a problem

Security issues follow `SECURITY.md`. Everything else is a normal pull request.
