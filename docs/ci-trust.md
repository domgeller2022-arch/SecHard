# CI trust model

What the workflows guarantee, what they cannot, and the platform settings a human must configure.
Read this before trusting a green run.

## What the local tests establish

`tests/workflows/trust.test.ts` asserts, on every run:

- every action is pinned to a full commit SHA, with the release named in a comment;
- no workflow grants a write permission, at top level or per job;
- no `${{ }}` expression is interpolated into a shell script (values go through `env:`);
- `pull_request_target` is not used anywhere;
- every `actions/checkout` disables credential persistence;
- a stable `hardening-gate` job exists, depends on every other job, and runs with `if: always()`;
- the callable workflows declare `workflow_call` and require the pinned `hardening_ref` input;
- the consumer template pins the called workflow *and* the policy ref to a commit;
- zizmor reports nothing on the pinned workflows.

## What the local tests cannot establish

**YAML is not enforcement.** The tests above read files. They cannot observe that GitHub actually
requires the checks, that review is required, or who may bypass protection. Those are platform
settings, and a repository can carry every file in this directory and still have no protection
configured. Do not read a passing local suite as "the gate is enforced".

## The trust limit, stated plainly

A maintainer who can replace workflows or policy, or who holds a bypass permission, can defeat the
gate. That is inherent to running checks in the same repository as the thing being checked, and it is
not fixed by any file here. A required-check name alone does not prevent a permitted workflow from
reporting a forged success. The mitigations are procedural: protect these paths, limit who can bypass
them, and review bypass use.

## Platform settings the owner must configure

These are paragraph-level instructions because the work is in repository settings, not in a file.

1. **Required checks.** On the default branch, require `hardening-gate` from the `repo-checks`
   workflow, and require it to be *from that workflow*, not merely a check with that name. GitHub
   matches a check by name and source; a different workflow can publish a check with the same name.
2. **Review before merge.** Require at least one approving review for changes under the paths in
   `agent-rules/review-manifest.yaml`, and enable dismissal of stale approvals when new commits
   arrive.
3. **CODEOWNERS.** Install `templates/CODEOWNERS.template` as `.github/CODEOWNERS` once
   `github_codeowners` in `01-owner-decisions.md` is filled with real usernames or teams that have
   write access. Verify the file parses: GitHub silently skips lines it cannot resolve.
4. **Bypass permissions.** Record who may bypass the required checks. Prefer nobody. If someone must,
   name them, and review their bypass use as an incident-style event rather than a routine.
5. **Sensitive-file review.** Treat `.github/`, `policy/`, `controls/`, `src/domain/`,
   `src/validation/`, `src/execution/`, and `tests/` as requiring review; the manifest lists them.
6. **Fork and queue behaviour.** Fork pull requests legitimately lack secrets; the workflows are
   written so they do not need any. If merge queues are enabled, the queue's synthetic merge commit
   is what gets evaluated, and a check that ran against the pull-request head does not cover it.
   Merge queues are unavailable on disposable personal-account repositories, so a queue claim is
   outside the supported set unless the owner's organisation supports it.
7. **Workflow protection.** Require review for workflow changes, and prefer the platform's own
   "require approval for workflows from forks" setting over any convention.
8. **A failure must stay visible.** A scheduled or required check that fails should notify someone.
   Nothing here rewrites a failing result into a passing one.

## Status

Platform verification has **not** been performed: the GitHub test environment fields
(`github_test_owner`, `github_test_repos`) are unfilled and no test token is available. Everything in
this document that describes platform behaviour is therefore a requirement on the owner, not a
verified claim. Recorded as `awaiting_external_verification` in the progress record.
