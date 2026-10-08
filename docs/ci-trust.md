# CI trust model

What the workflows guarantee, what they cannot, and the platform settings a human must configure.
Read this before trusting a green run.

Batch R (2026-10-08) made both consumer workflows fail-closed. Every gate step runs without
`|| echo` or `continue-on-error`, `check` exits nonzero when required work did not run, and the final
`hardening-gate` job re-runs the gate with trusted tooling against the uploaded plan and results
instead of trusting a dependency job's colour. `tests/workflows/trust.test.ts` executes the gate
step's own script with a failing stub to prove the failure propagates (the audit's C2 reproduction).

## Known gap: a pull request still supplies its own records

Until Batch W3 lands, both callable workflows evaluate against the **pull request's own**
`.hardening/app.yaml`, exceptions, and manual evidence. A pull request can therefore turn a feature
off, add a `pass` attestation, or add an exception, and be judged by those records. This is audit
finding H4, it is not fixed by anything in this directory, and it is why a green `hardening-pr` run
is not yet a trust claim about the change. The fix is to evaluate against the base branch's records
and report the PR's record changes as "requires review".

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
- no consumer workflow masks a gate failure with `|| echo`/`|| true` or `continue-on-error`;
- the gate step's actual script fails the job when the gate fails, by executing it;
- the installs are filtered to the tool package, so a consumer job does not install the example's
  Next.js, Playwright, and Supabase CLI dependencies;
- zizmor reports nothing on the pinned workflows (`tests/scanners`, which fetches the pinned tool).

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
3. **CODEOWNERS.** `.github/CODEOWNERS` is installed and names the recorded owner
   (`github_codeowners` in `01-owner-decisions.md`); a trust test asserts it contains no placeholder
   and matches the owner decisions exactly. The file only *requests* review. Require an approving
   review in the platform settings, or GitHub will merge without one: the file parses, but nothing
   enforces it by itself.
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

## GitHub test environment setup (for platform verification)

Platform verification needs a disposable environment. Exact steps:

1. **Create a separate account or organisation** — never your main account or any repository with
   real code. A free organisation is enough. Name it in `github_test_owner`.
2. **Create the disposable repositories** it will use — for example one repository for workflow
   tests and one to act as the "consumer" repository. Name them in `github_test_repos`.
3. **Make the repository settings reproducible**: protect the default branch, require the
   `hardening-gate` check, and note what you configured. The point is to test the settings as much
   as the YAML.
4. **Create a fine-grained personal access token** scoped to that owner:
   - Resource owner: the test account or organisation only.
   - Repository access: only the repositories in `github_test_repos`.
   - Permissions, minimum needed for the operations being tested: **Contents** read/write (push
     branches), **Actions** read/write (dispatch and read workflow runs), **Administration**
     read/write only if the tests must change repository settings, **Metadata** read (implied).
   - Short expiry — days, not months. Revoke it when the batch is done.
5. **Export it at run time only**, as the variable named by `github_test_token_env_var`
   (default `HARDENING_TEST_GITHUB_TOKEN`). Never write it to a file, a commit, an artifact, or a
   log. This repository reads it from the environment and nothing else.
6. **Tell me when steps 1–5 are done** and I will run the platform tests and record the results.

Two limits to know before you start, both recorded in the plan:

- A fine-grained token has **one resource owner**, so it cannot span an upstream repository and a
  fork under a different owner. Testing fork behaviour needs either a fork created by the owner or a
  second credential.
- **Merge queues are not available** for personal-account repositories; they need an organisation
  with queue support. If that capability is absent, the merge-queue claim stays outside the
  supported set rather than being reported as verified.

## Status

Platform verification has **not** been performed: the GitHub test environment fields
(`github_test_owner`, `github_test_repos`) are unfilled and no test token is available. Everything in
this document that describes platform behaviour is therefore a requirement on the owner, not a
verified claim. Recorded as `awaiting_external_verification` in the progress record.
