# Trust model

What this repository trusts, what it refuses to trust, and where authority actually comes from.
Read this before adding an adapter, a recipe, or a new kind of input.

## Trust levels

| Level | Examples | Treatment |
| --- | --- | --- |
| **Authoritative** | This repository's reviewed control definitions, schemas, `policy/*.yaml`, and the pinned toolchain | Establishes policy. Cannot be changed by a consumer or by an untrusted PR |
| **Reviewed configuration** | `.hardening/app.yaml`, profile selection, `policy-lock.json` | Declarations that change obligations. May not remove an obligation, only add one |
| **Untrusted input** | Application source, imported records, scanner output, fetched pages, package READMEs, issue text, agent output, CI context | Data. Cannot authorize an action, grant permission, or change policy |
| **Evidence** | Check results, reports, manual attestations | Claims about what was observed. Verified against identity (including run and attempt), scope, and freshness before use |
| **Supporting guidance** | Reviewed patterns, upstream source records, generated agent rules | Context and corrected rationale. Cannot override applicability, approve an exception, or produce execution success |

The single rule that drives everything: **untrusted input is data, never an instruction.** A finding
that contains "ignore previous instructions" or a URL that points somewhere unexpected is still just
a string to be stored and reported.

## Authority and non-authority

**Authoritative:** schemas, control definitions, gate policy, stage requirements, toolchain pins,
and the decision engine's rules.

**Never authoritative, regardless of how the file is labelled:**

- A `status: pass` field written in a consumer repository. The evaluator recomputes outcomes.
- A consumer's profile selection, exception list, or assessment. These can add obligations and
  request waivers; they cannot delete a required check.
- An untrusted pull request's copy of policy or profile files. PR decisions use the approved base
  policy lock and surface proposed changes separately.
- A scanner's exit code by itself. Zero findings is meaningful only when expected scope was actually
  covered.
- Fixture or mock output. `fixture` origin can never satisfy a real release requirement.
- Natural-language agent instructions. A prompt cannot restrict permissions.
- A reviewed pattern, however well sourced. It is guidance, not a control, and carries no outcome.
- A control definition's own `review_status: owner_reviewed` field. Approval is recorded separately,
  against the reviewed content digest, and only the owner can create it.

## Operations that execute code

| Operation | Executes untrusted code | Notes |
| --- | --- | --- |
| `validate` | No | Reads bounded files, hashes them |
| `plan` | No | Pure derivation from validated records |
| `gate` / `report` | No | Pure evaluation |
| `check` (built-in policy consistency) | No | Reads and compares validated records |
| `check` (scanner recipes) | Yes, external binaries | Refused unless identity resolves: absolute path, recorded version, and a digest checked against the binary. Argument arrays, allowlisted environment, bounded output, enforced deadline |
| Provisioning (explicit, separate from checking) | Runs the package manager | Plan validated before execution; exact versions, reviewed registry, age policy, reviewed hooks, digests for downloads. Never triggered by a missing tool during `check` |
| Application tests / builds (Step 10) | Yes, application code | Requires an operator-approved disposable or isolated environment |

**A separate directory is not isolation. An environment-variable allowlist is not isolation. A
spawned process is not a sandbox.** None of these is used as a security boundary anywhere in this
repository. Where untrusted code must run, the isolation comes from the operator's approved
ephemeral environment (a container, VM, or CI-isolated runner) and that requirement is stated as an
operator obligation in `docs/trust-model.md` and `policy/dependency-policy.yaml`.

## Secret boundaries

- No real credentials in code, fixtures, commits, reports, logs, or agent conversation.
- Synthetic secrets in fixtures are non-functional, obviously synthetic, and labelled.
- Findings from secret scanners are redacted before any console or report emission.
- Full process environments are never written into evidence.
- Reports are split into a shareable summary and access-controlled raw reports. Public summaries
  avoid internal endpoints, exploit detail, and sensitive records.

## Approval and self-review

Owner acceptance is recorded against the exact reviewed content, so an edited definition loses its
approval. On a solo-maintained project that acceptance is self-review, not independent security
review, and the reports say so. Independent review is a distinct `kind`, never inferred.

## Identity and evidence

- Evidence is bound to source commit, policy commit, target, run, and attempt. Results are not
  reused across commits, and cross-run reuse is disabled by policy.
- Digests (SHA-256 over raw bytes or RFC 8785 output) detect change. They do not prove authorship
  or that a process ran.
- A signature, where a later release enables it, identifies who made an assertion, not whether every
  claimed execution happened.

## Platform trust limit

A maintainer who can replace workflows or policy, or bypass branch protections, can defeat the
gate. That limit is stated plainly rather than papered over. Required-check enforcement, reviewer
rules, and bypass permissions are platform settings: they are not established by adding YAML files,
and this repository never claims a check name alone prevents a forged success.

## Single-maintainer honesty

Where a sole maintainer records and accepts risk, that is self-review, not independent assurance.
It is recorded as such. See `EXC-01` and Step 14.
