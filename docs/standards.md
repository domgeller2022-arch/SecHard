# Standards: what is used, where, and what is not claimed

The blueprint's "Standards and upstream resources" section lists standards and candidate tools. It
also says they are research context: they explain why a requirement exists, and they are not tasks in
themselves. This document records how each one was incorporated, so the choice is visible instead of
being implied by a URL in a table.

Every source named here is recorded in `upstream/sources.yaml` with a canonical URL, an edition, a
licence, a support status, and the date it was checked. `controls/mappings/standards.yaml` cites the
frameworks used by control mappings, and a test enforces that no mapping cites a standard this
repository has not recorded.

## The distinction that matters

| State | Meaning |
| --- | --- |
| `related_risk` | The standard describes the risk area this control addresses. It is **not** a claim of conformance and not verified coverage. |
| precise requirement ID | An ID was checked against the pinned edition. Still `related_risk` unless the control's acceptance criteria were actually assessed against the requirement. |
| `verified_coverage` | The requirement was assessed. **No mapping uses this state**, because no application has been assessed against ASVS, the Top 10, or any other standard. The catalogue describes intended coverage, not demonstrated conformance. |

A linked standard is not a certificate. That warning is stated here because it is the easiest thing
for a reader to get wrong.

## Standards used by v1 controls

| Standard | Edition | Used for |
| --- | --- | --- |
| OWASP ASVS | 5.0.0 (5.0.1 next) | Chapter-level references for authentication, authorization, input handling, logging, and deployment controls |
| OWASP Top 10 | 2025 | Risk labels: broken access control, supply-chain failures, vulnerable components, secrets management |
| OWASP API Security Top 10 | 2023 | Object, property, and function authorization; resource consumption; business-flow abuse |
| OWASP Cheat Sheets | living, cited per page | Recipe references: secrets management, AI secure coding, authorization regression testing |
| OWASP WSTG | 4.2 | Business-logic and authorization testing guidance |
| NIST SSDF | 1.1 (1.2 is a draft) | Process framing for secure development and vulnerability response |
| OpenSSF OSPS Baseline | v2026.08.28 | Repository, access, governance, build, and release practices applied to this repository itself |
| MVSP | current | Business and operational baseline: reporting, incident handling, access, subprocessors, recovery |
| RFC 9700 | RFC 9700 | OAuth and OIDC security practice for the reference stack's authentication flows |
| ASD Secure by Design | current | Lifecycle responsibilities, relevant to Australian procurement and customers |

## Standards recorded but deliberately not mapped

`controls/mappings/standards.yaml` lists these under `not_referenced` with a reason. They are real
sources, recorded with their licences, and the gap is explicit rather than hidden:

- **SLSA 1.2** — roadmap. v1 records source and build identity; it does not claim a SLSA level, and a
  signed artifact alone would not establish one.
- **OWASP AISVS** — runtime AI is excluded from the v1 profiles. The repository has no published
  release, so no stable edition can be pinned either.
- **OWASP LLM Top 10, Agentic Top 10, MCP Top 10** — conditional taxonomies for applications this
  release does not support. MCP Top 10 also carries a **non-commercial share-alike** licence, which is
  the reason nothing is adapted from it and only a link is recorded.
- **OWASP MASVS, Electron security** — future mobile and desktop profiles. No support is claimed.

## Candidate tools: what was adopted and what was not

The blueprint's tools table is a list of candidates. The plan fixes the v1 selection, so most of the
table is recorded as reviewed-but-not-adopted rather than integrated:

| Adopted in v1 | Recorded candidate, not adopted | Why not adopted |
| --- | --- | --- |
| Gitleaks (secrets) | TruffleHog | Optional deeper scanner; **AGPL-3.0** with network-use terms needs its own review |
| Opengrep (static analysis) | CodeQL | Named as an alternative, not an addition; adopting it means publishing tested language/rule coverage |
| OSV-Scanner (dependencies) | Dependabot / Renovate | Updater configuration is Step 16 work |
| zizmor (workflows) | harden-runner | Supplementary egress monitoring, not a substitute for workflow analysis |
| — | OpenSSF Scorecard | A posture signal; a score is not evidence that a setting is enforced |
| — | Syft, Grype, Checkov | Container/IaC artifact work, which is explicitly a later release |
| — | Claude Code security review / Codex Security | Review-candidate generators with access, cost, and data-handling questions; they cannot satisfy a check |
| — | Comparison checklists (vibe-check, preflight-checks, and similar) | Read for comparison; ideas are reviewed, text is not copied |

Adopting every listed tool would be the opposite of the blueprint's own instruction to keep a small
toolchain — and an adapter that exists but has never detected anything is worse than an honest gap.
Each not-adopted entry names what adoption would require.

## How this is checked

`tests/domain/standards.test.ts` asserts that:

- every framework named in a control mapping has a recorded edition with a source URL;
- every mapping is `related_risk`, and nothing claims `verified_coverage`;
- every standard recorded in the mappings file has a matching source record with a licence;
- the standards named in the blueprint are all recorded, either as used or as deliberately not
  referenced with a reason;
- the runtime-AI and mobile/desktop standards are recorded as outside v1 scope and no v1 control
  references them.

Source URLs, licences, and titles were fetched and checked on 2026-10-07; per-entry provenance is in
`upstream/sources.yaml`. Where a check was not performed — for example, the numbered ASVS edition
against the repository's moving `latest` release tag — the entry says so.
