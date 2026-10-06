# Changelog

All notable changes to this repository. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased sections are added per implementation step (Steps 00–16) and per batch (A–D).
Entries record **what actually changed and was checked**. A step is listed under "Verified" only
when its acceptance checks ran and passed; otherwise it is listed under "Blocked" or
"Awaiting external verification" with the reason.

`0.1.0` is the planned first release version (`first_release_version` in `01-owner-decisions.md`).
Nothing is released yet.

## [Unreleased]

### Added

- **Step 00 — build decisions and preflight.** `docs/architecture.md`, `docs/trust-model.md`,
  `docs/supported-versions.md`, `docs/implementation-progress.md`, `policy/toolchain.yaml`.
  Recorded the host preflight, the Node LTS recheck, verified dependency identities and licences,
  the trust boundary between inspecting files and executing untrusted code, and the deferred
  tool selections for later batches.
- **Step 00 — repository initialised.** Git repository created at `Security Hardening/hardening/`
  with no remote configured. Nothing has been pushed.

### Blocked

- `LICENSE` is absent because `code_licence` and `docs_licence` are still `TODO` in
  `01-owner-decisions.md`. Per plan Step 00 task 6, the file is left uncreated rather than
  invented.
- pnpm 12.9.1 is pinned but not installed; installing runtimes requires
  `agent_may_install_runtimes`, still `TODO`. The "clean install with the pinned package manager"
  acceptance check in Step 01 is therefore not yet executable.

### Known limitations

- 14 further `TODO` fields in `01-owner-decisions.md` are recorded as blockers in
  `docs/implementation-progress.md`.
- No scanner has been integrated or run. No application exists. No external platform verification
  has been performed.
