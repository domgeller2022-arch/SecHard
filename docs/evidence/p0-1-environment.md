# P0.1 environment snapshot (observed 2026-10-14T08:08:00Z)

- OS: macOS 26.3.1 (x86_64)
- Git: git version 2.55.0
- Node: v25.8.2; pnpm: 12.9.1
- Docker: Docker version 29.8.2, build 7fc2dff9bc
- Registry: https://registry.npmjs.org/
- CHANGELOG.md sha256: dc1d9020d2c56030d16a5dea850096550d2b83e5c4f96cfb0bab5a90681fa9fd
- Baseline commit: 3eaaaf6fda873e4ddbde4fb8f23952d85ae9e61e
- Branch: completion/p0-comprehensive; status: 1 modified
- Fetched tools (observed directories):
  - gitleaks/8.30.1
  - gitleaks/v8.30.1
  - opengrep/1.30.0
  - opengrep/v1.30.0
  - osv_scanner/2.6.0
  - osv_scanner/v2.6.0
  - zizmor/1.30.1
  - zizmor/v1.30.1

## Correction — 14 October 2026 (auditor P0 checkpoint review of 1406851)

The original snapshot above recorded the changelog hash `dc1d9020d2c5…` because a governance note
had been inserted into CHANGELOG.md on the (mistaken) reading of the owner's "state that in the
changelog" instruction. The auditor's correction note requires the changelog frozen at the
immutable programme hash. The insertion is removed; CHANGELOG.md now hashes
`858bb9cf8183a40c732d5c9003aca9c2a786b58211ef6b873ff5605ef85bd0bc`. The earlier observation above
stands as a record of that intermediate state; plan authority and progress are recorded in
`docs/completion-ledger.yaml` (decision P0-D-01), not in the changelog.
