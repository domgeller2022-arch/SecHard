# P0.2 classification check (observed 2026-10-14)

- Live RECIPES handlers (compiled map): 15
- Appendix B3 rows classified in the ledger: 40
- Still without a dispatch handler (observed against the live map): 40
- Live handlers: ['build/client-assets', 'data/migration-inventory', 'gitleaks/files', 'gitleaks/history', 'gitleaks/repository', 'opengrep/rules', 'osv/lockfile', 'quality/dependency-health', 'quality/error-handling', 'quality/repo-hygiene', 'quality/strict-correctness', 'quality/test-quality', 'quality/vibe-tells', 'web/http-requirements', 'zizmor/workflows']
- Ledger-classified missing recipes: ['abuse/resource-limits', 'agent/permissions', 'agent/security-test-suite', 'agent/test-change-review', 'agent/untrusted-context', 'auth/recovery-isolation', 'auth/session-behaviour', 'authorization/ownership', 'authorization/role-and-tenant', 'authorization/security-fields', 'biz/transaction-integrity', 'build/leak-fixture', 'ci/pins', 'ci/toolchain-pins', 'control/validate', 'data/grants-and-policies', 'dependency/install-hook-test', 'dependency/install-scripts', 'dependency/lockfile-policy', 'dependency/pins', 'deploy/environment', 'exception/expiry-drill', 'exception/validate', 'gate/completeness', 'governance/protections', 'manifest/validate', 'ops/redaction', 'quality/complexity', 'quality/dead-code', 'quality/duplication', 'quality/formatting', 'quality/frontend-quality', 'quality/module-structure', 'quality/test-suite', 'quality/type-and-lint', 'release/evidence-assembly', 'release/rollback-drill', 'web/negative-inputs', 'web/oauth-flow', 'web/tls']

Cross-check: every classified missing recipe is genuinely unimplemented in the compiled map,
and every live handler is accounted for.
