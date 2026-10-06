#!/usr/bin/env node
// Builds the Batch A CLI fixtures: a small valid consumer and a set of deliberately invalid ones.
//
// Every fixture is synthetic and clearly labelled. Nothing here is a real credential, and the
// deliberately broken records are used to prove `validate` and `gate` fail rather than to look like
// a passing example.
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..', 'tests', 'fixtures', 'consumer');
rmSync(root, { recursive: true, force: true });

const POLICY_COMMIT = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: resolve(import.meta.dirname, '..'),
  encoding: 'utf8',
}).trim();

const dir = join(root, '.hardening');
mkdirSync(dir, { recursive: true });

const digest = 'b'.repeat(64);

writeFileSync(
  join(dir, 'app.yaml'),
  `# FIXTURE: a small synthetic consumer used to exercise the CLI. Not a real application.
schema_version: app/v1
id: fixture-consumer
name: Fixture consumer
description: Synthetic manifest for CLI verification. Every field here is invented.

stack:
  kind: nextjs-supabase
  runtime_versions:
    node: { version: "24.21.0", support: supported }
  package_manager: { version: "12.9.1", support: supported }

features:
  accounts: { state: enabled }
  private_resources: { state: enabled }
  roles: { state: disabled, notes: "No custom role model in the fixture" }
  tenancy: { state: disabled, notes: "Single-tenant fixture" }
  recovery: { state: enabled }
  payments: { state: disabled, notes: "Excluded by the profile" }
  webhooks: { state: disabled, notes: "Excluded by the profile" }
  uploads: { state: disabled, notes: "Excluded by the profile" }
  outbound_requests: { state: disabled }
  personal_data: { state: disabled }
  runtime_ai: { state: disabled, notes: "Excluded by the profile" }
  hosting: { state: enabled }
  interfaces: { state: enabled }
  environments: { state: enabled }
  persistent_storage: { state: enabled }

data:
  classification: internal

exposed_interfaces:
  - { kind: page, path: "/", auth_required: false, environment: local }
  - { kind: page, path: "/notes", auth_required: true, environment: local }

environments:
  - { name: local, kind: local, internet_facing: false, separated: true }

profiles:
  - nextjs-supabase

policy_lock:
  repository: fixture/hardening
  commit: "${POLICY_COMMIT}"
  policy_digest: "${digest}"
  locked_at: "2026-10-06T00:00:00Z"

maintainer:
  name: fixture-maintainer
  contact: fixture@example.invalid

updated_at: "2026-10-06T00:00:00Z"
`,
  'utf8',
);

writeFileSync(
  join(dir, 'exceptions.yaml'),
  `# FIXTURE: one valid, precisely scoped, unexpired exception and one expired.
exceptions:
  - id: EXC-0001
    schema_version: exception/v1
    status: active
    scope:
      control: WEB-01
      check_id: WEB-01:functional_test:web/negative-inputs:pr
      environment: production
    reason: "Accepted temporarily; the input path is not attacker controlled."
    risk: "Residual risk is a missed negative case until the follow-up lands."
    compensating_measures:
      - "Input validation is covered by a schema check in the meantime."
    owner: fixture-maintainer
    approver: fixture-maintainer
    self_review: true
    expires_at: "2026-12-01T00:00:00Z"
    remediation_ref: "FIXTURE-ONLY no tracker"
`,
  'utf8',
);

writeFileSync(
  join(dir, 'assessments.yaml'),
  `# FIXTURE: consumer assessment records. A recorded status is a claim, never proof.
assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    implementation_refs: []
    owner: fixture-maintainer
    status: pending
    evidence_refs: []
    exception_refs: []
    assessed_at: "2026-10-01T00:00:00Z"

  - control: BIZ-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: not_applicable
    applicability_reason: "No payments or webhooks; the fixture manifest declares both disabled"
    implementation_refs: []
    owner: fixture-maintainer
    status: not_applicable
    assessed_at: "2026-10-01T00:00:00Z"
`,
  'utf8',
);

writeFileSync(
  join(dir, 'manual-evidence.yaml'),
  `# FIXTURE: manual records are operator attestations, not proof. These are synthetic.
schema_version: manual-evidence/v1
records: []
`,
  'utf8',
);

// --- invalid fixtures -----------------------------------------------------------------------

const invalidDir = join(root, 'invalid');
mkdirSync(join(invalidDir, '.hardening'), { recursive: true });

for (const file of ['app.yaml', 'exceptions.yaml', 'manual-evidence.yaml', 'assessments.yaml']) {
  writeFileSync(join(invalidDir, '.hardening', file), 'schema_version: app/v1\nid: broken\n', 'utf8');
}

writeFileSync(
  join(invalidDir, 'unknown-profile.yaml'),
  `# FIXTURE: names a profile that does not exist. Used to prove reference validation fails.
schema_version: app/v1
id: broken-profile
name: Fixture with an unknown profile
stack:
  kind: nextjs-supabase
  runtime_versions:
    node: { version: "24.21.0", support: supported }
features:
  accounts: { state: enabled }
environments:
  - { name: local, kind: local }
profiles:
  - does-not-exist
policy_lock:
  repository: fixture/hardening
  commit: "${POLICY_COMMIT}"
  policy_digest: "${digest}"
maintainer:
  name: fixture-maintainer
updated_at: "2026-10-06T00:00:00Z"
`,
  'utf8',
);

writeFileSync(
  join(invalidDir, 'forged-commit.yaml'),
  `# FIXTURE: pins a policy commit that is not the reviewed one. Used to prove version conflict fails.
schema_version: app/v1
id: broken-lock
name: Fixture with a wrong policy lock
stack:
  kind: nextjs-supabase
  runtime_versions:
    node: { version: "24.21.0", support: supported }
features:
  accounts: { state: enabled }
environments:
  - { name: local, kind: local }
profiles:
  - core
policy_lock:
  repository: fixture/hardening
  commit: "0000000000000000000000000000000000000000"
  policy_digest: "${digest}"
maintainer:
  name: fixture-maintainer
updated_at: "2026-10-06T00:00:00Z"
`,
  'utf8',
);

writeFileSync(
  join(invalidDir, 'duplicate-key.yaml'),
  `# FIXTURE: a duplicate YAML key. Used to prove the loader refuses ambiguous input.
schema_version: app/v1
id: duplicated
name: First value
name: Second value
`,
  'utf8',
);

process.stdout.write(`built fixtures at ${root}\n`);
