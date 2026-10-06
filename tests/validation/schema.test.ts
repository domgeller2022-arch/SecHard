import { describe, expect, it } from 'vitest';
import { validateAgainstSchema } from '../../src/validation/schema.js';

const app = {
  schema_version: 'app/v1',
  id: 'demo',
  name: 'Demo application',
  stack: {
    kind: 'nextjs-supabase',
    runtime_versions: { node: { version: '24.21.0', support: 'supported' } },
  },
  features: { accounts: { state: 'enabled' }, payments: { state: 'disabled' } },
  environments: [{ name: 'production', kind: 'production', internet_facing: true }],
  profiles: ['core'],
  policy_lock: {
    repository: 'example/hardening',
    commit: 'a'.repeat(40),
    policy_digest: 'b'.repeat(64),
  },
  maintainer: { name: 'demo-maintainer' },
  updated_at: '2026-10-06T00:00:00Z',
};

const control = {
  schema_version: 'control/v1',
  id: 'AUTHZ-01',
  definition_version: 1,
  review_status: 'draft',
  title: 'Enforce resource ownership',
  purpose: 'Private records belong to their owner.',
  applicability: { rule: 'when_feature_enabled', features: ['private_resources'] },
  acceptance: ['Owners can perform permitted operations', 'Other users cannot read private resources'],
  verification: [{ method: 'authorization_test', recipe: 'authorization/ownership', coverage: 'automated' }],
  evidence_requirements: [{ kind: 'check_result', required_origin: 'actual_tool' }],
  limitations: ['Does not cover role or tenant isolation'],
  owner_role: 'application-maintainer',
};

describe('schema validation', () => {
  it('accepts a valid application manifest', () => {
    expect(validateAgainstSchema('app', app)).toEqual({ valid: true, issues: [] });
  });

  it('accepts a valid draft control definition', () => {
    expect(validateAgainstSchema('control', control)).toEqual({ valid: true, issues: [] });
  });

  it('rejects an unknown field', () => {
    const result = validateAgainstSchema('app', { ...app, surprise: true });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.message).join(' ')).toMatch(/unknown property 'surprise'/);
  });

  it('rejects a missing required field', () => {
    const { maintainer: _omitted, ...without } = app;
    const result = validateAgainstSchema('app', without);
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.message).join(' ')).toMatch(/maintainer/);
  });

  it('rejects a bad enum value rather than coercing it', () => {
    const result = validateAgainstSchema('app', {
      ...app,
      features: { accounts: { state: 'yes' } },
    });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.message).join(' ')).toMatch(/enabled/);
  });

  it('rejects a malformed commit identity', () => {
    const result = validateAgainstSchema('app', {
      ...app,
      policy_lock: { ...app.policy_lock, commit: 'abc123' },
    });
    expect(result.valid).toBe(false);
  });

  it('rejects a non-date-time timestamp', () => {
    const result = validateAgainstSchema('app', { ...app, updated_at: 'yesterday' });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.message).join(' ')).toMatch(/date-time/);
  });

  it('does not insert defaults or remove fields', () => {
    const result = validateAgainstSchema('app', app);
    expect(result.valid).toBe(true);
    expect(app.features.payments).toEqual({ state: 'disabled' });
    expect(Object.keys(app)).not.toContain('extensions');
  });

  // A declared status of pass without examined scope is not a pass.
  it('rejects a pass whose coverage is not complete', () => {
    const base = {
      schema_version: 'check-result/v1',
      run_id: 'run-1',
      check_id: 'c1',
      control_ids: ['SEC-01'],
      recipe: 'gitleaks/repository',
      stage: 'pr',
      environment: 'local',
      outcome: 'pass',
      coverage: 'partial',
      started_at: '2026-10-06T00:00:00Z',
      finished_at: '2026-10-06T00:00:10Z',
      identity: { source_commit: 'a'.repeat(40), policy_commit: 'b'.repeat(40) },
      evidence_origin: 'actual_tool',
    };
    expect(validateAgainstSchema('check-result', base).valid).toBe(false);
    expect(validateAgainstSchema('check-result', { ...base, coverage: 'complete' }).valid).toBe(true);
  });

  it('rejects fixture-origin evidence claiming pass', () => {
    const base = {
      schema_version: 'check-result/v1',
      run_id: 'run-1',
      check_id: 'c1',
      control_ids: ['SEC-01'],
      recipe: 'gitleaks/repository',
      stage: 'pr',
      environment: 'local',
      outcome: 'pass',
      coverage: 'complete',
      started_at: '2026-10-06T00:00:00Z',
      finished_at: '2026-10-06T00:00:10Z',
      identity: { source_commit: 'a'.repeat(40), policy_commit: 'b'.repeat(40) },
      evidence_origin: 'fixture',
    };
    const result = validateAgainstSchema('check-result', base);
    expect(result.valid).toBe(false);
  });

  it('rejects owner_reviewed without a recorded reviewer', () => {
    const result = validateAgainstSchema('control', { ...control, review_status: 'owner_reviewed' });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.message).join(' ')).toMatch(/reviewed_by/);
  });

  it('accepts owner_reviewed with a reviewer and date', () => {
    const result = validateAgainstSchema('control', {
      ...control,
      review_status: 'owner_reviewed',
      reviewed_by: 'owner',
      reviewed_at: '2026-10-06T00:00:00Z',
    });
    expect(result.valid).toBe(true);
  });

  it('rejects a forger control ID shape', () => {
    expect(validateAgainstSchema('control', { ...control, id: 'MADE-99' }).valid).toBe(false);
    expect(validateAgainstSchema('control', { ...control, id: 'AUTHZ-1' }).valid).toBe(false);
  });

  it('rejects an exception with an empty scope', () => {
    const base = {
      schema_version: 'exception/v1',
      id: 'EXC-0001',
      scope: {},
      reason: 'accepted for a documented reason',
      risk: 'residual risk is recorded',
      compensating_measures: ['monitoring'],
      owner: 'maintainer',
      approver: 'maintainer',
      expires_at: '2026-12-01T00:00:00Z',
      status: 'active',
    };
    expect(validateAgainstSchema('exception', base).valid).toBe(false);
    expect(validateAgainstSchema('exception', { ...base, scope: { check_id: 'c1' } }).valid).toBe(true);
  });

  it('rejects a not_applicable assessment without a reason', () => {
    const base = {
      schema_version: 'assessment/v1',
      control: 'AUTHZ-01',
      definition_version: 1,
      applicability: 'not_applicable',
      owner: 'maintainer',
      status: 'pending',
      assessed_at: '2026-10-06T00:00:00Z',
    };
    expect(validateAgainstSchema('assessment', base).valid).toBe(false);
    expect(validateAgainstSchema('assessment', { ...base, applicability_reason: 'no private resources' }).valid).toBe(true);
  });

  it('rejects an applicability rule that names no features', () => {
    const result = validateAgainstSchema('control', {
      ...control,
      applicability: { rule: 'when_feature_enabled' },
    });
    expect(result.valid).toBe(false);
  });

  it('reports the field path of an error', () => {
    const result = validateAgainstSchema('app', {
      ...app,
      stack: {
        ...app.stack,
        runtime_versions: { node: { version: '24.21.0', support: 'fine' } },
      },
    });
    expect(result.valid).toBe(false);
    expect(result.issues[0]?.path).toBe('/stack/runtime_versions/node/support');
    expect(result.issues[0]?.code).toBe('schema.invalid');
  });
});
