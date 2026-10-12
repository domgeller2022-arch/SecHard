import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { validateAgainstSchema, packageRoot } from '../../src/validation/schema.js';
import { loadDocument } from '../../src/validation/loader.js';
import { loadConsumer, loadPolicy } from '../../src/commands/io.js';
import { crossCheck } from '../../src/commands/run.js';
import { allPassing, evaluateWith, planFor } from '../helpers/fixtures.js';
import type { ManualEvidence } from '../../src/domain/types.js';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = join(REPO, 'tests', 'fixtures', 'consumer');
const scratch = mkdtempSync(join(tmpdir(), 'hardening-records-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

let created = 0;

function consumerWith(overrides: {
  assessments?: string;
  manualEvidence?: string;
  exceptions?: string;
}): string {
  created += 1;
  const dir = join(scratch, `consumer-${created}`);
  mkdirSync(join(dir, '.hardening'), { recursive: true });
  cpSync(join(FIXTURE, '.hardening'), join(dir, '.hardening'), { recursive: true });
  if (overrides.assessments !== undefined) writeFileSync(join(dir, '.hardening', 'assessments.yaml'), overrides.assessments, 'utf8');
  if (overrides.manualEvidence !== undefined) writeFileSync(join(dir, '.hardening', 'manual-evidence.yaml'), overrides.manualEvidence, 'utf8');
  if (overrides.exceptions !== undefined) writeFileSync(join(dir, '.hardening', 'exceptions.yaml'), overrides.exceptions, 'utf8');
  return dir;
}

function load(dir: string) {
  const policy = loadPolicy({ appRoot: dir, policyRoot: REPO });
  const consumer = loadConsumer({ appRoot: dir, policyRoot: REPO }, ['core', 'nextjs-supabase']);
  return { policy, consumer };
}

describe('consumer assessment records are validated', () => {
  it('accepts the fixture records', () => {
    const { policy, consumer } = load(consumerWith({}));
    expect(policy.issues).toEqual([]);
    expect(consumer.issues).toEqual([]);
    expect(consumer.value?.assessments).toHaveLength(2);
  });

  it('rejects an assessment written against a different definition version', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 99
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { policy, consumer } = load(dir);
    expect(consumer.issues).toEqual([]);

    const issues = crossCheck(policy.value!, consumer.value!.manifest!, consumer.value!.assessments);
    expect(issues.some((item) => item.code === 'semantic.version_conflict')).toBe(true);
  });

  it('rejects an assessment for a control that does not exist', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: NOPE-99
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    // The schema rejects the forged ID shape before the semantic layer sees it.
    expect(consumer.issues.some((item) => item.code === 'schema.invalid')).toBe(true);
  });

  it('rejects two assessments for the same control', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    assessed_at: "2026-10-01T00:00:00Z"
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues.some((item) => item.code === 'semantic.duplicate_id')).toBe(true);
  });

  it('rejects a not_applicable assessment with no reason', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: not_applicable
    applicability_reason: "short"
    owner: fixture-maintainer
    status: not_applicable
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues.some((item) => item.code === 'semantic.missing_field')).toBe(true);
  });
});

describe('evidence references stay inside the application root', () => {
  it('rejects a traversal reference', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    implementation_refs: ["../../../etc/passwd"]
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues.some((item) => item.code === 'path.outside_root')).toBe(true);
  });

  it('accepts a local reference to evidence that does not exist yet', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    implementation_refs: ["evidence/not-produced-yet.json"]
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues).toEqual([]);
  });

  // A remote reference is a reference. Validation must never fetch it.
  it('accepts a remote reference without fetching it', () => {
    const dir = consumerWith({
      assessments: `assessments:
  - control: CTX-01
    schema_version: assessment/v1
    definition_version: 1
    applicability: applicable
    owner: fixture-maintainer
    status: pending
    evidence_refs: ["https://evidence.example.invalid/report.json"]
    assessed_at: "2026-10-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues).toEqual([]);
  });
});

describe('record freshness', () => {
  it('rejects a manual record that expires before it was observed', () => {
    const dir = consumerWith({
      manualEvidence: `records:
  - id: ME-BAD
    schema_version: manual-evidence/v1
    control: OPS-02
    recipe: ops/restore-exercise
    operator: { identity: operator }
    observed_at: "2026-10-01T00:00:00Z"
    target: { environment: production }
    scope_fingerprint: fp
    outcome: pass
    expires_at: "2026-09-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues.some((item) => item.code === 'semantic.invalid_interval')).toBe(true);
  });

  it('reports an expired record as a warning rather than an unusable record', () => {
    const dir = consumerWith({
      manualEvidence: `records:
  - id: ME-OLD
    schema_version: manual-evidence/v1
    control: OPS-02
    recipe: ops/restore-exercise
    operator: { identity: operator }
    observed_at: "2025-01-01T00:00:00Z"
    target: { environment: production }
    scope_fingerprint: fp
    outcome: pass
    expires_at: "2025-04-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues).toEqual([]);
    expect(consumer.warnings?.some((warning) => warning.includes('ME-OLD'))).toBe(true);
  });

  it('accepts a pending manual record but the gate does not count it as met', () => {
    const dir = consumerWith({
      manualEvidence: `records:
  - id: ME-PENDING
    schema_version: manual-evidence/v1
    control: OPS-02
    recipe: ops/restore-exercise
    operator: { identity: operator }
    observed_at: "2026-10-01T00:00:00Z"
    target: { environment: production }
    scope_fingerprint: fp
    outcome: pending
    expires_at: "2026-11-01T00:00:00Z"
`,
    });
    const { consumer } = load(dir);
    expect(consumer.issues).toEqual([]);

    const plan = planFor('release');
    const record = consumer.value?.manualEvidence[0] as ManualEvidence;
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      manualEvidence: [record],
      stage: 'release',
      environment: 'production',
    });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'manual.pending')).toBe(true);
  });
});

describe('manual requirements are planned and enforced at release, not at pr', () => {
  const manualChecks = (plan: ReturnType<typeof planFor>) => plan.expected_checks.filter((check) => check.execution?.mode === 'manual');

  it('plans a manual requirement for every applicable manual-only control at release', () => {
    const ids = new Set(manualChecks(planFor('release')).flatMap((check) => [...check.control_ids]));
    expect(ids.has('OPS-02')).toBe(true);
    expect(ids.has('OPS-03')).toBe(true);
    expect(ids.has('SEC-03')).toBe(true);
  });

  it('plans the human half at a pull request without blocking on it', () => {
    // F-03: a mixed method carries a manual companion at every stage — the control is never
    // satisfied by the tool half alone — but at pr the companion is not required: an unmet
    // companion reports as awaiting review and the decision does not block because of it.
    const pr = planFor('pr');
    const companions = manualChecks(pr);
    expect(companions.length).toBeGreaterThan(0);
    expect(companions.every((check) => check.required === false)).toBe(true);
    expect(manualChecks(planFor('release')).every((check) => check.required === true)).toBe(true);

    const decision = evaluateWith({ plan: pr, results: allPassing(pr) });
    expect(decision.satisfied).toBe(true);
    const awaiting = decision.control_outcomes.filter(
      (outcome) => outcome.outcome === 'unmet' && outcome.reasons.some((reason) => reason.code === 'manual.missing'),
    );
    expect(awaiting.length).toBeGreaterThan(0);
  });

  it('blocks a release when a required manual record is missing', () => {
    const plan = planFor('release');
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      stage: 'release',
      environment: 'production',
    });
    expect(decision.control_outcomes.find((outcome) => outcome.control === 'OPS-02')?.outcome).toBe('unmet');
    expect(decision.reasons.some((item) => item.code === 'manual.missing')).toBe(true);
  });

  it('satisfies the requirement with a current passing attestation', () => {
    const plan = planFor('release');
    const evidence = manualChecks(plan).map((check, index) => ({
      schema_version: 'manual-evidence/v1' as const,
      id: `ME-${index}`,
      control: check.control_ids[0] as string,
      recipe: check.recipe,
      operator: { identity: 'operator' },
      observed_at: '2026-10-01T00:00:00Z',
      target: { environment: 'local' as const },
      scope_fingerprint: 'fp',
      outcome: 'pass' as const,
      expires_at: '2026-11-01T00:00:00Z',
    }));

    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      manualEvidence: evidence,
      stage: 'release',
      environment: 'production',
    });
    expect(decision.reasons.filter((item) => item.code.startsWith('manual.'))).toEqual([]);
    expect(decision.control_outcomes.find((outcome) => outcome.control === 'OPS-02')?.outcome).toBe('satisfied');
  });
});

describe('templates are usable, not merely illustrative', () => {
  const fill = (text: string): string =>
    text.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_match, name: string) => {
      if (name.includes('COMMIT')) return 'a'.repeat(40);
      if (name.includes('DIGEST')) return 'b'.repeat(64);
      if (name.endsWith('_AT') || name.includes('EXPIRES')) return '2026-10-06T00:00:00Z';
      if (name.includes('VERSION')) return '15.0.0';
      return `value-${name.toLowerCase().replace(/_/g, '-')}`;
    });

  const templates = [
    { file: 'templates/app-manifest.template.yaml', schema: 'app' as const, document: 'single' },
    { file: 'templates/assessments.template.yaml', schema: 'assessment' as const, document: 'assessments' },
    { file: 'templates/manual-evidence.template.yaml', schema: 'manual-evidence' as const, document: 'records' },
    { file: 'templates/exceptions.template.yaml', schema: 'exception' as const, document: 'exceptions' },
  ];

  it('parses as valid YAML before substitution', () => {
    for (const template of templates) {
      const file = join(packageRoot(), template.file);
      expect(loadDocument(file).issues, template.file).toEqual([]);
    }
  });

  it('produces records that validate after placeholder substitution', () => {
    for (const template of templates) {
      const file = join(packageRoot(), template.file);
      const filled = fill(readFileSync(file, 'utf8'));
      const written = join(scratch, `${template.schema}-filled.yaml`);
      writeFileSync(written, filled, 'utf8');

      const loaded = loadDocument(written);
      expect(loaded.issues, template.file).toEqual([]);

      if (template.document === 'single') {
        const result = validateAgainstSchema(template.schema, loaded.data, written);
        expect(result.issues, template.file).toEqual([]);
        continue;
      }

      const records = (loaded.data as Record<string, unknown[]>)[template.document] ?? [];
      expect(records.length, template.file).toBeGreaterThan(0);
      for (const record of records) {
        const result = validateAgainstSchema(template.schema, record, written);
        expect(result.issues, template.file).toEqual([]);
      }
    }
  });
});
