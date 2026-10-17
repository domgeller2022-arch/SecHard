import { describe, expect, it } from 'vitest';
import {
  NOW,
  allPassing,
  catalogue,
  coreProfile,
  evaluateWith,
  exceptionFor,
  manifest,
  manualEvidence,
  policy,
  planFor,
  referenceProfile,
  resultIndexForControl,
} from '../helpers/fixtures.js';
import { evaluate } from '../../src/domain/evaluator.js';
import { planIdentity } from '../../src/domain/planner.js';
import type { ApplicabilityRule } from '../../src/domain/applicability.js';
import type { CheckResult, ExceptionRecord, ExecutionPlan, ManualEvidence } from '../../src/domain/types.js';

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((item) => item.code);

/**
 * These cases are the failures a hardening gate must survive: missing results, wrong identity,
 * stale data, expired waivers, and configuration that tries to remove required work.
 */
describe('the gate blocks on incomplete required work', () => {
  it('blocks a single missing required check even when everything else passes', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).filter((result) => result.check_id !== plan.expected_checks[0]!.check_id);
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('check.missing');
  });

  it('blocks an empty result set entirely', () => {
    const plan = planFor('pr');
    const decision = evaluateWith({ plan, results: [] });
    expect(decision.satisfied).toBe(false);
    // Tool checks report check.missing; the planner's manual companions (F-03) report
    // manual.missing — nothing is silently absent either way.
    const executed = plan.expected_checks.filter((check) => check.execution?.mode !== 'manual');
    expect(codes(decision.reasons).filter((code) => code === 'check.missing')).toHaveLength(executed.length);
    expect(codes(decision.reasons).filter((code) => code === 'manual.missing').length).toBeGreaterThan(0);
  });

  it('reports a missing required check as unmet for its control', () => {
    const plan = planFor('pr');
    const removed = plan.expected_checks[0]!;
    const results = allPassing(plan).filter((result) => result.check_id !== removed.check_id);
    const decision = evaluateWith({ plan, results });
    const outcome = decision.control_outcomes.find((item) => item.control === removed.control_ids[0]);
    expect(outcome?.outcome).toBe('unmet');
  });
});

describe('the gate blocks well-formed evidence for the wrong thing', () => {
  it('blocks a full pass produced for a different source commit', () => {
    const plan = planFor('pr');
    const results: CheckResult[] = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, source_commit: '1111111111111111111111111111111111111111' },
    }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    // Only executed checks can carry a mismatched identity; manual companions (F-03) have no
    // result to mismatch.
    const executed = plan.expected_checks.filter((check) => check.execution?.mode !== 'manual');
    expect(codes(decision.reasons).filter((code) => code === 'identity.source_mismatch')).toHaveLength(executed.length);
  });

  it('blocks a full pass produced under a different policy commit', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, policy_commit: '2222222222222222222222222222222222222222' },
    }));
    expect(codes(evaluateWith({ plan, results }).reasons)).toContain('identity.policy_mismatch');
  });

  it('blocks results replayed against a plan they were not produced for', () => {
    const original = planFor('pr');
    const results = allPassing(original);

    const otherRun = planFor('pr');
    const replayed: ExecutionPlan = {
      ...otherRun,
      plan_id: 'different-plan',
      inputs: { ...otherRun.inputs, profiles: ['core'] },
    };
    const decision = evaluateWith({ plan: replayed, results, expectedPlanIdentity: 'stale-identity' });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('plan.identity_mismatch');
  });
});

describe('an expired or changed exception does not hide the issue', () => {
  it('blocks when the only waiver has expired', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0
        ? { ...result, findings: [{ id: 'f-critical', tool: 'opengrep', rule_id: 'sqli', severity: 'critical' as const }] }
        : result,
    );
    const expired: ExceptionRecord = {
      schema_version: 'exception/v1',
      id: 'EXC-0007',
      status: 'active',
      scope: { control: 'CODE-01', finding_id: 'f-critical' },
      reason: 'accepted for a recorded reason',
      risk: 'residual risk recorded',
      compensating_measures: ['none yet'],
      owner: 'maintainer',
      approver: 'maintainer',
      expires_at: '2026-09-01T00:00:00Z',
    };

    const decision = evaluateWith({ plan, results, exceptions: [expired] });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('exception.invalid');
    expect(codes(decision.reasons)).toContain('finding.blocking');
  });

  it('blocks when a waiver is scoped to a different finding than the one present', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0
        ? { ...result, findings: [{ id: 'f-new', tool: 'opengrep', rule_id: 'sqli', severity: 'critical' as const }] }
        : result,
    );
    const waiver: ExceptionRecord = {
      schema_version: 'exception/v1',
      id: 'EXC-0008',
      status: 'active',
      scope: { control: 'CODE-01', finding_id: 'f-old-different' },
      reason: 'accepted for a recorded reason',
      risk: 'residual risk recorded',
      compensating_measures: ['none yet'],
      owner: 'maintainer',
      approver: 'maintainer',
      expires_at: '2026-12-01T00:00:00Z',
    };

    const decision = evaluateWith({ plan, results, exceptions: [waiver] });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('finding.blocking');
  });

  it('still records the waiver when it genuinely applies', () => {
    const plan = planFor('pr');
    const index = resultIndexForControl(plan, 'CODE-01');
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? { ...result, findings: [{ id: 'f-medium', tool: 'opengrep', rule_id: 'weak-crypto', severity: 'medium' as const }] }
        : result,
    );
    const waiver: ExceptionRecord = {
      schema_version: 'exception/v1',
      id: 'EXC-0009',
      status: 'active',
      scope: { control: 'CODE-01', finding_id: 'f-medium' },
      reason: 'accepted for a recorded reason',
      risk: 'residual risk recorded',
      compensating_measures: ['input is not attacker controlled here'],
      owner: 'maintainer',
      approver: 'maintainer',
      expires_at: '2026-12-01T00:00:00Z',
    };
    const decision = evaluateWith({ plan, results, exceptions: [waiver] });
    // The finding is attached to whichever check reported it, so the waived control is the one whose
    // outcome carries the waiver rather than a control named in the record.
    const waived = decision.control_outcomes.find((item) => item.waiver_refs.length > 0);
    expect(waived?.outcome).toBe('waived');
    expect(waived?.waiver_refs).toEqual(['EXC-0009']);
    // The finding itself stays visible: an accepted risk is not a clean pass.
    expect(waived?.reasons.some((item) => item.code === 'waiver.applied' && item.message.includes('remains visible'))).toBe(true);
  });
});

describe('consumer configuration cannot remove required work', () => {
  it('blocks when the plan omits a check the profile requires', () => {
    const full = planFor('pr');
    const expected = full.expected_checks.length;
    const truncated: ExecutionPlan = { ...full, expected_checks: full.expected_checks.slice(0, expected - 5) };

    const decision = evaluateWith({
      plan: truncated,
      results: allPassing(truncated),
      expectedPlanIdentity: planIdentityOf(full),
    });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('plan.identity_mismatch');
  });

  it('blocks when a control is silently dropped from the plan', () => {
    const full = planFor('pr');
    const withoutSecretScan: ExecutionPlan = {
      ...full,
      expected_checks: full.expected_checks.filter((check) => check.method !== 'secret_scan'),
    };
    const decision = evaluateWith({
      plan: withoutSecretScan,
      results: allPassing(withoutSecretScan),
      expectedPlanIdentity: planIdentityOf(full),
    });
    expect(decision.satisfied).toBe(false);
  });

  it('does not let a narrower profile satisfy the reference profile plan', () => {
    const referencePlan = planFor('pr', { profiles: [referenceProfile] });
    const coreResults = allPassing(planFor('pr', { profiles: [coreProfile] }));
    const decision = evaluateWith({
      plan: referencePlan,
      results: coreResults,
      expectedPlanIdentity: planIdentityOf(referencePlan),
    });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('check.missing');
  });
});

describe('a recorded status is a claim, not proof', () => {
  it('ignores a stored pass and evaluates the actual results', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0 ? { ...result, outcome: 'fail' as const } : result,
    );

    const decision = evaluate({
      ...evaluateInputFor(plan),
      results,
      // A consumer asserting everything passes must not change the outcome.
      assessments: plan.expected_checks.map((check) => ({
        control: check.control_ids[0]!,
        definition_version: 1,
        applicability: 'applicable' as const,
        status: 'pass' as const,
        owner: 'maintainer',
        assessed_at: NOW.toISOString(),
      })),
    });

    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('check.not_passed');
  });

  it('ignores a stored not_applicable for a control the manifest says applies', () => {
    const plan = planFor('pr');
    const decision = evaluate({
      ...evaluateInputFor(plan),
      results: allPassing(plan),
      assessments: [
        {
          control: 'AUTHZ-01',
          definition_version: 1,
          applicability: 'not_applicable',
          applicability_reason: 'we said so',
          status: 'not_applicable',
          owner: 'maintainer',
          assessed_at: NOW.toISOString(),
        },
      ],
    });
    // The evaluator computes applicability from the manifest; the record cannot override it, so the
    // real check work still decides AUTHZ-01.
    const outcome = decision.control_outcomes.find((item) => item.control === 'AUTHZ-01');
    expect(outcome?.applicability).toBe('applicable');
  });
});

describe('manual evidence freshness and correspondence', () => {
  it('blocks when a manual record has already expired', () => {
    const plan = planFor('release');
    const expired: ManualEvidence = {
      schema_version: 'manual-evidence/v1',
      id: 'ME-OLD',
      control: 'OPS-02',
      recipe: 'ops/restore-exercise',
      operator: { identity: 'operator' },
      observed_at: '2025-01-01T00:00:00Z',
      target: { environment: 'production' },
      scope_fingerprint: 'fp',
      outcome: 'pass',
      expires_at: '2025-04-01T00:00:00Z',
    };
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      manualEvidence: [expired],
      stage: 'release',
      environment: 'production',
    });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('manual.stale');
  });

  it('blocks when a manual record reports a negative outcome', () => {
    const plan = planFor('release');
    const negative: ManualEvidence = {
      schema_version: 'manual-evidence/v1',
      id: 'ME-NEG',
      control: 'OPS-02',
      recipe: 'ops/restore-exercise',
      operator: { identity: 'operator' },
      observed_at: '2026-10-01T00:00:00Z',
      target: { environment: 'production' },
      scope_fingerprint: 'fp',
      outcome: 'fail',
      expires_at: '2026-11-01T00:00:00Z',
    };
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      manualEvidence: [negative],
      stage: 'release',
      environment: 'production',
    });
    expect(decision.satisfied).toBe(false);
    expect(codes(decision.reasons)).toContain('manual.fail');
  });
});

describe('stage requirements are not interchangeable', () => {
  it('blocks a release built from a dirty tree but allows the same tree at pr', () => {
    const dirtyPlan = planFor('release', { sourceDirty: true });
    const results = allPassing(dirtyPlan).map((result) => ({ ...result, stage: 'release' as const, environment: 'production' as const }));

    expect(evaluateWith({ plan: dirtyPlan, results, stage: 'release', environment: 'production' }).satisfied).toBe(false);

    const prPlan = planFor('pr', { sourceDirty: true });
    const prResults = allPassing(prPlan);
    expect(evaluateWith({ plan: prPlan, results: prResults, stage: 'pr' }).satisfied).toBe(true);
  });

  it('requires an actual tool origin at release but not at operations', () => {
    const releasePlan = planFor('release');
    const fixtureResults = allPassing(releasePlan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
      evidence_origin: 'fixture' as const,
    }));
    const releaseDecision = evaluateWith({ plan: releasePlan, results: fixtureResults, stage: 'release', environment: 'production' });
    expect(codes(releaseDecision.reasons)).toContain('evidence.fixture_origin');
    expect(releaseDecision.satisfied).toBe(false);

    const operationsPlan = planFor('operations');
    const operationsFixture = allPassing(operationsPlan).map((result) => ({
      ...result,
      stage: 'operations' as const,
      evidence_origin: 'fixture' as const,
    }));
    const operationsDecision = evaluateWith({
      plan: operationsPlan,
      results: operationsFixture,
      stage: 'operations',
    });
    expect(codes(operationsDecision.reasons)).not.toContain('evidence.fixture_origin');
  });
});

describe('an unchecked feature does not become a pass', () => {
  it('blocks and reports a gap when an excluded feature is switched on', () => {
    const enabled = manifest({ payments: { state: 'enabled' } });
    const plan = planFor('pr', { manifest: enabled });
    const decision = evaluateWith({ plan, results: allPassing(plan), manifest: enabled });

    expect(decision.satisfied).toBe(false);
    expect(decision.coverage_gaps.some((gap) => gap.includes('payments'))).toBe(true);
    expect(codes(decision.reasons)).toContain('coverage.feature_gap');
    // The obligation is also planned, not merely reported as a gap.
    expect(plan.expected_checks.some((check) => check.control_ids.includes('BIZ-01'))).toBe(true);
  });

  it('does not report a gap for a feature the manifest disables', () => {
    const decision = evaluateWith({ plan: planFor('pr'), results: allPassing(planFor('pr')) });
    expect(decision.coverage_gaps).toEqual([]);
    expect(decision.satisfied).toBe(true);
  });
});

const planIdentityOf = planIdentity;

function evaluateInputFor(plan: ExecutionPlan): Parameters<typeof evaluate>[0] {
  return {
    stage: 'pr',
    environment: 'local',
    manifest: manifest(),
    controls: catalogue.map((control) => ({
      id: control.id,
      definition_version: control.definition_version,
      applicability: control.applicability as ApplicabilityRule,
    })),
    plan,
    results: [],
    manualEvidence: [],
    exceptions: [],
    policy,
    now: NOW,
    planIdentity: planIdentity(plan),
    excludedFeatures: referenceProfile.excluded_features ?? [],
  };
}

describe('manual evidence intervals are per control, not one global number', () => {
  // OPS-02 declares 90 days for its restore exercise; the policy default is 30. A drill performed
  // 60 days ago is therefore current for that control and stale for one that declares 30.
  it('accepts a 60-day-old restore drill because the control allows 90 days', () => {
    const plan = planFor('release');
    const record = manualEvidence({
      id: 'ME-RESTORE',
      control: 'OPS-02',
      recipe: 'ops/restore-exercise',
      observed_at: '2026-08-08T12:00:00Z',
      expires_at: '2026-12-01T00:00:00Z',
      target: { environment: 'production' },
    });
    const decision = evaluateWith({ plan, results: allPassing(plan), manualEvidence: [record], stage: 'release', environment: 'production' });
    const outcome = decision.control_outcomes.find((item) => item.control === 'OPS-02');
    expect(outcome?.outcome).toBe('satisfied');
  });

  it('treats the same age as stale for a control that declares 30 days', () => {
    const plan = planFor('release');
    const record = manualEvidence({
      id: 'ME-CREDENTIALS',
      control: 'SEC-03',
      recipe: 'credentials/inventory',
      observed_at: '2026-08-08T12:00:00Z',
      expires_at: '2026-12-01T00:00:00Z',
      target: { environment: 'production' },
    });
    const decision = evaluateWith({ plan, results: allPassing(plan), manualEvidence: [record], stage: 'release', environment: 'production' });
    const outcome = decision.control_outcomes.find((item) => item.control === 'SEC-03');
    expect(outcome?.outcome).toBe('unmet');
    expect(outcome?.reasons.some((item) => item.code === 'manual.stale')).toBe(true);
  });

  it('is stale beyond the control interval even when the record has not expired', () => {
    const plan = planFor('release');
    const record = manualEvidence({
      id: 'ME-OLD-DRILL',
      control: 'OPS-02',
      recipe: 'ops/restore-exercise',
      observed_at: '2026-01-01T12:00:00Z',
      expires_at: '2027-01-01T00:00:00Z',
      target: { environment: 'production' },
    });
    const decision = evaluateWith({ plan, results: allPassing(plan), manualEvidence: [record], stage: 'release', environment: 'production' });
    expect(decision.reasons.some((item) => item.code === 'manual.stale')).toBe(true);
  });
});

describe('reuse across a source change requires the scope to be pinned', () => {
  it('accepts a record from an older commit that records its configuration fingerprint', () => {
    const plan = planFor('release');
    const record = manualEvidence({
      id: 'ME-CONFIG',
      control: 'DEPLOY-01',
      recipe: 'deploy/production-access',
      observed_at: '2026-10-01T00:00:00Z',
      expires_at: '2026-11-01T00:00:00Z',
      source_commit: 'b'.repeat(40),
      target: { environment: 'production', configuration_fingerprint: 'config-fp-2026-10-01' },
    });
    const decision = evaluateWith({ plan, results: allPassing(plan), manualEvidence: [record], stage: 'release', environment: 'production' });
    const outcome = decision.control_outcomes.find((item) => item.control === 'DEPLOY-01');
    expect(outcome?.outcome).toBe('satisfied');
  });

  it('refuses the same record when it does not say what configuration it observed', () => {
    const plan = planFor('release');
    const record = manualEvidence({
      id: 'ME-NOSCOPE',
      control: 'DEPLOY-01',
      recipe: 'deploy/production-access',
      observed_at: '2026-10-01T00:00:00Z',
      expires_at: '2026-11-01T00:00:00Z',
      source_commit: 'b'.repeat(40),
      target: { environment: 'production' },
    });
    const decision = evaluateWith({ plan, results: allPassing(plan), manualEvidence: [record], stage: 'release', environment: 'production' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'manual.reuse_without_scope')).toBe(true);
  });
});

describe('an exception cannot override a profile that forbids it', () => {
  it('rejects an exception for a never-exceptable control', () => {
    const plan = planFor('release');
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      stage: 'release',
      environment: 'production',
      exceptions: [
        exceptionFor({
          id: 'EXC-9001',
          scope: { control: 'AUTHZ-01', finding_id: 'f1', environment: 'production' },
        }),
      ],
    });
    const reason = decision.reasons.find((item) => item.code === 'exception.invalid');
    expect(reason?.message).toMatch(/not exceptable/);
  });

  it('rejects an exception granted against a different definition version', () => {
    const plan = planFor('release');
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      stage: 'release',
      environment: 'production',
      exceptions: [
        exceptionFor({
          id: 'EXC-9002',
          scope: { control: 'WEB-01', finding_id: 'f1', environment: 'production', control_definition_version: 0 },
        }),
      ],
    });
    const reason = decision.reasons.find((item) => item.code === 'exception.invalid');
    expect(reason?.message).toMatch(/definition version/);
  });

  it('reports a valid exception as a waiver rather than as a pass', () => {
    const plan = planFor('release');
    const index = resultIndexForControl(plan, 'WEB-01');
    const results = allPassing(plan).map((result, i) =>
      i === index ? { ...result, findings: [{ id: 'f-waive', tool: 'manual', rule_id: 'x', severity: 'medium' as const }] } : result,
    );
    const decision = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      // The control also carries a manual requirement at release; it is current here so the only
      // thing between this control and satisfaction is the accepted finding.
      manualEvidence: [manualEvidence({ id: 'ME-WEB-01', control: 'WEB-01', recipe: 'web/manual-boundaries' })],
      exceptions: [exceptionFor({ id: 'EXC-9003', scope: { control: 'WEB-01', finding_id: 'f-waive', environment: 'production' } })],
    });
    const waived = decision.control_outcomes.find((item) => item.waiver_refs.length > 0);
    expect(waived?.outcome).toBe('waived');
    // And it is reported as a waiver, with the self-review recorded rather than hidden.
    expect(waived?.reasons.some((item) => item.message.includes('remains visible'))).toBe(true);
  });
});
