import { describe, expect, it } from 'vitest';
import {
  NOW,
  POLICY_COMMIT,
  RUN_ID,
  SOURCE_COMMIT,
  allPassing,
  approvalFor,
  catalogue,
  policy,
  coreProfile,
  evaluateWith,
  exceptionFor,
  manifest,
  manualEvidence,
  passingResult,
  planFor,
  referenceProfile,
} from '../helpers/fixtures.js';
import { planIdentity } from '../../src/domain/planner.js';
import { evaluate } from '../../src/domain/evaluator.js';
import type { CheckResult, Finding } from '../../src/domain/types.js';

describe('planning derives the expected work before execution', () => {
  it('produces checks with unique ids', () => {
    const plan = planFor('pr');
    expect(plan.expected_checks.length).toBeGreaterThan(0);
    const ids = plan.expected_checks.map((check) => check.check_id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('records source and policy identity on every check', () => {
    for (const check of planFor('pr').expected_checks) {
      expect(check.identity.source_commit).toBe(SOURCE_COMMIT);
      expect(check.identity.policy_commit).toBe(POLICY_COMMIT);
      expect(check.required_coverage).toBeTruthy();
    }
  });

  it('separates the two secret_scan recipes so neither is lost', () => {
    const ids = planFor('pr').expected_checks.map((check) => check.check_id);
    expect(ids.some((id) => id.includes('gitleaks/repository'))).toBe(true);
    expect(ids.some((id) => id.includes('gitleaks/history'))).toBe(true);
  });

  it('requires a clean source only for release', () => {
    const release = planFor('release', { sourceDirty: true });
    const pr = planFor('pr', { sourceDirty: true });
    expect(release.inputs.source_dirty).toBe(true);
    expect(pr.inputs.source_dirty).toBe(true);
    // The plan records dirtiness; the gate is what turns it into a decision.
    expect(release.expected_checks.every((check) => check.stage === 'release')).toBe(true);
  });

  it('keeps production-only obligations out of an ordinary pr plan', () => {
    const pr = planFor('pr');
    const release = planFor('release');
    expect(pr.expected_checks.some((check) => check.method === 'tls_check')).toBe(false);
    expect(release.expected_checks.some((check) => check.method === 'tls_check')).toBe(true);
  });

  it('plans BIZ-01 when payments are enabled', () => {
    const withPayments = manifest({ payments: { state: 'enabled' } });
    const plan = planFor('pr', { manifest: withPayments });
    expect(plan.expected_checks.some((check) => check.control_ids.includes('BIZ-01'))).toBe(true);
  });

  it('still plans the obligation when the feature is undeclared, so applicability surfaces as unknown', () => {
    const undeclared = manifest({ tenancy: undefined });
    const plan = planFor('pr', { manifest: undeclared });
    expect(plan.expected_checks.some((check) => check.control_ids.includes('AUTHZ-02'))).toBe(true);
  });

  it('produces a stable identity for an unchanged plan', () => {
    const plan = planFor('pr');
    expect(planIdentity(plan)).toBe(planIdentity(planFor('pr')));
  });

  it('changes identity when a required check is removed', () => {
    const full = planFor('pr');
    const trimmed = { ...full, expected_checks: full.expected_checks.slice(1) };
    expect(planIdentity(trimmed)).not.toBe(planIdentity(full));
  });

  it('rejects an unknown stage rather than planning nothing', () => {
    expect(() => planFor('nonsense' as 'pr')).toThrow(/unknown stage/);
  });

  it('gives a core-only application a smaller plan than the reference stack', () => {
    expect(planFor('pr', { profiles: [coreProfile] }).expected_checks.length).toBeLessThan(
      planFor('pr', { profiles: [referenceProfile] }).expected_checks.length,
    );
  });
});

describe('a satisfied decision', () => {
  it('is reached when every planned check genuinely passes', () => {
    const plan = planFor('pr');
    const decision = evaluateWith({ plan, results: allPassing(plan) });
    expect(decision.reasons).toEqual([]);
    expect(decision.satisfied).toBe(true);
  });

  it('keeps stage outcomes distinct', () => {
    const plan = planFor('pr');
    expect(evaluateWith({ plan, results: allPassing(plan), stage: 'pr' }).stage).toBe('pr');
    const release = planFor('release');
    expect(evaluateWith({ plan: release, results: allPassing(release), stage: 'release', environment: 'production' }).stage).toBe('release');
  });
});

describe('missing required work blocks', () => {
  it('blocks when a required check has no result', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).slice(1);
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'check.missing')).toBe(true);
  });

  it('blocks when a result exists for no planned check', () => {
    const plan = planFor('pr');
    const results = [
      ...allPassing(plan),
      passingResult({
        check_id: 'GHOST-01:secret_scan:x:pr',
        control_ids: ['SEC-01'],
        recipe: 'r',
        identity: { source_commit: SOURCE_COMMIT, policy_commit: POLICY_COMMIT, run_id: RUN_ID, attempt: 1 },
      }),
    ];
    const decision = evaluateWith({ plan, results });
    expect(decision.reasons.some((item) => item.code === 'result.unplanned')).toBe(true);
  });

  it('blocks a duplicate result for one check', () => {
    const plan = planFor('pr');
    const results = allPassing(plan);
    const first = results[0]!;
    const decision = evaluateWith({ plan, results: [...results, first] });
    expect(decision.reasons.some((item) => item.code === 'check.duplicate_result')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });

  it('blocks an execution error rather than treating it as a pass', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0 ? { ...result, outcome: 'error' as const, diagnostic: 'tool exited 2' } : result,
    );
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'check.not_passed')).toBe(true);
  });

  it('blocks an unsupported required coverage and reports it as unsupported scope', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0 ? { ...result, outcome: 'unsupported' as const, diagnostic: 'no supported lockfile format' } : result,
    );
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.unsupported_scope.length).toBeGreaterThan(0);
  });

  it('blocks a forged control id in the plan', () => {
    const plan = planFor('pr');
    const forged: typeof plan = {
      ...plan,
      expected_checks: [
        ...plan.expected_checks,
        {
          check_id: 'FAKE-99:secret_scan:x:pr',
          control_ids: ['FAKE-99'],
          method: 'secret_scan',
          recipe: 'r',
          recipe_version: '1',
          stage: 'pr',
          environment: 'local',
          required: true,
          identity: { source_commit: SOURCE_COMMIT, policy_commit: POLICY_COMMIT, run_id: RUN_ID, attempt: 1 },
          expected_scope: { min_files: 1 },
          required_coverage: 'complete',
        },
      ],
    };
    const decision = evaluateWith({ plan: forged, results: allPassing(plan) });
    expect(decision.reasons.some((item) => item.code === 'gate.forged_control')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });

  it('blocks when the plan does not match the plan recomputed from policy', () => {
    const plan = planFor('pr');
    const trimmed = { ...plan, expected_checks: plan.expected_checks.slice(0, -1) };
    const decision = evaluateWith({
      plan: trimmed,
      results: allPassing(trimmed),
      expectedPlanIdentity: planIdentity(plan),
    });
    expect(decision.reasons.some((item) => item.code === 'plan.identity_mismatch')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });
});

describe('zero findings do not pass absent required scope coverage', () => {
  it('blocks a valid zero-finding scan whose examined scope was empty', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({ ...result, scope: { expected: 12, observed: 0, files: [] } }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'scope.incomplete')).toBe(true);
  });

  it('blocks a pass whose coverage is only partial', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) => (index === 0 ? { ...result, coverage: 'partial' as const } : result));
    const decision = evaluateWith({ plan, results });
    expect(decision.reasons.some((item) => item.code === 'coverage.incomplete_pass')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });

  it('accepts the same scan once the expected scope is actually examined', () => {
    const plan = planFor('pr');
    const decision = evaluateWith({ plan, results: allPassing(plan) });
    expect(decision.satisfied).toBe(true);
  });
});

describe('evidence must belong to the exact source, policy, and target', () => {
  it('blocks all-pass evidence produced for a different commit', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, source_commit: '9'.repeat(40) },
    }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'identity.source_mismatch')).toBe(true);
  });

  it('blocks evidence produced under a different policy', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, policy_commit: '8'.repeat(40) },
    }));
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'identity.policy_mismatch')).toBe(true);
  });

  it('blocks evidence produced against a different configuration', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, configuration_digest: '7'.repeat(64) },
    }));
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'identity.configuration_mismatch')).toBe(true);
  });

  it('blocks a release decision produced from a dirty working tree', () => {
    const plan = planFor('release', { sourceDirty: true });
    const decision = evaluateWith({ plan, results: allPassing(plan), stage: 'release', environment: 'production' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'source.dirty')).toBe(true);
  });
});

describe('a result is evidence only for the run it belongs to', () => {
  it('blocks a well-formed report replayed from a different run for the same commit', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, run_id: 'run-previous', attempt: 1 },
    }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'identity.run_mismatch')).toBe(true);
    // The commit still matches; that is exactly why commit matching alone is not enough.
    expect(decision.reasons.some((item) => item.code === 'identity.source_mismatch')).toBe(false);
  });

  it('blocks a result carried over from an earlier attempt in the same run', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({
      ...result,
      identity: { ...result.identity, attempt: 2 },
    }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'identity.attempt_mismatch')).toBe(true);
  });

  it('accepts a result from the expected run and attempt', () => {
    const plan = planFor('pr');
    expect(evaluateWith({ plan, results: allPassing(plan) }).satisfied).toBe(true);
  });
});

describe('freshness', () => {
  const advisoryScanIndex = (plan: ReturnType<typeof planFor>): number =>
    plan.expected_checks.findIndex((check) => check.method === 'dependency_scan');

  it('makes a result stale when the advisory snapshot exceeds the stage limit', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? { ...result, tool: { ...result.tool, advisory_snapshot_at: '2026-09-20T00:00:00Z' } }
        : result,
    );
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(true);
  });

  it('uses the tighter release limit of 24 hours', () => {
    const plan = planFor('release');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? { ...result, stage: 'release' as const, environment: 'production' as const, tool: { ...result.tool, advisory_snapshot_at: '2026-10-05T00:00:00Z' } }
        : result,
    );
    const decision = evaluateWith({ plan, results, stage: 'release', environment: 'production' });
    expect(decision.reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(true);
  });

  it('accepts an advisory snapshot inside the limit', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index ? { ...result, tool: { ...result.tool, advisory_snapshot_at: '2026-10-04T12:00:00Z' } } : result,
    );
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(false);
  });

  it('rejects implausible future evidence rather than treating it as fresh', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({ ...result, finished_at: '2026-10-20T00:00:00Z' }));
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'freshness.future_evidence')).toBe(true);
  });

  it('tolerates a small clock skew', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({ ...result, finished_at: '2026-10-06T12:02:00Z' }));
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.future_evidence')).toBe(false);
  });

  it('rejects an unparsable timestamp', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result) => ({ ...result, started_at: 'yesterday' }));
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.unparsable')).toBe(true);
  });

  // The scanner ran today, but it scanned a database fetched weeks ago. The scan is fresh; the data
  // is not, and a newly recorded scan time must not launder an old database.
  it('treats an old offline advisory database as stale even when the scan just ran', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? {
            ...result,
            finished_at: '2026-10-06T11:59:00Z',
            tool: {
              ...result.tool,
              advisory_mode: 'offline_database' as const,
              advisory_provenance: {
                queried_at: '2026-10-06T11:59:00Z',
                database_id: 'osv-db-2026-09-01',
                database_retrieved_at: '2026-09-01T00:00:00Z',
              },
            },
          }
        : result,
    );
    const decision = evaluateWith({ plan, results });
    expect(decision.satisfied).toBe(false);
    const stale = decision.reasons.find((item) => item.code === 'freshness.advisory_stale');
    expect(stale?.message).toMatch(/database is/);
    expect(stale?.message).toMatch(/scan itself ran/);
  });

  it('accepts an offline database retrieved within the limit', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? {
            ...result,
            tool: {
              ...result.tool,
              advisory_mode: 'offline_database' as const,
              advisory_provenance: { queried_at: '2026-10-06T11:00:00Z', database_retrieved_at: '2026-10-04T00:00:00Z' },
            },
          }
        : result,
    );
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(false);
  });

  it('uses the upstream update time for an offline database when the interface supplies one', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? {
            ...result,
            tool: {
              ...result.tool,
              advisory_mode: 'offline_database' as const,
              advisory_provenance: {
                queried_at: '2026-10-06T11:00:00Z',
                database_retrieved_at: '2026-10-05T00:00:00Z',
                upstream_updated_at: '2026-09-01T00:00:00Z',
              },
            },
          }
        : result,
    );
    // The database was fetched yesterday but its content is a month old: the older indicator governs.
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(true);
  });

  it('measures an online advisory query by the query time', () => {
    const plan = planFor('pr');
    const index = advisoryScanIndex(plan);
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? {
            ...result,
            tool: {
              ...result.tool,
              advisory_mode: 'online_query' as const,
              advisory_provenance: { queried_at: '2026-10-06T11:00:00Z', endpoint: 'https://api.osv.dev' },
            },
          }
        : result,
    );
    expect(evaluateWith({ plan, results }).reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(false);
  });
});

describe('findings block regardless of a friendly label', () => {
  const withFinding = (plan: ReturnType<typeof planFor>, finding: Partial<Finding>) => {
    const results: CheckResult[] = allPassing(plan).map((result, index) =>
      index === 0 ? { ...result, findings: [finding as Finding] } : result,
    );
    return evaluateWith({ plan, results });
  };

  it('blocks an unresolved critical finding', () => {
    const decision = withFinding(planFor('pr'), { id: 'f1', tool: 'gitleaks', rule_id: 'aws-key', severity: 'critical', title: 'AWS key' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'finding.blocking')).toBe(true);
  });

  it('blocks an unresolved high finding', () => {
    expect(withFinding(planFor('pr'), { id: 'f1', tool: 'opengrep', rule_id: 'sqli', severity: 'high' }).satisfied).toBe(false);
  });

  it('does not block a low finding, which stays visible as an outstanding item', () => {
    const decision = withFinding(planFor('pr'), { id: 'f1', tool: 'opengrep', rule_id: 'style', severity: 'low' });
    expect(decision.satisfied).toBe(true);
    expect(decision.reasons).toEqual([]);
  });

  it('requires triage for unknown severity rather than treating it as low', () => {
    const decision = withFinding(planFor('pr'), { id: 'f1', tool: 'osv-scanner', rule_id: 'GHSA-x', severity: 'unknown' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'finding.unknown_severity_untriaged')).toBe(true);
  });

  it('accepts unknown severity once explicitly triaged with a reason', () => {
    const decision = withFinding(planFor('pr'), {
      id: 'f1',
      tool: 'osv-scanner',
      rule_id: 'GHSA-x',
      severity: 'unknown',
      triage: 'false_positive',
      triage_reason: 'Dev-only transitive package, confirmed against the lockfile',
    });
    expect(decision.reasons.some((item) => item.code === 'finding.unknown_severity_untriaged')).toBe(false);
  });

  it('rejects a false-positive label with no stated reason', () => {
    const decision = withFinding(planFor('pr'), {
      id: 'f1',
      tool: 'opengrep',
      rule_id: 'sqli',
      severity: 'high',
      triage: 'false_positive',
    });
    expect(decision.reasons.some((item) => item.code === 'finding.false_positive_unsupported')).toBe(true);
  });

  it('does not block a finding already triaged as fixed', () => {
    const decision = withFinding(planFor('pr'), { id: 'f1', tool: 'opengrep', rule_id: 'sqli', severity: 'critical', triage: 'fixed' });
    expect(decision.satisfied).toBe(true);
  });
});

describe('exceptions are narrow, current, and never erase the failure', () => {
  it('accepts a valid precisely scoped exception and keeps the finding visible', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0
        ? { ...result, findings: [{ id: 'f1', tool: 'opengrep', rule_id: 'sqli', severity: 'medium' as const }] }
        : result,
    );
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f1', environment: 'production' } })],
    });
    const outcome = decision.control_outcomes.find((item) => item.reasons.some((r) => r.code === 'waiver.applied'));
    expect(outcome?.outcome).toBe('waived');
    expect(outcome?.waiver_refs).toEqual(['EXC-0001']);
    expect(outcome?.reasons.some((item) => item.code === 'waiver.applied' && item.message.includes('remains visible'))).toBe(true);
  });

  it('rejects an expired exception and leaves the finding blocking', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) =>
      index === 0 ? { ...result, findings: [{ id: 'f1', tool: 'opengrep', rule_id: 'sqli', severity: 'critical' as const }] } : result,
    );
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ expires_at: '2026-09-01T00:00:00Z', scope: { control: 'SEC-01', finding_id: 'f1' } })],
    });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'exception.invalid')).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'finding.blocking')).toBe(true);
  });

  it('rejects a blanket control-only scope', () => {
    const decision = evaluateWith({
      plan: planFor('pr'),
      results: allPassing(planFor('pr')),
      exceptions: [exceptionFor({ scope: { control: 'SEC-01' } })],
    });
    expect(decision.reasons.some((item) => item.code === 'exception.invalid')).toBe(true);
  });

  it('rejects a revoked exception', () => {
    const decision = evaluateWith({
      plan: planFor('pr'),
      results: allPassing(planFor('pr')),
      exceptions: [exceptionFor({ status: 'revoked' })],
    });
    expect(decision.reasons.some((item) => item.code === 'exception.invalid')).toBe(true);
  });

  it('accepts a precisely scoped exception instead of rejecting it', () => {
    const plan = planFor('pr');
    const decision = evaluateWith({ plan, results: allPassing(plan), exceptions: [exceptionFor()] });
    expect(decision.reasons.some((item) => item.code === 'exception.invalid')).toBe(false);
  });

  // A sole maintainer accepting risk is self-review, not independent review, and must stay labelled.
  it('preserves the self_review flag rather than implying independent approval', () => {
    const selfReviewed = exceptionFor({ self_review: true });
    const independentlyApproved = exceptionFor({ self_review: false });
    expect(selfReviewed.self_review).toBe(true);
    expect(independentlyApproved.self_review).toBe(false);
    expect(exceptionFor().approver).not.toBe('');
  });
});

describe('manual evidence and feature gaps', () => {
  it('blocks a negative manual attestation', () => {
    const plan = planFor('release');
    const decision = evaluateWith({
      plan,
      results: allPassing(plan),
      manualEvidence: [
        manualEvidence({ control: 'OPS-02', recipe: 'ops/restore-exercise', outcome: 'fail' }),
      ],
      stage: 'release',
      environment: 'production',
    });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'manual.fail')).toBe(true);
  });

  it('reports a coverage gap when an excluded feature is enabled', () => {
    const decision = evaluateWith({
      plan: planFor('pr'),
      results: allPassing(planFor('pr')),
      manifest: manifest({ payments: { state: 'enabled' } }),
    });
    expect(decision.coverage_gaps.some((gap) => gap.includes('payments'))).toBe(true);
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'coverage.feature_gap')).toBe(true);
  });

  it('reports no gap for a feature that is explicitly disabled', () => {
    const decision = evaluateWith({ plan: planFor('pr'), results: allPassing(planFor('pr')) });
    expect(decision.coverage_gaps).toEqual([]);
  });

  it('treats an undeclared feature as unknown applicability, not absence', () => {
    const undeclared = manifest({ tenancy: undefined, roles: undefined });
    const plan = planFor('pr', { manifest: undeclared });
    expect(plan.expected_checks.some((check) => check.control_ids.includes('AUTHZ-02'))).toBe(true);

    const decision = evaluateWith({ plan, results: allPassing(plan), manifest: undeclared });
    expect(decision.reasons.some((item) => item.code === 'control.applicability_unknown')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });

  it('blocks fixture-origin evidence from satisfying a real stage', () => {
    const plan = planFor('release');
    const results = allPassing(plan).map((result) => ({ ...result, stage: 'release' as const, environment: 'production' as const, evidence_origin: 'fixture' as const }));
    const decision = evaluateWith({ plan, results, stage: 'release', environment: 'production' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'evidence.fixture_origin')).toBe(true);
  });
});

describe('the evaluator is a pure function', () => {
  it('returns the same decision for the same input and never mutates it', () => {
    const plan = planFor('pr');
    const results = allPassing(plan);
    const before = JSON.stringify({ plan, results });
    const first = evaluateWith({ plan, results });
    const second = evaluateWith({ plan, results });
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(JSON.stringify({ plan, results })).toBe(before);
  });

  it('does not consult the clock directly; the injected time governs freshness', () => {
    const plan = planFor('pr');
    const index = plan.expected_checks.findIndex((check) => check.method === 'dependency_scan');
    const results = allPassing(plan).map((result, i) =>
      i === index ? { ...result, tool: { ...result.tool, advisory_snapshot_at: '2026-10-05T00:00:00Z' } } : result,
    );
    expect(evaluateWith({ plan, results, now: NOW }).satisfied).toBe(true);
    const muchLater = new Date('2026-10-20T12:00:00Z');
    const later = evaluateWith({ plan, results, now: muchLater });
    expect(later.satisfied).toBe(false);
    expect(later.reasons.some((item) => item.code === 'freshness.advisory_stale')).toBe(true);
  });
});

describe('control approval is a release obligation, not a development one', () => {
  // Scenario 1: a draft definition. Development stages may use it; a release may not.
  it('allows draft definitions at pr but blocks the same definitions at release', () => {
    const prPlan = planFor('pr');
    expect(evaluateWith({ plan: prPlan, results: allPassing(prPlan) }).satisfied).toBe(true);

    const releasePlan = planFor('release');
    const releaseResults = allPassing(releasePlan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
    }));
    const decision = evaluateWith({ plan: releasePlan, results: releaseResults, stage: 'release', environment: 'production' });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'policy.control_not_approved')).toBe(true);
  });

  // Scenario 2: a changed definition carrying an old approval.
  it('blocks a release when an approved definition changed after approval', () => {
    const plan = planFor('release');
    const results = allPassing(plan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
    }));

    // Approvals for every applicable control, but one is issued against different content.
    const applicable = [...new Set(plan.expected_checks.flatMap((check) => [...check.control_ids]))];
    const stale = { ...approvalFor('AUTHZ-01'), content_digest: 'f'.repeat(64) };
    const approvals = applicable.map((id) => (id === 'AUTHZ-01' ? stale : approvalFor(id)));

    const decision = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      approvals,
    });
    expect(decision.satisfied).toBe(false);
    const reasonForChanged = decision.reasons.find((item) => item.code === 'policy.approval_invalid');
    expect(reasonForChanged?.message).toMatch(/content digest changed/);
  });

  // Scenario 3: a correctly approved, unchanged definition.
  it('allows a release when every applicable definition is correctly approved and unchanged', () => {
    const plan = planFor('release');
    const results = allPassing(plan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
    }));

    const applicable = [...new Set(plan.expected_checks.flatMap((check) => [...check.control_ids]))];
    const approvals = applicable.map((id) => approvalFor(id));
    // Manual requirements are satisfied by current attestations, one per planned manual recipe.
    const evidence = plan.expected_checks
      .filter((check) => check.execution?.mode === 'manual')
      .map((check, index) =>
        manualEvidence({
          id: `ME-${index}`,
          control: check.control_ids[0] ?? 'CTX-01',
          recipe: check.recipe,
          target: { environment: 'production' },
        }),
      );

    const decision = evaluateWith({
      plan,
      results,
      manualEvidence: evidence,
      stage: 'release',
      environment: 'production',
      approvals,
    });
    expect(decision.reasons.some((item) => item.code.startsWith('policy.'))).toBe(false);
    expect(decision.satisfied).toBe(true);
    // Only applicable controls need approval. BIZ-01 has no plan entries here because payments are
    // disabled, and an inapplicable control must not be required to carry an approval.
    const applied = new Set(applicable);
    expect(decision.approval_states?.filter((state) => applied.has(state.control)).every((state) => state.approved)).toBe(true);
  });

  it('reports owner acceptance as self-review and independent review as not', () => {
    const plan = planFor('release');
    const results = allPassing(plan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
    }));
    const applicable = [...new Set(plan.expected_checks.flatMap((check) => [...check.control_ids]))];

    const byOwner = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      approvals: applicable.map((id) => approvalFor(id, { kind: 'owner' })),
    });
    const independent = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      approvals: applicable.map((id) => approvalFor(id, { kind: 'independent', reviewer: 'external-reviewer' })),
    });

    const applied = new Set(applicable);
    expect(byOwner.approval_states?.filter((state) => applied.has(state.control)).every((state) => state.self_review)).toBe(true);
    expect(independent.approval_states?.filter((state) => applied.has(state.control)).every((state) => state.self_review)).toBe(false);
  });

  it('cannot verify approval without the definitions themselves', () => {
    const plan = planFor('release');
    const results = allPassing(plan).map((result) => ({
      ...result,
      stage: 'release' as const,
      environment: 'production' as const,
    }));

    const decision = evaluate({
      stage: 'release',
      environment: 'production',
      manifest: manifest(),
      controls: catalogue.map((control) => ({
        id: control.id,
        definition_version: control.definition_version,
        applicability: control.applicability as never,
      })),
      plan,
      results,
      manualEvidence: [],
      exceptions: [],
      policy,
      now: NOW,
      planIdentity: planIdentity(plan),
      // controlDefinitions deliberately omitted.
    });

    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'policy.approval_unverifiable')).toBe(true);
  });
});
