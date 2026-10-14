import { describe, expect, it } from 'vitest';
import {
  allManual,
  allPassing,
  catalogue,
  evaluateWith,
  exceptionFor,
  policy,
  planFor,
  referenceProfile,
  resultIndexForControl,
} from '../helpers/fixtures.js';
import type { CheckResult, ExecutionPlan, Finding } from '../../src/domain/types.js';

/**
 * Regression tests for the three exception defects the 2026-10-08 external audit reproduced.
 *
 * H1: a "never waivable" control could be waived by scoping the exception by rule_id or finding_id,
 *     because the never policy was read from the exception's own scope.control.
 * H2: a valid exception could never let a gate pass, because `waiver.applied` was counted as a
 *     blocking reason.
 * H3: a waiver could be applied over an execution error, which means no answer was produced.
 *
 * Each probe below is the audit's original reproduction, now asserted in the safe direction.
 */

function resultsWithFinding(plan: ExecutionPlan, controlId: string, finding: Finding): CheckResult[] {
  const index = resultIndexForControl(plan, controlId);
  expect(index).toBeGreaterThanOrEqual(0);
  return allPassing(plan).map((result, i) => (i === index ? { ...result, findings: [finding] } : result));
}

const neverControlIn = (plan: ExecutionPlan): string => {
  const candidates = new Set([...policy.control_categories.never_exceptable]);
  for (const entry of referenceProfile.permitted_exceptions) {
    if (entry.policy === 'never') candidates.add(entry.control);
  }
  const control = [...candidates].find((id) => resultIndexForControl(plan, id) >= 0);
  expect(control).toBeDefined();
  return control as string;
};

describe('H1: the never policy resolves from the finding control, not the exception scope', () => {
  it('rejects a rule_id-only scope outright — it cannot be anchored to one item', () => {
    const plan = planFor('pr');
    const control = neverControlIn(plan);
    const results = resultsWithFinding(plan, control, {
      id: 'f-critical',
      tool: 'opengrep',
      rule_id: 'cross-user-read',
      severity: 'critical',
      title: 'cross-user read',
    });
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { rule_id: 'cross-user-read' } })],
    });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'exception.invalid')).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'finding.blocking')).toBe(true);
  });

  it('does not waive a finding on a never control when the exception names an exceptable control', () => {
    const plan = planFor('pr');
    const control = neverControlIn(plan);
    const otherControl = catalogue.find((candidate) => candidate.id !== control && resultIndexForControl(plan, candidate.id) >= 0);
    if (otherControl === undefined) throw new Error('no second check-bearing control in the plan');

    const results = resultsWithFinding(plan, control, {
      id: 'f-critical',
      tool: 'opengrep',
      rule_id: 'cross-user-read',
      severity: 'critical',
      title: 'cross-user read',
    });
    // The scope names a control the finding does not belong to. It must not apply, and it must not
    // launder the never policy through the scope.
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control: otherControl.id, finding_id: 'f-critical', environment: 'production' } })],
    });
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'finding.blocking')).toBe(true);
    expect(decision.satisfied).toBe(false);
  });

  it('reports a forbidden waiver when the scope is precise but the finding control is never exceptable', () => {
    const plan = planFor('pr');
    const control = neverControlIn(plan);
    const results = resultsWithFinding(plan, control, {
      id: 'f-critical',
      tool: 'opengrep',
      rule_id: 'cross-user-read',
      severity: 'critical',
      title: 'cross-user read',
    });
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control, finding_id: 'f-critical', environment: 'production' } })],
    });
    expect(decision.satisfied).toBe(false);
    // Either the structural filter reports it invalid (scope.control case) or the apply-time check
    // reports it forbidden (the union check). Both block; at least one must be present.
    const blocked = decision.reasons.some((item) => item.code === 'exception.invalid' || item.code === 'waiver.forbidden');
    expect(blocked).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
  });

  it('checks every never control against finding-scoped, rule-scoped, and wrong-control scopes', () => {
    const plan = planFor('pr');
    const never = new Set<string>([...policy.control_categories.never_exceptable]);
    for (const entry of referenceProfile.permitted_exceptions) if (entry.policy === 'never') never.add(entry.control);

    for (const control of never) {
      const index = resultIndexForControl(plan, control);
      if (index < 0) continue; // manual-only at this stage: no result can carry a finding

      const finding: Finding = { id: 'f1', tool: 't', rule_id: 'r1', severity: 'high', title: 'x' };
      const results = allPassing(plan).map((result, i) => (i === index ? { ...result, findings: [finding] } : result));
      const shapes = [
        exceptionFor({ scope: { finding_id: 'f1' } }),
        exceptionFor({ scope: { rule_id: 'r1', check_id: plan.expected_checks[index]?.check_id ?? '' } }),
        exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f1', environment: 'production' } }),
      ];
      for (const exception of shapes) {
        const decision = evaluateWith({ plan, results, exceptions: [exception] });
        const waived = decision.control_outcomes.some((outcome) => outcome.waiver_refs.length > 0);
        expect(waived, `${control} was waived by ${JSON.stringify(exception.scope)}`).toBe(false);
        expect(decision.satisfied).toBe(false);
      }
    }
  });
});

describe('H2: a valid waiver is acceptable, while a forbidden one is not', () => {
  it('lets the gate pass when the only outstanding item is a permitted, precisely scoped waiver', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-medium',
      tool: 'opengrep',
      rule_id: 'weak-crypto',
      severity: 'medium',
      title: 'weak crypto',
    });
    const decision = evaluateWith({
      plan,
      results,
      manualEvidence: allManual(plan),
      exceptions: [exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f-medium', environment: 'production' } })],
    });
    expect(decision.control_outcomes.find((item) => item.control === 'SEC-01')?.outcome).toBe('waived');
    expect(decision.satisfied).toBe(true);
  });

  it('never waives a critical finding, even on a permitted control', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-critical',
      tool: 'gitleaks',
      rule_id: 'private-key',
      severity: 'critical',
      title: 'private key in tree',
    });
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f-critical', environment: 'production' } })],
    });
    expect(decision.reasons.some((item) => item.code === 'waiver.forbidden')).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
    expect(decision.satisfied).toBe(false);
  });

  it('requires a non-self approver for a high finding at release', () => {
    const plan = planFor('release');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-high',
      tool: 'opengrep',
      rule_id: 'sqli',
      severity: 'high',
      title: 'sql injection',
    });

    const selfReviewed = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      manualEvidence: allManual(plan),
      exceptions: [
        exceptionFor({ self_review: true, scope: { control: 'SEC-01', finding_id: 'f-high', environment: 'production' } }),
      ],
    });
    expect(selfReviewed.reasons.some((item) => item.code === 'waiver.forbidden')).toBe(true);

    const independentlyApproved = evaluateWith({
      plan,
      results,
      stage: 'release',
      environment: 'production',
      manualEvidence: allManual(plan),
      exceptions: [
        exceptionFor({ self_review: false, approver: 'security-reviewer', scope: { control: 'SEC-01', finding_id: 'f-high', environment: 'production' } }),
      ],
    });
    expect(independentlyApproved.control_outcomes.find((item) => item.control === 'SEC-01')?.outcome).toBe('waived');
    expect(independentlyApproved.reasons.some((item) => item.code === 'waiver.forbidden')).toBe(false);
  });

  it('allows a high finding to be waived outside release without an independent approver', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-high',
      tool: 'opengrep',
      rule_id: 'sqli',
      severity: 'high',
      title: 'sql injection',
    });
    const decision = evaluateWith({
      plan,
      results,
      manualEvidence: allManual(plan),
      exceptions: [exceptionFor({ self_review: true, scope: { control: 'SEC-01', finding_id: 'f-high', environment: 'production' } })],
    });
    expect(decision.control_outcomes.find((item) => item.control === 'SEC-01')?.outcome).toBe('waived');
  });
});

describe('H3: a waiver cannot be applied over a result that produced no answer', () => {
  it('does not waive a finding attached to an errored result', () => {
    const plan = planFor('pr');
    const index = resultIndexForControl(plan, 'SEC-01');
    // The audit probe used a finding the exception covered. Here the result errored, so there is no
    // answer to accept: the error must surface as unmet, not as a waiver.
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? { ...result, outcome: 'error' as const, findings: [{ id: 'f1', tool: 't', rule_id: 'r', severity: 'medium' as const, title: 'x' }] }
        : result,
    );
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f1', environment: 'production' } })],
    });
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
    expect(decision.control_outcomes.find((item) => item.control === 'SEC-01')?.outcome).toBe('unmet');
    expect(decision.satisfied).toBe(false);
  });

  it('does not waive a finding attached to an unsupported result', () => {
    const plan = planFor('pr');
    const index = resultIndexForControl(plan, 'SEC-01');
    const results = allPassing(plan).map((result, i) =>
      i === index
        ? { ...result, outcome: 'unsupported' as const, coverage: 'unknown' as const, findings: [{ id: 'f1', tool: 't', rule_id: 'r', severity: 'medium' as const, title: 'x' }] }
        : result,
    );
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor({ scope: { control: 'SEC-01', finding_id: 'f1', environment: 'production' } })],
    });
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
    expect(decision.satisfied).toBe(false);
  });
});
