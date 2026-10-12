import { describe, expect, it } from 'vitest';
import { allPassing, evaluateWith, exceptionFor, planFor, resultIndexForControl, triageFor } from '../helpers/fixtures.js';
import type { CheckResult, ExecutionPlan, Finding } from '../../src/domain/types.js';

/**
 * The follow-up audit's probe tests, kept permanently (fix brief Appendix B; plan addendum C-2).
 *
 * P7a and P7b guard the exact hole the audit found: an unknown-severity secret finding on SEC-01
 * was waived by a valid exception and the gate passed. The exposure ban must hold through both
 * routes — the `category: secret` marker and the policy's secret-scanner tool list — because a
 * classifier regression that stops setting the marker must not reopen the hole.
 *
 * P10, B1, and M1 land with their owning batches (F-17, F-03) in this same file.
 */

function resultsWithFinding(plan: ExecutionPlan, controlId: string, finding: Finding): CheckResult[] {
  const index = resultIndexForControl(plan, controlId);
  expect(index).toBeGreaterThanOrEqual(0);
  return allPassing(plan).map((result, i) => (i === index ? { ...result, findings: [finding] } : result));
}

// The scope shape a valid exception uses: control + finding_id + environment, as the H2 tests
// established. `expires_at` is current relative to the fixtures' NOW.
const validScopeFor = (findingId: string): Parameters<typeof exceptionFor>[0] => ({
  scope: { control: 'SEC-01', finding_id: findingId, environment: 'production' },
});

describe('P7a: an unknown-severity secret marked by category can never be waived', () => {
  it('refuses the waiver and keeps the finding blocking, with waiver.forbidden', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-secret-unknown',
      // Deliberately NOT a secret-scanner tool: this probe exercises the category marker alone.
      tool: 'opengrep',
      rule_id: 'hardening.test-secret',
      severity: 'unknown',
      category: 'secret',
      title: 'a credential-shaped value',
      triage: 'unresolved',
    });
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor(validScopeFor('f-secret-unknown'))],
    });

    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'waiver.forbidden')).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
  });
});

describe('P7b: a gitleaks finding with no category can never be waived', () => {
  it('refuses the waiver through the secret-scanner tool list, with waiver.forbidden', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', {
      id: 'f-secret-uncategorized',
      // A secret scanner, no `category` field: the classifier has regressed or never ran. The
      // policy's scanner list must still hold the ban.
      tool: 'gitleaks',
      rule_id: 'jwt',
      severity: 'unknown',
      title: 'Uncovered a JSON Web Token',
      triage: 'unresolved',
    });
    const decision = evaluateWith({
      plan,
      results,
      exceptions: [exceptionFor(validScopeFor('f-secret-uncategorized'))],
    });

    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'waiver.forbidden')).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'waiver.applied')).toBe(false);
  });
});

describe('A-4: a reviewed triage record clears a finding; a stale fingerprint reopens it', () => {
  const secretFinding: Finding = {
    id: 'f-secret-abc',
    tool: 'gitleaks',
    rule_id: 'generic-api-key',
    severity: 'high',
    category: 'secret',
    location: 'src/config.ts:4',
    secret_digest: 'd'.repeat(64),
  };

  it('clears the finding as a visible, non-blocking note when the record matches rule, file, and fingerprint', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', secretFinding);
    const decision = evaluateWith({
      plan,
      results,
      triages: [triageFor({ rule_id: 'generic-api-key', file: 'src/config.ts', finding_fingerprint: 'd'.repeat(64) })],
    });
    expect(decision.satisfied).toBe(true);
    expect(decision.reasons.some((item) => item.code === 'finding.false_positive_recorded')).toBe(true);
  });

  it('does not clear the finding when the content changed: the fingerprint no longer matches', () => {
    // The file was edited after the record was written, so the finding's digest changed. The
    // record must stop matching and the finding must return — that is what the fingerprint is for.
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', secretFinding);
    const decision = evaluateWith({
      plan,
      results,
      triages: [triageFor({ rule_id: 'generic-api-key', file: 'src/config.ts', finding_fingerprint: '0'.repeat(64) })],
    });
    expect(decision.satisfied).toBe(false);
    expect(decision.reasons.some((item) => item.code === 'finding.false_positive_recorded')).toBe(false);
  });

  it('does not clear the same rule in a different file', () => {
    const plan = planFor('pr');
    const results = resultsWithFinding(plan, 'SEC-01', secretFinding);
    const decision = evaluateWith({
      plan,
      results,
      triages: [triageFor({ rule_id: 'generic-api-key', file: 'docs/example.md', finding_fingerprint: 'd'.repeat(64) })],
    });
    expect(decision.satisfied).toBe(false);
  });
});
