import { describe, expect, it } from 'vitest';
import { explainFinding } from '../../src/audit/explanations.js';
import type { Finding } from '../../src/domain/types.js';

/**
 * Plain-English explanations (Batch U). A rule with a canned explanation must produce one; a rule
 * without one must fall back to an honest generic that names the rule instead of inventing a
 * meaning for it.
 */

const finding = (fields: Partial<Finding>): Finding => ({
  id: 'fixture',
  tool: 'gitleaks',
  rule_id: 'github-pat',
  severity: 'high',
  ...fields,
});

describe('explainFinding', () => {
  it('explains a gitleaks token finding with a fix, an effort, and a prompt', () => {
    const explanation = explainFinding(finding({}));
    expect(explanation.what.length).toBeGreaterThan(40);
    expect(explanation.fix).toContain('Revoke');
    expect(explanation.effort).toBe('S');
    expect(explanation.confidence).toBe('confirmed');
    expect(explanation.prompt).toContain('GitHub token');
    expect(explanation.prompt).toContain('do not weaken');
  });

  it('matches opengrep rules whether or not the namespace is present', () => {
    const bare = explainFinding(finding({ tool: 'opengrep', rule_id: 'no-eval', severity: 'high' }));
    const namespaced = explainFinding(finding({ tool: 'opengrep', rule_id: 'hardening.no-eval', severity: 'high' }));
    expect(bare.what).toContain('eval');
    expect(namespaced.what).toBe(bare.what);
    expect(namespaced.confidence).toBe('likely');
  });

  it('treats any osv advisory id the same way: a dependency with a published advisory', () => {
    const explanation = explainFinding(finding({ tool: 'osv-scanner', rule_id: 'GHSA-abcd-1234-wxyz', severity: 'high' }));
    expect(explanation.what).toContain('dependency');
    expect(explanation.fix).toContain('Upgrade');
  });

  it('explains privileged client-bundle markers as a live credential exposure', () => {
    const explanation = explainFinding(finding({ tool: 'client-asset-inspection', rule_id: 'supabase-secret-key', severity: 'critical' }));
    expect(explanation.what).toContain('public');
    expect(explanation.confidence).toBe('confirmed');
  });

  it('falls back honestly for an unknown rule instead of inventing a meaning', () => {
    const explanation = explainFinding(finding({ tool: 'some-future-scanner', rule_id: 'mystery-rule', severity: 'medium' }));
    expect(explanation.what).toContain('No plain-English explanation is recorded');
    expect(explanation.what).toContain('mystery-rule');
    expect(explanation.prompt).toContain('mystery-rule');
    expect(explanation.confidence).toBe('signal');
  });

  it('names the matched rule in the gitleaks fallback', () => {
    const explanation = explainFinding(finding({ tool: 'gitleaks', rule_id: 'future-token-rule', severity: 'high' }));
    expect(explanation.what).toContain('future-token-rule');
    expect(explanation.confidence).toBe('likely');
  });

  it('keeps the finding location inside the prompt so the paste is actionable', () => {
    const explanation = explainFinding(finding({ location: 'src/config.ts:12', title: 'a token' }));
    expect(explanation.prompt).toContain('src/config.ts:12');
    expect(explanation.prompt).toContain('a token');
  });
});
