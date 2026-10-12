import { describe, expect, it } from 'vitest';
import { annotateSecretFindings, classifySecret, dedupeSecretFindings, splitLocation } from '../../src/evidence/secret-severity.js';
import type { CheckResult, Finding } from '../../src/domain/types.js';

/**
 * F-02 unit tests: the classifier is total, live-versus-test Stripe keys are distinguished, the
 * digest is recorded instead of the value, and the repository/history de-duplication folds the
 * same secret into one finding.
 *
 * All secret-shaped values here are synthetic and composed at runtime from fragments.
 */

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
// A structurally valid, functionally meaningless JWT carrying the role claim the classifier reads.
const jwt = (role: string): string => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.${'a'.repeat(43)}`;
const stripeLive = `sk_live_${'51Hq8xYz3kT' + '4mLpQ9wRz' + '7vNsA2bC'}`;
const stripeTest = `sk_test_${'51Hq8xYz3kT' + '4mLpQ9wRz' + '7vNsA2bC'}`;
const slackToken = `xoxb-${'123456789012-987654321098-' + 'ZzQqWwEeRrTt'}`;
const supabaseSecret = `sb_secret_${'Fq3kP8' + 'zR2mW9tL5xN7vB4cD'}`;
const supabasePublishable = `sb_publishable_${'Fq3kP8' + 'zR2mW9tL5xN7vB4cD'}`;
const awsKeyId = `AKIA${'Q7Z2XW9PLM4NVK8T'}`;

describe('classifySecret: value first, rule id second, high last — never unknown', () => {
  it('classifies privileged and live material critical, with plain-English titles', () => {
    expect(classifySecret('jwt', `SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}`)).toMatchObject({
      severity: 'critical',
    });
    expect(classifySecret('jwt', `const key = "${jwt('service_role')}"`).title).toContain('service-role');
    expect(classifySecret('stripe-access-token', `STRIPE_KEY=${stripeLive}`).severity).toBe('critical');
    expect(classifySecret('generic-api-key', `SUPABASE_SECRET_KEY=${supabaseSecret}`).severity).toBe('critical');
    expect(classifySecret('aws-access-token', `aws_access_key_id = ${awsKeyId}`).severity).toBe('critical');
    expect(classifySecret('generic-api-key', 'DATABASE_URL=postgres://app:hunter2hunter2@db.example.com/app').severity).toBe('critical');
  });

  it('keeps Stripe test keys out of the OpenAI class (sk- must not shadow sk_test_)', () => {
    expect(classifySecret('stripe-access-token', `STRIPE_KEY=${stripeTest}`).severity).toBe('high');
  });

  it('treats publishable and anon material as informational low, not a leak', () => {
    expect(classifySecret('jwt', `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt('anon')}`).severity).toBe('low');
    expect(classifySecret('generic-api-key', supabasePublishable).severity).toBe('low');
  });

  it('classifies other credentials high and is total over rule ids', () => {
    expect(classifySecret('slack-token', `slack=${slackToken}`).severity).toBe('high');
    for (const ruleId of ['jwt', 'generic-api-key', 'stripe-access-token', 'slack-bot-token', 'some-unknown-rule']) {
      const result = classifySecret(ruleId, undefined);
      expect(['critical', 'high', 'low'], ruleId).toContain(result.severity);
      expect(result.title.length, ruleId).toBeGreaterThan(0);
    }
  });

  it('falls back to the rule id when the value cannot be read, treating privileged rules as critical', () => {
    expect(classifySecret('stripe-access-token', undefined).severity).toBe('critical');
    expect(classifySecret('private-key', undefined).severity).toBe('critical');
    expect(classifySecret('generic-api-key', undefined).severity).toBe('high');
  });
});

describe('annotateSecretFindings: total classification and digest instead of value', () => {
  it('sets severity, title, category, and the digest — and never records the value', () => {
    const line = `const key = "${stripeLive}";`;
    const findings = annotateSecretFindings(
      [{ id: 'f1', tool: 'gitleaks', rule_id: 'stripe-access-token', severity: 'unknown', location: 'src/config.ts:4' }],
      () => line,
    );
    const annotated = findings[0]!;
    expect(annotated.severity).toBe('critical');
    expect(annotated.category).toBe('secret');
    expect(annotated.secret_digest).toMatch(/^[0-9a-f]{64}$/);
    // The digest is of the line, not the value; the value itself appears nowhere on the finding.
    expect(JSON.stringify(annotated)).not.toContain(stripeLive);
  });

  it('stays total when the value cannot be read: category still set, severity from the rule', () => {
    const findings = annotateSecretFindings(
      [{ id: 'f2', tool: 'gitleaks', rule_id: 'jwt', severity: 'unknown', location: 'removed.ts:9' }],
      () => undefined,
    );
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.category).toBe('secret');
    expect(findings[0]).not.toHaveProperty('secret_digest');
  });
});

describe('dedupeSecretFindings: the same secret is one finding, annotated, not two rows', () => {
  const resultFor = (recipe: string, findings: Finding[]): CheckResult =>
    ({
      check_id: `${recipe}:${recipe}`,
      recipe,
      findings,
    }) as unknown as CheckResult;

  const repositoryFinding: Finding = {
    id: 'repo-1',
    tool: 'gitleaks',
    rule_id: 'jwt',
    severity: 'critical',
    location: 'lib/supabase.ts:3',
    secret_digest: 'a'.repeat(64),
    detail: 'secret material detected; value redacted',
  };
  const historyDuplicate: Finding = { ...repositoryFinding, id: 'hist-1', commit: 'c0ffee', detail: 'secret material detected; value redacted' };
  const historyOnly: Finding = {
    id: 'hist-2',
    tool: 'gitleaks',
    rule_id: 'stripe-access-token',
    severity: 'critical',
    location: '.env:2',
    secret_digest: 'b'.repeat(64),
    commit: 'c0ffee',
  };

  it('drops the duplicate from history and annotates the kept repository finding', () => {
    const results = dedupeSecretFindings([
      resultFor('gitleaks/repository', [repositoryFinding]),
      resultFor('gitleaks/history', [historyDuplicate, historyOnly]),
    ]);
    const history = results.find((result) => result.recipe === 'gitleaks/history');
    expect(history?.findings?.map((finding) => finding.id)).toEqual(['hist-2']);
    const repository = results.find((result) => result.recipe === 'gitleaks/repository');
    expect(repository?.findings?.[0]?.detail).toContain('also present in committed history');
  });

  it('leaves results alone when there is nothing to fold, and falls back to the line number without a digest', () => {
    const noRepository = dedupeSecretFindings([resultFor('gitleaks/history', [historyOnly])]);
    expect(noRepository[0]?.findings).toEqual([historyOnly]);

    const lineOnly: Finding = { id: 'repo-2', tool: 'gitleaks', rule_id: 'r', severity: 'high', location: 'a.ts:7' };
    const lineOnlyHistory: Finding = { ...lineOnly, id: 'hist-3' };
    const folded = dedupeSecretFindings([resultFor('gitleaks/repository', [lineOnly]), resultFor('gitleaks/history', [lineOnlyHistory])]);
    expect(folded.find((result) => result.recipe === 'gitleaks/history')?.findings).toEqual([]);

    const differentLine: Finding = { ...lineOnlyHistory, location: 'a.ts:8' };
    const kept = dedupeSecretFindings([resultFor('gitleaks/repository', [lineOnly]), resultFor('gitleaks/history', [differentLine])]);
    expect(kept.find((result) => result.recipe === 'gitleaks/history')?.findings).toEqual([differentLine]);
  });
});

describe('splitLocation', () => {
  it('splits file:line and leaves locations without a numeric suffix whole', () => {
    expect(splitLocation('src/a.ts:12')).toEqual({ file: 'src/a.ts', line: 12 });
    expect(splitLocation('.github/workflows/ci.yml')).toEqual({ file: '.github/workflows/ci.yml' });
    expect(splitLocation(undefined)).toBeUndefined();
  });
});
