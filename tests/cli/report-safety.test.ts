import { describe, expect, it } from 'vitest';
import { buildReport } from '../../src/commands/report.js';
import { makeResult } from '../../src/commands/check.js';
import { consoleSafe, renderMarkdown } from '../../src/commands/run.js';
import { NOW, SOURCE_COMMIT, allPassing, planFor, triageFor } from '../helpers/fixtures.js';
import type { GateDecision } from '../../src/domain/types.js';

/**
 * M1 regression: untrusted finding text reached report.md unescaped and unredacted. The probe is a
 * title that tries to inject an image, raw HTML, and a secret-shaped value.
 */
const SYNTHETIC_TOKEN = `ghp_${'0'.repeat(36)}`;
const HOSTILE_TITLE = `![x](https://attacker.example/p.png) <script>alert(1)</script> ${SYNTHETIC_TOKEN}`;

function reportWithHostileFinding() {
  const plan = planFor('pr');
  const results = allPassing(plan).map((result, index) =>
    index === 0
      ? {
          ...result,
          findings: [
            {
              id: `f|<script>${SYNTHETIC_TOKEN}`,
              tool: 'opengrep',
              rule_id: 'x',
              severity: 'high' as const,
              title: HOSTILE_TITLE,
            },
          ],
        }
      : result,
  );
  const decision: GateDecision = {
    satisfied: false,
    stage: 'pr',
    environment: 'local',
    reasons: [{ code: 'finding.blocking', message: `f1 (high): ${HOSTILE_TITLE}`, severity: 'high' }],
    control_outcomes: [],
    coverage_gaps: [],
    unsupported_scope: [],
  };

  return buildReport({
    decision,
    plan,
    results,
    manualEvidence: [],
    exceptions: [],
    appId: 'demo',
    sourceCommit: SOURCE_COMMIT,
    sourceClean: true,
    policyRepository: 'example/hardening',
    policyCommit: 'f0e1d2c3b4a5968778695a4b3c2d1e0f99887766',
    controlCatalogueDigest: 'b'.repeat(64),
    gatePolicyDigest: 'c'.repeat(64),
    generatedAt: NOW,
    runId: 'run-1',
  });
}

describe('untrusted finding text cannot inject structure or leak values into a report', () => {
  it('neutralises image syntax, raw HTML, and secret-shaped values in Markdown', () => {
    const { evidence, outstanding } = reportWithHostileFinding();
    const markdown = renderMarkdown(evidence, outstanding.length);

    expect(markdown).not.toContain('![x](');
    expect(markdown).not.toContain('<script>');
    expect(markdown).not.toContain(SYNTHETIC_TOKEN);
    // The redaction marker is itself escaped by the Markdown writer, so assert on the word.
    expect(markdown).toContain('REDACTED');
    expect(markdown).toContain('!\\[x\\]');
  });

  it('neutralises nothing silently: the finding is still present and still blocking', () => {
    const { evidence, outstanding } = reportWithHostileFinding();
    const markdown = renderMarkdown(evidence, outstanding.length);
    expect(markdown).toContain('attacker.example');
    expect(outstanding.length).toBe(1);
    expect(evidence.decision.outcome).toBe('blocked');
  });
});

describe('console output cannot carry secrets or forged report lines', () => {
  it('redacts secrets and flattens newlines', () => {
    const hostile = `finding: ${SYNTHETIC_TOKEN}\n  - forged: this looks like a new report line`;
    const safe = consoleSafe(hostile);
    expect(safe).not.toContain(SYNTHETIC_TOKEN);
    expect(safe).not.toContain('\n');
    expect(safe).toContain('[REDACTED]');
  });
});

describe('F-15: every result location is relativized against the audit root at creation', () => {
  it('strips the root from finding locations and scope files, keeps URLs and out-of-root paths, and is idempotent', () => {
    const plan = planFor('pr');
    const check = plan.expected_checks[0]!;
    const root = `/tmp/sechard-f15-unit-${'a1b2'}`;
    const result = makeResult(
      check,
      plan,
      {
        outcome: 'pass',
        coverage: 'complete',
        observed: 2,
        files: [`${root}/lib/a.ts`, 'src/already-relative.ts'],
        findings: [
          { id: 'f1', tool: 'gitleaks', rule_id: 'x', severity: 'high', location: `${root}/app/x.ts` },
          { id: 'f2', tool: 'http', rule_id: 'y', severity: 'low', location: 'https://example.com/route' },
          { id: 'f3', tool: 'opengrep', rule_id: 'z', severity: 'low', location: '/elsewhere/outside.ts' },
          { id: 'f4', tool: 'opengrep', rule_id: 'w', severity: 'low' },
          { id: 'f5', tool: 'opengrep', rule_id: 'v', severity: 'low', location: 'app/relative.ts' },
        ],
      },
      'run-relativize',
      SOURCE_COMMIT,
      NOW,
      NOW,
      root,
    );

    const findings = result.findings ?? [];
    // Under the root: relativized. This is the F-01 root cause — an absolute prefix reads as ''
    // to the console.log scoping rule and held back real findings in audit mode.
    expect(findings[0]!.location).toBe('app/x.ts');
    // A live HTTP finding is a URL, not a path.
    expect(findings[1]!.location).toBe('https://example.com/route');
    // Absolute but outside the root: rare, kept as-is rather than mangled.
    expect(findings[2]!.location).toBe('/elsewhere/outside.ts');
    // Absent stays absent.
    expect(findings[3]).not.toHaveProperty('location');
    // Idempotent: the SARIF writer relativizes again, and must be a no-op.
    expect(findings[4]!.location).toBe('app/relative.ts');
    expect(result.scope!.files).toEqual(['lib/a.ts', 'src/already-relative.ts']);
  });
});

describe('F-02/A-4: recorded false positives stay visible in their own report section', () => {
  it('lists matched and stale triage records, and never silently removes the cleared finding', () => {
    const plan = planFor('pr');
    const digest = 'd'.repeat(64);
    const indexed = allPassing(plan).map((result, index) =>
      index === 0
        ? {
            ...result,
            findings: [
              {
                id: 'f-triaged',
                tool: 'gitleaks',
                rule_id: 'generic-api-key',
                severity: 'high' as const,
                category: 'secret' as const,
                title: 'Committed credential material',
                location: 'src/config.ts:4',
                secret_digest: digest,
              },
            ],
          }
        : result,
    );
    const { evidence, outstanding } = buildReport({
      decision: {
        satisfied: true,
        stage: 'pr',
        environment: 'local',
        reasons: [],
        control_outcomes: [],
        coverage_gaps: [],
        unsupported_scope: [],
      },
      plan,
      results: indexed,
      manualEvidence: [],
      exceptions: [],
      triages: [
        // Matches the finding above: recorded, cleared, and still listed.
        triageFor({ rule_id: 'generic-api-key', file: 'src/config.ts', finding_fingerprint: digest }),
        // A record whose content changed: nothing matches it any more. It is shown as stale, not
        // dropped — the finding it used to clear is back and the record needs review.
        triageFor({ id: 'TRIAGE-STALE', rule_id: 'aws-access-token', file: '.env', finding_fingerprint: '0'.repeat(64) }),
      ],
      appId: 'demo',
      sourceCommit: SOURCE_COMMIT,
      sourceClean: true,
      policyRepository: 'example/hardening',
      policyCommit: 'f0e1d2c3b4a5968778695a4b3c2d1e0f99887766',
      controlCatalogueDigest: 'b'.repeat(64),
      gatePolicyDigest: 'c'.repeat(64),
      generatedAt: NOW,
      runId: 'run-triage',
    });

    const entries = evidence.recorded_false_positives ?? [];
    expect(entries).toHaveLength(2);
    expect(entries.find((entry) => entry.id === 'TRIAGE-TEST-1')?.matched_finding).toBe('f-triaged');
    expect(entries.find((entry) => entry.id === 'TRIAGE-STALE')?.matched_finding).toBeUndefined();

    // The cleared finding is still an outstanding item: clearing is not removal.
    expect(outstanding.some((item) => item.id === 'f-triaged')).toBe(true);

    const markdown = renderMarkdown(evidence, outstanding.length);
    expect(markdown).toContain('## Recorded false positives');
    expect(markdown).toContain('TRIAGE-TEST-1');
    expect(markdown).toContain('reviewer');
    expect(markdown).toContain('Synthetic test value');
    expect(markdown).toContain('content changed since review');
  });
});
