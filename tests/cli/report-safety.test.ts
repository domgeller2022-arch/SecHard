import { describe, expect, it } from 'vitest';
import { buildReport } from '../../src/commands/report.js';
import { consoleSafe, renderMarkdown } from '../../src/commands/run.js';
import { NOW, SOURCE_COMMIT, allPassing, planFor } from '../helpers/fixtures.js';
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
