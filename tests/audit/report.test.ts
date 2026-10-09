import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
// ajv-formats is CommonJS; the callable lives on .default under NodeNext resolution.
import formatsPlugin from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { buildAuditReport, type AuditReportInput } from '../../src/audit/report.js';
import type { Detection } from '../../src/audit/detect.js';
import type { CheckResult, ExecutionPlan, GateDecision, ReleaseEvidence, Severity } from '../../src/domain/types.js';

/**
 * The audit report (Batch U, remediation-plan A3 plus gap items D5 and D9's reporting half).
 *
 * The properties that must hold for every input:
 * - the same evaluation drives every format; scores and orderings agree across md/html/json;
 * - untrusted text is redacted and structurally escaped in Markdown and HTML;
 * - SARIF validates against the vendored 2.1.0 schema, carries no snippets, and leaks no absolute
 *   local paths;
 * - quality can never change the security verdict and vice versa.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const detection: Detection = {
  stack: { kind: 'react-spa', evidence: [{ file: 'package.json', detail: 'declares a dependency on vite' }] },
  languages: { typescript: 10, javascript: 2 },
  profiles: [
    { id: 'core', evidence: [{ file: '.', detail: 'the core profile applies to every audited application' }] },
    { id: 'react-spa', evidence: [{ file: 'package.json', detail: 'declares a dependency on vite' }] },
  ],
  features: { runtime_ai: { state: 'enabled', evidence: [{ file: 'src/ai.ts', detail: 'imports the OpenAI SDK' }] } },
  gaps: ['no GitHub workflows detected; workflow analysis will report nothing to scan'],
};

const plan = {
  schema_version: 'execution-plan/v1',
  plan_id: 'audit-test',
  run_id: 'audit-test',
  attempt: 1,
  stage: 'pr',
  environment: 'local',
  created_at: '2026-10-09T00:00:00.000Z',
  policy_identity: { commit: '0'.repeat(40), control_catalogue_digest: '0'.repeat(64), gate_policy_digest: '0'.repeat(64), profile_digests: {} },
  inputs: { app_id: 'fixture', source_commit: '0'.repeat(40), source_dirty: false, profiles: ['core'] },
  expected_checks: [
    { check_id: 'SEC-01:secret_scan:gitleaks/repository:pr', control_ids: ['SEC-01'], method: 'secret_scan', recipe: 'gitleaks/repository', stage: 'pr', environment: 'local', required: true, identity: { source_commit: '0'.repeat(40), policy_commit: '0'.repeat(40), run_id: 'audit-test', attempt: 1 }, expected_scope: {}, required_coverage: 'partial' },
    { check_id: 'OPS-02:manual_attestation:ops/restore-exercise:pr', control_ids: ['OPS-02'], method: 'manual_attestation', recipe: 'ops/restore-exercise', stage: 'pr', environment: 'local', required: true, identity: { source_commit: '0'.repeat(40), policy_commit: '0'.repeat(40), run_id: 'audit-test', attempt: 1 }, expected_scope: {}, execution: { mode: 'manual' }, required_coverage: 'partial' },
  ],
} as unknown as ExecutionPlan;

const decision: GateDecision = {
  satisfied: false,
  stage: 'pr',
  environment: 'local',
  reasons: [{ code: 'check.missing', message: 'no result was produced for required check ops/restore-exercise' }],
  control_outcomes: [
    { control: 'SEC-01', definition_version: 2, applicability: 'applicable', outcome: 'unmet', coverage: 'partial', required_checks: [], satisfied_checks: [], reasons: [], waiver_refs: [] },
  ],
  coverage_gaps: [],
  unsupported_scope: [],
};

const evidence = {} as ReleaseEvidence;

function resultFor(recipe: string, findings: readonly { id: string; rule: string; severity: Severity; tool: string; title: string; location: string }[]): CheckResult {
  return {
    schema_version: 'check-result/v1',
    run_id: 'audit-test',
    check_id: `${recipe}:pr`,
    control_ids: ['SEC-01'],
    recipe,
    stage: 'pr',
    environment: 'local',
    required: true,
    outcome: 'pass',
    coverage: 'partial',
    tool: { name: 'fixture' },
    identity: { source_commit: '0'.repeat(40), policy_commit: '0'.repeat(40), run_id: 'audit-test', attempt: 1 },
    started_at: '2026-10-09T00:00:00.000Z',
    finished_at: '2026-10-09T00:00:01.000Z',
    scope: { expected: 1, observed: 1, files: [] },
    findings: findings.map((finding) => ({
      id: finding.id,
      tool: finding.tool,
      rule_id: finding.rule,
      severity: finding.severity,
      title: finding.title,
      location: finding.location,
      control_ids: ['SEC-01'],
      triage: 'unresolved' as const,
    })),
    evidence_origin: 'actual_tool',
  };
}

function inputWith(results: readonly CheckResult[], depth: 'quick' | 'standard' | 'deep' = 'standard'): AuditReportInput {
  return {
    target: '/tmp/fixture-app',
    targetName: 'fixture-app',
    detection,
    plan,
    results,
    decision,
    evidence,
    controls: [],
    depth,
    generatedAt: new Date('2026-10-09T00:00:00Z'),
    policyCommit: '0'.repeat(40),
  };
}

describe('audit report scores and priority', () => {
  const results = [
    resultFor('gitleaks/repository', [
      // A synthetic token shape, a Markdown/HTML injection attempt, and a plain finding, in a
      // deliberately unhelpful severity order.
      { id: 'f-low', rule: 'generic-api-key', severity: 'low', tool: 'gitleaks', title: 'low source finding', location: 'src/low.ts' },
      { id: 'f-high-client', rule: 'supabase-secret-key', severity: 'high', tool: 'client-asset-inspection', title: 'privileged key in bundle', location: 'dist/bundle.js' },
      { id: 'f-high-source', rule: 'github-pat', severity: 'high', tool: 'gitleaks', title: 'token in source', location: 'src/token.ts' },
    ]),
  ];

  it('orders "fix these first" by severity, then deployed exposure', () => {
    const report = buildAuditReport(inputWith(results));
    expect(report.fixFirst.map((finding) => finding.id)).toEqual(['f-high-client', 'f-high-source', 'f-low']);
    expect(report.findings[0]?.exposure).toBe('deployed-surface');
  });

  it('computes the security score from the checks that ran and states the coverage caveat', () => {
    const report = buildAuditReport(inputWith(results));
    expect(report.securityScore.score).toBe(100 - 20 - 20 - 3);
    expect(report.securityScore.verdict).toContain('High-severity findings');
    expect(report.markdown).toContain('1 of 1');
    // Quality is never invented: no quality recipe ran, so there is no quality score.
    expect(report.qualityScore.score).toBeNull();
    expect(report.qualityScore.verdict).toContain('Not assessed');
  });

  it('redacts secret-shaped titles in every format', () => {
    const withSecret = [
      resultFor('gitleaks/repository', [
        // Composed at runtime so no secret-shaped literal lives in this test file.
        { id: 'f-secret', rule: 'github-pat', severity: 'high', tool: 'gitleaks', title: `leaked ${['ghp_', 'A'.repeat(36)].join('')} in source`, location: 'src/token.ts' },
      ]),
    ];
    const report = buildAuditReport(inputWith(withSecret));
    expect(report.markdown).not.toContain('ghp_');
    expect(report.html).not.toContain('ghp_');
    expect(report.sarif).not.toContain('ghp_');
    expect(report.json).not.toContain('ghp_');
    // The marker survives (bracket-escaped by the Markdown writer, which is expected).
    expect(report.markdown).toContain('REDACTED');
    expect(report.html).toContain('REDACTED');
  });

  it('structurally escapes untrusted titles in Markdown and HTML', () => {
    const hostile = [
      resultFor('gitleaks/repository', [
        { id: 'f-xss', rule: 'generic-api-key', severity: 'medium', tool: 'gitleaks', title: '![x](https://attacker.invalid/p.png) <script>alert(1)</script>', location: 'src/x.ts' },
      ]),
    ];
    const report = buildAuditReport(inputWith(hostile));
    expect(report.markdown).not.toContain('![x]');
    expect(report.markdown).not.toContain('<script>');
    // In HTML, markdown image syntax is inert text; what must never survive is markup.
    expect(report.html).not.toContain('<script>alert');
    expect(report.html).not.toContain('<img');
  });

  it('lists what could not be checked, including depth and manual obligations', () => {
    const report = buildAuditReport(inputWith(results, 'quick'));
    const text = report.couldNotCheck.join('\n');
    expect(text).toContain('quick mode does not run');
    expect(text).toContain('manual/operational obligations');
    expect(text).toContain('TLS assessment is not part of this audit');
    // The deep-level statement is honest about what deep does not add in this build.
    const deep = buildAuditReport(inputWith(results, 'deep'));
    expect(deep.couldNotCheck.join('\n')).toContain('same set as standard');
  });

  it('includes a ready-to-paste prompt for every finding', () => {
    const report = buildAuditReport(inputWith(results));
    for (const finding of report.findings) {
      expect(finding.prompt).toContain('do not weaken');
      expect(report.markdown).toContain(finding.prompt.slice(0, 40));
    }
  });

  it('states the unsupported-stack gap as a banner when the stack is unsupported', () => {
    const unsupported: Detection = {
      ...detection,
      stack: { kind: 'expo', evidence: [{ file: 'package.json', detail: 'declares a dependency on expo' }] },
      unsupported_stack: { reason: 'the detected stack (expo) has no stack profile in this build', generic_checks: ['secret scan'] },
    };
    const report = buildAuditReport({ ...inputWith(results), detection: unsupported });
    expect(report.markdown).toContain('UNSUPPORTED STACK');
    expect(report.html).toContain('Unsupported stack');
  });
});

describe('SARIF output', () => {
  // The SARIF schema declares itself draft-07 (an OASIS artifact, predating 2020-12), so its
  // meta-schema is registered on the validator explicitly. What is validated is our output
  // against the vendored schema — not a claim about the schema itself.
  const sarifSchema = JSON.parse(readFileSync(join(REPO, 'schemas', 'sarif-2.1.0.schema.json'), 'utf8')) as object;
  const ajv = new Ajv2020({ allErrors: true });
  formatsPlugin.default(ajv);
  ajv.addMetaSchema(JSON.parse(readFileSync(join(REPO, 'node_modules', 'ajv', 'dist', 'refs', 'json-schema-draft-07.json'), 'utf8')) as object);
  const validate = ajv.compile(sarifSchema);

  it('validates against the vendored SARIF 2.1.0 schema', () => {
    const report = buildAuditReport(inputWith([
      resultFor('gitleaks/repository', [
        { id: 'f-1', rule: 'github-pat', severity: 'high', tool: 'gitleaks', title: 'token in source', location: 'src/token.ts:3' },
        { id: 'f-2', rule: 'missing-security-header', severity: 'medium', tool: 'live-http-check', title: 'header absent', location: 'https://example.invalid/' },
      ]),
    ]));
    const parsed = JSON.parse(report.sarif);
    expect(validate(parsed), JSON.stringify(validate.errors)).toBe(true);
  });

  it('maps severities to SARIF levels and keeps URIs relative or remote', () => {
    const report = buildAuditReport(inputWith([
      resultFor('gitleaks/repository', [
        { id: 'f-1', rule: 'github-pat', severity: 'high', tool: 'gitleaks', title: 'token in source', location: 'src/token.ts:3' },
        { id: 'f-2', rule: 'missing-security-header', severity: 'medium', tool: 'live-http-check', title: 'header absent', location: 'https://example.invalid/' },
        { id: 'f-3', rule: 'browser-source-map', severity: 'info', tool: 'client-asset-inspection', title: 'source map shipped', location: '/abs/dist/map.js' },
      ]),
    ]));
    const parsed = JSON.parse(report.sarif) as {
      runs: { results: { level: string; locations: { physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } } }[] }[] }[];
    };
    const results = parsed.runs[0]?.results ?? [];
    expect(results.map((result) => result.level)).toEqual(['error', 'warning', 'note']);
    // A path with a line suffix is percent-encoded so the URI stays a valid uri-reference.
    expect(results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('src/token.ts%3A3');
    expect(results[1]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('https://example.invalid/');
    // An absolute local path becomes relative-with-base rather than a machine path.
    expect(results[2]?.locations[0]?.physicalLocation.artifactLocation.uriBaseId).toBe('AUDITROOT');
    expect(results[2]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('/abs/dist/map.js');
  });

  it('carries no snippets, so a secret finding cannot ship its own secret', () => {
    const report = buildAuditReport(inputWith([
      resultFor('gitleaks/repository', [
        { id: 'f-1', rule: 'github-pat', severity: 'high', tool: 'gitleaks', title: 'token in source', location: 'src/token.ts:3' },
      ]),
    ]));
    expect(report.sarif).not.toContain('snippet');
    expect(report.sarif).not.toContain('region');
  });
});
