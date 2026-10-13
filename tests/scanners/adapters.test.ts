import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { runAdapter, parseGitleaksReport, parseZizmorReport, parseOsvReport, parseOpengrepReport } from '../../src/adapters/index.js';
import { containsCredentialMaterial } from '../../src/adapters/gitleaks.js';
import { resolveTool } from '../../src/execution/registry.js';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURES = join(REPO, 'tests', 'fixtures', 'scanners');
const scratch = mkdtempSync(join(tmpdir(), 'hardening-scanners-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

// The tools are downloaded provisioning artifacts, not committed files. If they are absent this
// suite cannot run, and a skipped test would hide that. Each test asserts the tool is present and
// fails with a clear message if it is not.
for (const name of ['gitleaks', 'zizmor', 'osv_scanner', 'opengrep'] as const) {
  const availability = resolveTool(name);
  if (!availability.available) {
    throw new Error(
      `scanner '${name}' is not available (${availability.reason}: ${availability.message}). ` +
        'Run `node tools/fetch-tools.mjs` to provision the pinned tools before running this suite.',
    );
  }
}

// Synthetic credential material is composed at runtime rather than written as a literal.
// A committed literal is indistinguishable from a leaked secret to a secret scanner, and this
// repository scans itself: a real scan flagged these test files before they were changed. Splitting
// the prefix from the body keeps the test meaningful and removes the false positive at its source.
const SYNTHETIC_GITHUB_TOKEN = ['ghp', 'Qz3vN8pR2mXwL7yK5tJ1aB4cD9eF6gH0iJ2k'].join('_');

describe('gitleaks detects synthetic secrets and accepts the fixed fixture', () => {
  it('finds the synthetic credentials in the vulnerable fixture', async () => {
    const reportPath = join(scratch, 'gitleaks-vulnerable.json');
    const result = await runAdapter(
      {
        name: 'gitleaks',
        args: [
          'dir',
          join(FIXTURES, 'secrets', 'vulnerable.ts'),
          '--report-format', 'json',
          '--report-path', reportPath,
          '--no-banner',
          '--redact',
          '--exit-code', '0',
        ],
        successExitCodes: [0],
      },
      { reportPath, cwd: REPO, intendedScope: [join(FIXTURES, 'secrets', 'vulnerable.ts')] },
    );

    expect(result.ran, result.error).toBe(true);
    const findings = result.outcome?.findings ?? [];
    expect(findings.length).toBeGreaterThanOrEqual(3);
    const rules = findings.map((finding) => finding.rule_id);
    expect(rules).toContain('github-pat');
    expect(rules).toContain('slack-bot-token');
    expect(rules).toContain('private-key');

    // Gitleaks reports no severity; the adapter records unknown so a human must triage.
    expect(findings.every((finding) => finding.severity === 'unknown')).toBe(true);
  });

  it('finds nothing in the fixed fixture', async () => {
    const reportPath = join(scratch, 'gitleaks-fixed.json');
    const result = await runAdapter(
      {
        name: 'gitleaks',
        args: [
          'dir',
          join(FIXTURES, 'secrets', 'fixed.ts'),
          '--report-format', 'json',
          '--report-path', reportPath,
          '--no-banner',
          '--redact',
          '--exit-code', '0',
        ],
        successExitCodes: [0],
      },
      { reportPath, cwd: REPO, intendedScope: [join(FIXTURES, 'secrets', 'fixed.ts')] },
    );

    expect(result.ran, result.error).toBe(true);
    expect(result.outcome?.findings).toEqual([]);
  });

  it('reports partial coverage rather than claiming file-level certainty', async () => {
    const parsed = parseGitleaksReport('[]', { stderr: 'INF scanned ~1083 bytes (1.08 KB) in 89.3ms' });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;
    // Gitleaks does not list scanned files, so the adapter must not claim complete coverage.
    expect(parsed.coverage).toBe('partial');
    expect(parsed.scope.notes).toMatch(/does not list the files|bytes examined/);
  });

  it('redacts any secret material that reaches the parser', () => {
    // A report produced *without* --redact still must not leak through the adapter.
    const unredacted = JSON.stringify([
      {
        RuleID: 'github-pat',
        Description: 'GitHub token',
        File: 'src/config.ts',
        StartLine: 3,
        Secret: SYNTHETIC_GITHUB_TOKEN,
        Match: SYNTHETIC_GITHUB_TOKEN,
      },
    ]);
    expect(containsCredentialMaterial(unredacted)).toBe(true);

    const parsed = parseGitleaksReport(unredacted);
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;
    // The parsed outcome must carry no credential material. The raw report is not retained on the
    // outcome at all: it belongs on disk with a digest, not inside findings that get serialized.
    expect(JSON.stringify(parsed)).not.toContain(SYNTHETIC_GITHUB_TOKEN);
    expect(Object.keys(parsed)).not.toContain('raw');
    expect(parsed.findings[0]?.detail).toMatch(/redacted/);
  });

  it('relativizes absolute file paths and fingerprints against the scan root (dir mode)', () => {
    // Dir mode pointed at an absolute root reports absolute paths in `File` and embeds them in the
    // `Fingerprint`. The adapter mints ids from the root-relative form (F-01/F-15): an id that
    // embeds the auditing host's layout is a leak in every report and unstable across machines.
    const report = JSON.stringify([
      {
        RuleID: 'generic-api-key',
        Description: 'Generic API key',
        File: `${REPO}/examples/app/.env.local`,
        StartLine: 4,
        Fingerprint: `${REPO}/examples/app/.env.local:generic-api-key:4`,
        Secret: 'REDACTED',
      },
    ]);
    const parsed = parseGitleaksReport(report, { appRoot: REPO });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;
    expect(parsed.findings[0]?.location).toBe('examples/app/.env.local:4');
    expect(parsed.findings[0]?.resource).toBe('examples/app/.env.local:generic-api-key:4');
    expect(JSON.stringify(parsed)).not.toContain(REPO);
  });

  it('treats an unreadable report as an error, not an empty clean scan', () => {
    expect(parseGitleaksReport('')).toMatchObject({ error: expect.stringContaining('empty') });
    expect(parseGitleaksReport('{"not":"an array"}')).toMatchObject({ error: expect.stringContaining('not a JSON array') });
    expect(parseGitleaksReport('[{"RuleID":"x"')).toMatchObject({ error: expect.stringContaining('not valid JSON') });
  });
});

describe('zizmor finds workflow problems and accepts the fixed workflow', () => {
  it('finds the dangerous trigger, unpinned action, template injection, and credential persistence', async () => {
    const reportPath = join(scratch, 'zizmor-vulnerable.json');
    const result = await runAdapter(
      {
        name: 'zizmor',
        args: [join(FIXTURES, 'workflows', 'vulnerable.yaml'), '--format', 'json', '--no-progress'],
        successExitCodes: [0, 14],
      },
      { reportPath, cwd: REPO, intendedScope: [join(FIXTURES, 'workflows', 'vulnerable.yaml')] },
    );

    // zizmor emits the report on stdout, so a report file is not written. Parse stdout directly.
    expect(result.ran || result.error?.includes('report was not written')).toBeTruthy();
    const stdoutRun = await runZizmorToStdout(join(FIXTURES, 'workflows', 'vulnerable.yaml'));
    const parsed = parseZizmorReport(stdoutRun.json, { intendedScope: [join(FIXTURES, 'workflows', 'vulnerable.yaml')] });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;

    const idents = parsed.findings.map((finding) => finding.rule_id);
    expect(idents).toContain('dangerous-triggers');
    expect(idents).toContain('unpinned-uses');
    expect(idents).toContain('template-injection');
    expect(parsed.findings.every((finding) => finding.severity !== 'unknown')).toBe(true);
  });

  it('finds nothing in the fixed workflow', async () => {
    const run = await runZizmorToStdout(join(FIXTURES, 'workflows', 'fixed.yaml'));
    const parsed = parseZizmorReport(run.json, { intendedScope: [join(FIXTURES, 'workflows', 'fixed.yaml')] });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;
    expect(parsed.findings).toEqual([]);
    expect(run.exitCode).toBe(0);
  });

  it('treats a truncated report as an error', () => {
    expect(parseZizmorReport('[{"ident":"x"')).toMatchObject({ error: expect.stringContaining('not valid JSON') });
    expect(parseZizmorReport('{}')).toMatchObject({ error: expect.stringContaining('not a JSON array') });
  });
});

describe('osv-scanner finds advisories for a pinned vulnerable dependency', () => {
  it('finds advisories for lodash and groups aliases into one finding per issue', async () => {
    const reportPath = join(scratch, 'osv.json');
    const result = await runAdapter(
      {
        name: 'osv_scanner',
        args: ['scan', 'source', '-L', join(FIXTURES, 'dependencies', 'package-lock.json'), '--format', 'json', '--output-file', reportPath],
        successExitCodes: [0, 1],
      },
      { reportPath, cwd: REPO, intendedScope: [join(FIXTURES, 'dependencies', 'package-lock.json')], timeoutMs: 300_000 },
    );

    expect(result.ran, result.error).toBe(true);
    const findings = result.outcome?.findings ?? [];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.rule_id.startsWith('GHSA-'))).toBe(true);
    expect(findings.every((finding) => finding.resource?.includes('lodash@4.17.15'))).toBe(true);
    // At least one advisory has a CVSS score high enough to map above 'low'.
    expect(findings.some((finding) => finding.severity === 'high' || finding.severity === 'critical' || finding.severity === 'medium')).toBe(true);
    // Coverage is per package and partial unless the caller supplies the lockfile's package count.
    expect(result.outcome?.coverage).toBe('partial');
  }, 300_000);

  it('claims complete coverage only when the lockfile package count matches', () => {
    const report = JSON.stringify({
      results: [
        {
          source: { path: 'package-lock.json', type: 'lockfile' },
          packages: [{ package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' }, groups: [{ ids: ['GHSA-1'], aliases: [], max_severity: '7.5' }] }],
        },
      ],
    });
    const partial = parseOsvReport(report);
    expect('error' in partial).toBe(false);
    if ('error' in partial) return;
    expect(partial.coverage).toBe('partial');
    expect(partial.findings[0]?.severity).toBe('high');

    const complete = parseOsvReport(report, { expectedPackages: 1 });
    if ('error' in complete) return;
    expect(complete.coverage).toBe('complete');
  });

  it('treats a malformed dependency report as an error', () => {
    expect(parseOsvReport('')).toMatchObject({ error: expect.stringContaining('empty') });
    expect(parseOsvReport('{"results":"nope"}')).toMatchObject({ error: expect.stringContaining('not an array') });
  });
});

describe('opengrep detects the vulnerable patterns and accepts the fixed fixture', () => {
  const rules = join(REPO, 'ci', 'configs', 'opengrep-rules', 'hardening-core.yaml');

  it('finds the eval, shell-exec, and innerHTML patterns', async () => {
    const run = await runOpengrep(join(FIXTURES, 'sast', 'vulnerable.ts'), rules);
    const parsed = parseOpengrepReport(run.json, { intendedScope: [join(FIXTURES, 'sast', 'vulnerable.ts')] });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;

    const rules_found = parsed.findings.map((finding) => finding.rule_id);
    expect(rules_found.some((id) => id.endsWith('hardening.no-eval'))).toBe(true);
    expect(rules_found.some((id) => id.endsWith('hardening.child-process-exec-interpolation'))).toBe(true);
    expect(rules_found.some((id) => id.endsWith('hardening.dom-innerhtml-assignment'))).toBe(true);

    const evalFinding = parsed.findings.find((finding) => finding.rule_id.endsWith('no-eval'));
    expect(evalFinding?.severity).toBe('high');
    const htmlFinding = parsed.findings.find((finding) => finding.rule_id.endsWith('innerhtml-assignment'));
    expect(htmlFinding?.severity).toBe('medium');
  });

  it('finds nothing in the fixed fixture', async () => {
    const run = await runOpengrep(join(FIXTURES, 'sast', 'fixed.ts'), rules);
    const parsed = parseOpengrepReport(run.json, { intendedScope: [join(FIXTURES, 'sast', 'fixed.ts')] });
    expect('error' in parsed).toBe(false);
    if ('error' in parsed) return;
    expect(parsed.findings).toEqual([]);
  });

  it('reports a parser error for a truncated report rather than a clean scan', () => {
    expect(parseOpengrepReport('{"results":[')).toMatchObject({ error: expect.stringContaining('not valid JSON') });
  });

  // Batch S rules: each fires on its vulnerable fixture and stays silent on the fixed twin -
  // the API Top 10 SSRF and unsafe-consumption rules, the RFC 9700 implicit-grant rule, and the
  // Electron renderer configuration rules.
  it('finds SSRF, unsafe consumption, implicit-grant, and Electron findings on their fixtures', async () => {
    const cases: readonly { dir: string; vulnerable: readonly string[]; fixed: readonly string[] }[] = [
      {
        dir: 'api',
        vulnerable: ['hardening.ssrf-request-derived-url', 'hardening.api-unvalidated-response-consumption'],
        fixed: [],
      },
      { dir: 'oauth', vulnerable: ['hardening.oauth-implicit-grant'], fixed: [] },
      {
        dir: 'electron',
        vulnerable: ['hardening.electron-node-integration', 'hardening.electron-context-isolation-off', 'hardening.electron-sandbox-off'],
        fixed: [],
      },
    ];
    for (const testCase of cases) {
      for (const variant of ['vulnerable', 'fixed'] as const) {
        const file = join(FIXTURES, testCase.dir, `${variant}.ts`);
        const run = await runOpengrep(file, rules);
        const parsed = parseOpengrepReport(run.json, { intendedScope: [file] });
        expect('error' in parsed, `${testCase.dir}/${variant}`).toBe(false);
        if ('error' in parsed) continue;
        const found = new Set(parsed.findings.map((finding) => finding.rule_id));
        const expected = variant === 'vulnerable' ? testCase.vulnerable : testCase.fixed;
        for (const ruleId of testCase.vulnerable) {
          expect(found.has(ruleId), `${testCase.dir}/${variant}: ${ruleId}`).toBe(expected.includes(ruleId));
        }
      }
    }
  });

  it('surfaces tool-reported errors as parser errors', () => {
    const parsed = parseOpengrepReport(JSON.stringify({ results: [], errors: [{ message: 'timeout on a.ts' }], paths: { scanned: ['a.ts'] } }));
    if ('error' in parsed) return;
    expect(parsed.parserErrors.join(' ')).toMatch(/timeout on a\.ts/);
  });
});

async function runZizmorToStdout(target: string): Promise<{ json: string; exitCode: number | null }> {
  const { runTool } = await import('../../src/execution/registry.js');
  const result = await runTool('zizmor', [target, '--format', 'json', '--no-progress'], { cwd: REPO, timeoutMs: 120_000 });
  if (!result.ran || result.outcome === undefined) {
    throw new Error(`zizmor did not run: ${result.availability.available ? 'unknown' : result.availability.message}`);
  }
  return { json: result.outcome.stdout, exitCode: result.outcome.exitCode };
}

async function runOpengrep(target: string, rules: string): Promise<{ json: string; exitCode: number | null }> {
  const { runTool } = await import('../../src/execution/registry.js');
  const result = await runTool(
    'opengrep',
    ['scan', '--config', rules, '--json', '--quiet', target],
    { cwd: REPO, timeoutMs: 300_000 },
  );
  if (!result.ran || result.outcome === undefined) {
    throw new Error(`opengrep did not run: ${result.availability.available ? 'unknown' : result.availability.message}`);
  }
  // opengrep writes the JSON report to stdout; the diagnostic summary goes to stderr.
  return { json: result.outcome.stdout, exitCode: result.outcome.exitCode };
}

void writeFileSync;
