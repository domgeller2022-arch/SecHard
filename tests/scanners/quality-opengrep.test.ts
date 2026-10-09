import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseOpengrepReport } from '../../src/adapters/opengrep.js';
import { resolveTool, runTool } from '../../src/execution/registry.js';

/**
 * QUAL-07's rule pack (ci/configs/opengrep-rules/quality-errors.yaml) against the calibration
 * corpus, with the real pinned opengrep binary: every rule fires on its seed in the vibe-coded
 * fixture and stays silent on the clean twin. Adapter unit tests alone do not count — the rule
 * must run through the same reviewed-execution path the recipe uses.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CONFIG = join(REPO, 'ci', 'configs', 'opengrep-rules', 'quality-errors.yaml');
const CORPUS = join(REPO, 'tests', 'corpus');

async function scan(target: string): Promise<readonly { rule: string }[]> {
  const run = await runTool('opengrep', ['scan', '--config', CONFIG, '--json', '--quiet', '--exclude', 'node_modules', '--exclude', '.git', target], { cwd: target, timeoutMs: 120_000 });
  expect(run.ran, 'opengrep must be available (run pnpm run fetch:tools)').toBe(true);
  if (run.outcome === undefined) return [];
  expect(run.outcome.exitCode, run.outcome.stderr.slice(-400)).toBe(0);
  const parsed = parseOpengrepReport(run.outcome.stdout);
  expect('error' in parsed, 'error' in parsed ? parsed.error : '').toBe(false);
  if ('error' in parsed) return [];
  return parsed.findings.map((finding) => ({ rule: finding.rule_id }));
}

describe('the quality error-handling rule pack, with the real opengrep binary', () => {
  it('exists as reviewed configuration with the scoping decision recorded in it', () => {
    expect(existsSync(CONFIG)).toBe(true);
    const config = readFileSync(CONFIG, 'utf8');
    // The production-path scoping for console.log lives in the recipe, and the pack says so:
    // semgrep `paths` filters resolve differently for `.` and absolute targets, so the rule ships
    // unscoped and the reviewed filter is testable code.
    expect(config).toContain('the recipe applies the reviewed directory convention');
    expect(config).toContain('console.log(...)');
    expect(config).not.toContain('paths:');
  });

  it('fires every seeded error-handling rule on the vibe-coded corpus app', async () => {
    const findings = await scan(join(CORPUS, 'vibe-app'));
    const rules = new Set(findings.map((finding) => finding.rule));
    expect(rules.has('hardening.quality-empty-catch'), `findings: ${[...rules].join(', ')}`).toBe(true);
    expect(rules.has('hardening.quality-floating-promise')).toBe(true);
    expect(rules.has('hardening.quality-console-log-production')).toBe(true);
  }, 300_000);

  it('stays silent on the clean twin', async () => {
    const findings = await scan(join(CORPUS, 'clean-twin'));
    expect(findings, JSON.stringify(findings)).toEqual([]);
  }, 300_000);

  it('the pinned opengrep binary resolves and the pack parses through the adapter', async () => {
    const availability = resolveTool('opengrep');
    expect(availability.available).toBe(true);
    const findings = await scan(join(CORPUS, 'vibe-app'));
    expect(findings.length).toBeGreaterThan(0);
  }, 300_000);
});
