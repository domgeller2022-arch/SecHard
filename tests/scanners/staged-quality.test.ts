import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { analyzeComplexity, analyzeDeadCode, analyzeDuplication, analyzeModuleStructure, resolveStagedTool, type StagedAnalysis, type StagedTool, type StagedUnsupported } from '../../src/quality/staged.js';

/**
 * The four staged quality analysers (P4.2 — F-07) against the corpus fixture with the real
 * provisioned tools. Each analyser finds its corpus positive, keeps the clean twins clean, and —
 * the execution-safety contract (plan item 5) — leaves the audited tree byte-identical while a
 * hostile target configuration, demonstrably executable in an isolated validation step, is never
 * loaded during the ordinary scan.
 *
 * This suite needs the provisioned quality tools (`tools/quality`: the frozen npm install and
 * the Lizard virtual environment), exactly like the other scanner acceptance tests. It is
 * skipped — visibly — where they are absent; the corpus seed gate (measure-corpus through the
 * compiled CLI) carries the same requirement.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CORPUS = join(REPO, 'tests', 'corpus', 'independent-nextjs');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-staged-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function corpusCopy(name: string): string {
  const dir = join(scratch, name);
  cpSync(CORPUS, dir, { recursive: true });
  return dir;
}

/** A content digest of a whole tree: names and bytes — the change-nothing contract. */
function treeDigest(root: string): string {
  const hash = createHash('sha256');
  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir).sort()) {
      const full = join(dir, entry);
      const stats = statSync(full);
      if (stats.isDirectory()) {
        hash.update(`d:${prefix}${entry}\n`);
        walk(full, `${prefix}${entry}/`);
      } else {
        hash.update(`f:${prefix}${entry}\n`);
        hash.update(readFileSync(full));
      }
    }
  };
  walk(root, '');
  return hash.digest('hex');
}

async function jscpd(): Promise<StagedTool> {
  const tool = await resolveStagedTool('jscpd');
  if ('unavailable' in tool) throw new Error(`jscpd is not provisioned: ${tool.unavailable}`);
  return tool;
}

/** Narrows an analyser outcome to its success: a failed or unsupported result fails the test. */
function asAnalysis(result: StagedAnalysis | { readonly failed: string } | StagedUnsupported): StagedAnalysis {
  if ('failed' in result) throw new Error(result.failed);
  if ('unsupported' in result) throw new Error(`unexpected unsupported: ${result.unsupported}`);
  return result;
}

const provisioned = existsSync(join(REPO, 'tools', 'quality', 'node_modules', '.bin', 'jscpd'));
const lizardProvisioned = existsSync(join(REPO, 'tools', 'quality', 'venv', 'bin', 'lizard'));
const d = describe;
const ifProvisioned = provisioned ? d : d.skip;
const ifLizard = lizardProvisioned ? d : d.skip;

ifProvisioned('the staged quality analysers find their corpus positives (P4.2)', () => {
  it('jscpd finds the formatPrice/legacyFormatter clone and reports both sites', async () => {
    const app = corpusCopy('duplication');
    const before = treeDigest(app);
    const result = asAnalysis(await analyzeDuplication(app, await jscpd()));
    const clones = result.findings.filter((finding) => finding.rule_id === 'jscpd-clone');
    expect(clones.length).toBeGreaterThanOrEqual(1);
    const clone = clones[0] as { title: string; detail: string; location: string; severity: string };
    // jscpd reports the clone block's first token line; the fixture's shared block starts at line 4.
    expect(clone.location).toBe('utils/format.ts:4');
    // The clone pair is the formatPrice/legacyFormatter bodies: both sites named by line range.
    expect(clone.detail).toContain('utils/format.ts:4-9');
    expect(clone.detail).toContain('utils/format.ts:11-16');
    expect(clone.severity).toBe('low');
    // Change-nothing contract: the audited tree is byte-identical after the scan.
    expect(treeDigest(app)).toBe(before);
  }, 300_000);

  it('knip finds the unused left-pad dependency and the dead utils/format.ts file, and stays silent on used dependencies', async () => {
    const app = corpusCopy('dead-code');
    const tool = await resolveStagedTool('knip');
    if ('unavailable' in tool) throw new Error(tool.unavailable);
    const result = asAnalysis(await analyzeDeadCode(app, tool));
    const rules = result.findings.map((finding) => finding.rule_id);
    expect(rules).toContain('knip-unused-dependency');
    const dependencyFindings = result.findings.filter((finding) => finding.rule_id === 'knip-unused-dependency');
    expect(dependencyFindings.some((finding) => (finding.detail ?? '').includes('left-pad'))).toBe(true);
    // Used dependencies are not dead: next and react are imported by reachable modules.
    expect(dependencyFindings.some((finding) => (finding.detail ?? '').includes("'next'"))).toBe(false);
    expect(rules).toContain('knip-unused-file');
    expect(result.findings.some((finding) => finding.rule_id === 'knip-unused-file' && finding.location === 'utils/format.ts')).toBe(true);
  }, 300_000);

  it('dependency-cruiser finds the UI data-access violation without loading any target configuration', async () => {
    const app = corpusCopy('module-structure');
    // The hostile marker: if any analyser executes the target's own configuration, this file
    // appears. The isolated validation step below first proves the marker is executable.
    writeFileSync(join(app, 'next.config.js'), "require('node:fs').writeFileSync(__dirname + '/.target-config-was-executed', 'x');\nmodule.exports = {};\n");
    const before = treeDigest(app);
    const depcruise = await resolveStagedTool('dependency-cruiser');
    if ('unavailable' in depcruise) throw new Error(depcruise.unavailable);
    const result = asAnalysis(await analyzeModuleStructure(app, depcruise));
    const violations = result.findings.filter((finding) => finding.rule_id === 'depcruise-no-ui-database-access');
    expect(violations.length).toBeGreaterThanOrEqual(1);
    const pageViolation = violations.find((finding) => finding.location === 'app/dashboard/page.tsx');
    expect(pageViolation?.severity).toBe('medium');
    // The marker never fired, the marker file never appeared, and the tree is unchanged.
    expect(existsSync(join(app, '.target-config-was-executed'))).toBe(false);
    expect(treeDigest(app)).toBe(before);
  }, 300_000);

  it('the hostile configuration is demonstrably executable in the isolated validation step (plan item 5)', () => {
    const app = corpusCopy('marker-validation');
    writeFileSync(join(app, 'next.config.js'), "require('node:fs').writeFileSync(__dirname + '/.target-config-was-executed', 'x');\nmodule.exports = {};\n");
    execFileSync(process.execPath, [join(app, 'next.config.js')], { cwd: app });
    expect(existsSync(join(app, '.target-config-was-executed'))).toBe(true);
  });
});

ifLizard('the complexity analyser measures per-function complexity (P4.2)', () => {
  it('stays clean on simple functions and flags a genuinely complex one against the reviewed threshold', async () => {
    const tool = await (await import('../../src/quality/staged.js')).resolveStagedTool('lizard');
    if ('unavailable' in tool) throw new Error(tool.unavailable);

    const clean = corpusCopy('complexity-clean');
    const cleanResult = asAnalysis(await analyzeComplexity(clean, tool));
    expect(cleanResult.observed).toBeGreaterThanOrEqual(3);
    // The corpus's one positive is computeScore (CCN 10, Q19); everything else is clean. The
    // simplified twin of computeScore stays silent: same shape, one decision point.
    const computeFindings = cleanResult.findings.filter((finding) => finding.rule_id === 'lizard-cyclomatic-complexity');
    expect(computeFindings).toHaveLength(1);
    expect(computeFindings[0]?.location).toBe('app/dashboard/page.tsx:7');
    writeFileSync(join(clean, 'twin-simplified.ts'), 'export function computeScoreSimplified(input: number): number {\n  return input > 0 ? 1 : -1;\n}\n');

    const noisy = join(scratch, 'complexity-noisy');
    mkdirSync(noisy, { recursive: true });
    writeFileSync(join(noisy, 'messy.js'), [
      'export function messy(a) {',
      ...Array.from({ length: 12 }, (_, index) => `  if (a === ${String(index + 1)}) return ${String(index + 1)};`),
      '  return 0;',
      '}',
      '',
    ].join('\n'));
    const noisyResult = asAnalysis(await analyzeComplexity(noisy, tool));
    expect(noisyResult.findings.some((finding) => finding.rule_id === 'lizard-cyclomatic-complexity')).toBe(true);
    // The metric is in the finding's title; the location carries the function's start line.
    expect(noisyResult.findings[0]?.title).toContain('cyclomatic complexity of 13');
  }, 300_000);
});
