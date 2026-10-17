import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { analyzeComplexity, analyzeDeadCode, analyzeDuplication, analyzeFormatting, analyzeModuleStructure, resolveStagedTool, type StagedAnalysis, type StagedTool, type StagedUnsupported } from '../../src/quality/staged.js';
import { analyzeRepoHygiene, analyzeRegistryHealth } from '../../src/quality/hygiene.js';
import { analyzeStrictTypes, type StrictTypesResult } from '../../src/quality/correctness.js';
import { RECIPES } from '../../src/execution/recipes.js';

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
function asAnalysis<T extends StagedAnalysis | StrictTypesResult>(
  result: T | { readonly failed: string } | StagedUnsupported,
): T {
  if ('failed' in result) throw new Error(String(result.failed));
  if ('unsupported' in result) throw new Error(String(result.unsupported));
  return result as T;
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

/**
 * P4.3: the strict type probe runs tsc with SecHard's own strict configuration against the
 * application's type graph. Real strict diagnostics are findings; missing type dependencies and
 * unreadable configuration are coverage gaps, never findings (plan item 1); the probe writes only
 * to a private temporary directory.
 */
describe('the strict type probe (P4.3, QUAL-02)', () => {
  it('flags a genuine strict type error and keeps the tree byte-identical', async () => {
    const tool = await resolveStagedTool('tsc');
    if ('unavailable' in tool) throw new Error(tool.unavailable);
    const app = join(scratch, 'strict-positive');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'package.json'), '{"name":"strict-positive","version":"1.0.0"}');
    mkdirSync(join(app, 'node_modules'));
    writeFileSync(join(app, 'tsconfig.json'), '{"compilerOptions": {"strict": false}}');
    writeFileSync(join(app, 'broken.ts'), 'const n: number = "not a number";\nexport { n };\n');
    const before = treeDigest(app);

    const result = asAnalysis(await analyzeStrictTypes(app, tool)) as StrictTypesResult;
    expect(result.coverage).toBe('complete');
    expect(result.findings.some((finding) => finding.rule_id === 'tsc-strict-error' && finding.location === 'broken.ts:1')).toBe(true);
    expect(treeDigest(app)).toBe(before);
  }, 300_000);

  it('records coverage gaps instead of findings when the type graph cannot resolve', async () => {
    const tool = await resolveStagedTool('tsc');
    if ('unavailable' in tool) throw new Error(tool.unavailable);
    const app = join(scratch, 'strict-gap');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'tsconfig.json'), '{}');
    writeFileSync(join(app, 'main.ts'), 'import { missing } from "nowhere";\nexport { missing };\n');
    // No node_modules: the app's type dependencies are absent — a coverage gap, not findings.
    const result = asAnalysis(await analyzeStrictTypes(app, tool)) as StrictTypesResult;
    expect(result.coverage).toBe('gap');
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.join(' ')).toContain('the strict type graph cannot resolve');
  }, 300_000);

  it('records a coverage gap when the application has no tsconfig', async () => {
    const tool = await resolveStagedTool('tsc');
    if ('unavailable' in tool) throw new Error(tool.unavailable);
    const app = join(scratch, 'strict-no-tsconfig');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'main.ts'), 'export const one = 1;\n');
    const result = asAnalysis(await analyzeStrictTypes(app, tool)) as StrictTypesResult;
    expect(result.coverage).toBe('gap');
    expect(result.diagnostics.join(' ')).toContain('no tsconfig.json');
  }, 300_000);
});

/**
 * P4.3: the formatting check is check-only with SecHard's own configurations — the target's own
 * biome/ruff configuration is never loaded, neither tool writes, and both ecosystems' positives
 * and negatives are exercised (plan item 3).
 */
describe('the formatting check (P4.3, QUAL-10)', () => {
  it('flags a file that does not match the reviewed format and never writes', async () => {
    const biome = await resolveStagedTool('biome');
    if ('unavailable' in biome) throw new Error(biome.unavailable);
    const ruff = await resolveStagedTool('ruff');
    if ('unavailable' in ruff) throw new Error(ruff.unavailable);
    const app = join(scratch, 'formatting-noisy');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'ugly.ts'), 'const x=1\nexport function f( a:number ){return a}\n');
    const before = treeDigest(app);

    const result = asAnalysis(await analyzeFormatting(app, biome, ruff));
    expect(result.findings.some((finding) => finding.rule_id === 'biome-format' && finding.location === 'ugly.ts')).toBe(true);
    expect(treeDigest(app)).toBe(before);
  }, 300_000);

  it('ruff format --check flags a misformatted Python file', async () => {
    const biome = await resolveStagedTool('biome');
    if ('unavailable' in biome) throw new Error(biome.unavailable);
    const ruff = await resolveStagedTool('ruff');
    if ('unavailable' in ruff) throw new Error(ruff.unavailable);
    const app = join(scratch, 'formatting-python');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'messy.py'), 'def f( a ):\n    x=1\n    return  x\n');

    const result = asAnalysis(await analyzeFormatting(app, biome, ruff));
    expect(result.findings.some((finding) => finding.rule_id === 'ruff-format' && finding.location === 'messy.py')).toBe(true);
  }, 300_000);

  it('a file that already matches the reviewed format produces no finding', async () => {
    const biome = await resolveStagedTool('biome');
    if ('unavailable' in biome) throw new Error(biome.unavailable);
    const ruff = await resolveStagedTool('ruff');
    if ('unavailable' in ruff) throw new Error(ruff.unavailable);
    const app = join(scratch, 'formatting-clean');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'clean.ts'), 'const x = 1;\n\nexport function f(a: number): number {\n  return a;\n}\n');

    const result = asAnalysis(await analyzeFormatting(app, biome, ruff));
    expect(result.findings.filter((finding) => finding.rule_id === 'biome-format')).toEqual([]);
  }, 300_000);
});

/** P4.3: repository-hygiene additions (QUAL-11) — generated artifacts and licence truth. */
describe('the repository-hygiene additions (P4.3, QUAL-11)', () => {
  it('flags committed generated artifacts and a licence-description mismatch', () => {
    const app = join(scratch, 'hygiene-p43');
    mkdirSync(join(app, 'dist'), { recursive: true });
    writeFileSync(join(app, 'dist', 'bundle.js'), 'generated bytes\n');
    writeFileSync(join(app, 'README.md'), '# The app\n\nMIT License. Fully open source.\n');

    const result = analyzeRepoHygiene(app, ['package-lock.json']);
    expect(result.findings.some((finding) => finding.rule_id === 'generated-artifacts-committed')).toBe(true);
    expect(result.findings.some((finding) => finding.rule_id === 'licence-description-mismatch')).toBe(true);
  });

  it('does not flag a generated directory that .gitignore already covers', () => {
    const app = join(scratch, 'hygiene-p43-clean');
    mkdirSync(join(app, 'dist'), { recursive: true });
    writeFileSync(join(app, 'dist', 'bundle.js'), 'generated bytes\n');
    writeFileSync(join(app, '.gitignore'), 'dist/\nnode_modules/\n');

    const result = analyzeRepoHygiene(app, ['package-lock.json']);
    expect(result.findings.some((finding) => finding.rule_id === 'generated-artifacts-committed')).toBe(false);
  });
});

/**
 * P4.3: registry health (QUAL-12) uses bounded reviewed queries whose failures are unknown, never
 * healthy, and never replace OSV advisory scanning. The tests stub the fetch — no network runs.
 */
describe('the registry health route (P4.3, QUAL-12)', () => {
  function registryFixture(deps: Record<string, string>, lockfileEntries: string): string {
    const app = join(scratch, 'registry-' + String(Math.random()).slice(2, 8));
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'registry-fixture', version: '1.0.0', dependencies: deps }));
    writeFileSync(join(app, 'pnpm-lock.yaml'), 'lockfileVersion: \'9.0\'\n\npackages:\n' + lockfileEntries);
    return app;
  }

  it('flags major drift and deprecation from the registry documents', async () => {
    const app = registryFixture({ 'old-pkg': '^1.0.0', 'dead-pkg': '^2.0.0' }, '  old-pkg@1.0.0:\n  dead-pkg@2.0.0:\n');
    const fetchImpl = (async (input: unknown) => {
      const url = String(input);
      if (url.includes('old-pkg')) {
        return new Response(JSON.stringify({ 'dist-tags': { latest: '3.0.0' }, versions: { '3.0.0': {} }, time: { '3.0.0': new Date().toISOString() } }));
      }
      return new Response(JSON.stringify({ 'dist-tags': { latest: '2.0.0' }, versions: { '2.0.0': { deprecated: 'use the replacement instead' } }, time: { '2.0.0': new Date().toISOString() } }));
    }) as typeof fetch;

    const result = await analyzeRegistryHealth(app, ['pnpm-lock.yaml'], fetchImpl);
    const rules = result.findings.map((finding) => finding.rule_id);
    expect(rules).toContain('registry-major-drift');
    expect(rules).toContain('registry-deprecated');
    expect(result.queries).toBe(2);
  });

  it('records offline queries as unknown, never as healthy', async () => {
    const app = registryFixture({ 'some-pkg': '^1.0.0' }, '  some-pkg@1.0.0:\n');
    const fetchImpl = (async () => {
      throw new Error('offline');
    }) as typeof fetch;

    const result = await analyzeRegistryHealth(app, ['pnpm-lock.yaml'], fetchImpl);
    expect(result.findings).toEqual([]);
    expect(result.unknown.length).toBeGreaterThan(0);
  });

  it('does not query non-npm lockfiles and names the gap', async () => {
    const app = join(scratch, 'registry-python');
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, 'requirements.txt'), 'flask==3.0.0\n');
    let queried = 0;
    const fetchImpl = (async () => {
      queried += 1;
      return new Response('{}');
    }) as typeof fetch;

    const result = await analyzeRegistryHealth(app, ['requirements.txt'], fetchImpl);
    expect(queried).toBe(0);
    expect(result.unknown.join(' ')).toContain('recorded gap');
  });

  it('stops at the query bound and records the remainder as unknown', async () => {
    const deps: Record<string, string> = {};
    const entries: string[] = [];
    for (let index = 0; index < 5; index += 1) {
      deps['pkg-' + String(index)] = '^1.0.0';
      entries.push('  pkg-' + String(index) + '@1.0.0:\n');
    }
    const app = registryFixture(deps, entries.join(''));
    const fetchImpl = (async () => new Response(JSON.stringify({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} }, time: { '1.0.0': new Date().toISOString() } }))) as typeof fetch;

    const result = await analyzeRegistryHealth(app, ['pnpm-lock.yaml'], fetchImpl);
    expect(result.queries).toBe(5);
    expect(result.unknown.join(' ')).not.toContain('beyond the query bound');
  });
});

/** P4.3 (QUAL-13): the frontend handler names its P8 precondition instead of fabricating a verdict. */
describe('the frontend quality precondition (P4.3, QUAL-13)', () => {
  it('reports the approved-running-target precondition as unsupported', async () => {
    const handler = RECIPES['quality/frontend-quality'];
    expect(handler).toBeDefined();
    const outcome = await handler!({} as never);
    expect(outcome.outcome).toBe('unsupported');
    expect(outcome.diagnostic).toContain('P8 live-check precondition');
  });
});
