import { execFileSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * P3.1 acceptance (A-09/A-10), through the CLI: a failed or missing pack, invalid rules, an
 * ignored vulnerable file, or an unreviewed target suppression must never produce a clean,
 * complete result. Each audit runs the real pinned scanner against a policy root that is a copy
 * of the reviewed tree with exactly one input broken — no sample JSON.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-packfail-'));
const lockedDirs: string[] = [];
afterAll(() => {
  // The unreadable fixture directory must be readable again before the tree can be removed.
  for (const dir of lockedDirs) chmodSync(dir, 0o755);
  rmSync(scratch, { recursive: true, force: true });
});

interface ResultRow {
  readonly check_id: string;
  readonly outcome: string;
  readonly coverage?: string;
  readonly diagnostic?: string;
  readonly scope?: { readonly unexamined?: number; readonly failed?: number; readonly suppressions?: number };
}

let runCounter = 0;

function cli(args: readonly string[], cwd: string): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 600_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

/** A copy of the reviewed policy tree, with the test's single break applied if any. */
function policyCopy(name: string, damage?: (root: string) => void): string {
  const root = join(scratch, 'policy', name);
  mkdirSync(root, { recursive: true });
  for (const dir of ['policy', 'controls', 'profiles', 'ci']) {
    cpSync(join(REPO, dir), join(root, dir), { recursive: true });
  }
  damage?.(root);
  return root;
}

/** A scratch application with one visible eval finding, its own git history. */
function app(name: string, build: (root: string) => void): string {
  const root = join(scratch, 'apps', name);
  mkdirSync(join(root, 'src'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { next: '14.0.0' } }, null, 2));
  writeFileSync(join(root, 'src', 'visible.ts'), 'export const boom = (): unknown => eval("1+1");\n');
  build(root);
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
  execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: root });
  execFileSync('git', ['add', '-A'], { cwd: root });
  execFileSync('git', ['commit', '-q', '-m', 'fixture'], { cwd: root });
  return root;
}

function audit(target: string, policyRoot: string): { status: number; results: ResultRow[] } {
  const outDir = join(scratch, 'out', `run-${String(runCounter++)}`);
  mkdirSync(join(scratch, 'out'), { recursive: true });
  const run = cli(['audit', target, '--out', outDir, '--depth', 'standard', '--policy', policyRoot], scratch);
  const results = existsSync(join(outDir, 'results.json'))
    ? (JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as ResultRow[])
    : [];
  return { status: run.status, results };
}

const opengrep = (results: readonly ResultRow[]): ResultRow | undefined =>
  results.find((result) => result.check_id.includes('opengrep/rules'));

describe('P3.1: failed packs, ignored files, and unreviewed suppressions cannot look clean (A-09/A-10)', () => {
  it('a missing detection-depth pack errors the combined result even though the core pack scanned fine', () => {
    const appRoot = app('missing-depth', () => {});
    const policy = policyCopy('missing-depth', (root) => {
      rmSync(join(root, 'ci', 'configs', 'opengrep-rules', 'detection-depth.yaml'));
    });

    const run = audit(appRoot, policy);
    // A successful sibling never masks the failed pack: the audit reports the error, not a pass.
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.diagnostic ?? '').toContain('detection-depth.yaml');
    expect(result?.diagnostic ?? '').toContain('missing');
  }, 600_000);

  it('a missing core pack errors the combined result even though the depth pack scanned fine', () => {
    const appRoot = app('missing-core', () => {});
    const policy = policyCopy('missing-core', (root) => {
      rmSync(join(root, 'ci', 'configs', 'opengrep-rules', 'hardening-core.yaml'));
    });

    const run = audit(appRoot, policy);
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.diagnostic ?? '').toContain('hardening-core.yaml');
  }, 600_000);

  it('invalid rules error the pack instead of scanning', () => {
    const appRoot = app('invalid-rules', () => {});
    const policy = policyCopy('invalid-rules', (root) => {
      writeFileSync(join(root, 'ci', 'configs', 'opengrep-rules', 'detection-depth.yaml'), 'rules:\n  - id: broken\n   languages: [typescript\n');
    });

    const run = audit(appRoot, policy);
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.diagnostic ?? '').toContain('exited 7');
  }, 600_000);

  it('a gitignored vulnerable file leaves the scope explicitly incomplete', () => {
    const appRoot = app('ignored-vuln', (root) => {
      writeFileSync(join(root, 'src', 'hidden.ts'), 'export const boom = (): unknown => eval("2+2");\n');
      writeFileSync(join(root, '.gitignore'), 'src/hidden.ts\n');
    });

    const run = audit(appRoot, policyCopy('ignored-vuln'));
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.coverage).toBe('partial');
    expect(result?.scope?.unexamined ?? 0).toBeGreaterThanOrEqual(1);
    expect(result?.diagnostic ?? '').toContain('not examined');
  }, 600_000);

  it('an inline nosemgrep annotation suppresses a finding without review, so the scan cannot claim complete', () => {
    const appRoot = app('nosemgrep', (root) => {
      writeFileSync(join(root, 'src', 'suppressed.ts'), 'export const boom = (): unknown => eval("3+3"); // nosemgrep\n');
    });

    const run = audit(appRoot, policyCopy('nosemgrep'));
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.scope?.suppressions ?? 0).toBeGreaterThanOrEqual(1);
    expect(result?.diagnostic ?? '').toContain('nosemgrep');
  }, 600_000);

  it('a target .semgrepignore cannot shrink the reviewed scan scope — the scan covers everything and records the suppression', () => {
    const appRoot = app('semgrepignore', (root) => {
      writeFileSync(join(root, '.semgrepignore'), 'src/\n');
    });

    const run = audit(appRoot, policyCopy('semgrepignore'));
    const result = opengrep(run.results);
    // The reviewed ignore file replaces the target's, so the ignore cannot affect the scan (P3.1
    // requirement 4, first branch): the scan stays complete with the suppression recorded.
    expect(result?.outcome).toBe('pass');
    expect(result?.coverage).toBe('complete');
    expect(result?.scope?.suppressions ?? 0).toBeGreaterThanOrEqual(1);
    expect(result?.diagnostic ?? '').toContain('.semgrepignore');
  }, 600_000);

  it('an unreadable directory leaves entries the inventory could not record, and the scan says so', () => {
    const appRoot = app('unreadable', (root) => {
      mkdirSync(join(root, 'src', 'locked'), { recursive: true });
      writeFileSync(join(root, 'src', 'locked', 'hidden.ts'), 'export const x = 1;\n');
      chmodSync(join(root, 'src', 'locked'), 0o000);
      lockedDirs.push(join(root, 'src', 'locked'));
    });

    const run = audit(appRoot, policyCopy('unreadable'));
    expect(run.status, opengrep(run.results)?.diagnostic).toBe(1);
    const result = opengrep(run.results);
    expect(result?.outcome).toBe('error');
    expect(result?.diagnostic ?? '').toContain('could not be inventoried');
  }, 600_000);
});
