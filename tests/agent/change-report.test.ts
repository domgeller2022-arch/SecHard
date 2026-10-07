import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildChangeReport } from '../../src/agent/change-report.js';
import { gitExecutable } from '../../src/agent/review-manifest.js';

const git = gitExecutable();
const scratch = mkdtempSync(join(tmpdir(), 'hardening-change-report-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function gitIn(cwd: string, args: readonly string[]): string {
  if (git === undefined) throw new Error('git is not available');
  return execFileSync(git, [...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

const ORIGINAL_TEST = `import { describe, expect, it } from 'vitest';

describe('ownership', () => {
  it('allows the owner to read', () => {
    expect(read('a')).toBe('a');
  });

  it('denies another user', () => {
    expect(readAs('b', 'a')).toBeUndefined();
  });

  it('leaves stored data unchanged after a denied write', () => {
    expect(writeAs('b', 'a', 'x')).toBe(false);
    expect(read('a')).toBe('a');
  });
});
`;

const WEAKENED_TEST = `import { describe, expect, it } from 'vitest';

describe('ownership', () => {
  it('allows the owner to read', () => {
    expect(read('a')).toBe('a');
  });

  it.skip('denies another user', () => {
    expect(readAs('b', 'a')).toBeUndefined();
  });

  it('leaves stored data unchanged after a denied write', () => {
    const db = mockDatabase();
    expect(db.unchanged).toBe(true);
  });
});
`;

let repo = '';

beforeAll(() => {
  repo = join(scratch, 'repo');
  mkdirSync(join(repo, 'tests', 'authorization'), { recursive: true });
  mkdirSync(join(repo, 'ci', 'configs'), { recursive: true });
  writeFileSync(join(repo, 'tests', 'authorization', 'ownership.test.ts'), ORIGINAL_TEST, 'utf8');
  writeFileSync(join(repo, 'ci', 'configs', 'scan.toml'), '# original\n', 'utf8');
  writeFileSync(join(repo, 'notes.md'), 'initial\n', 'utf8');

  gitIn(repo, ['init', '-q', '-b', 'main']);
  gitIn(repo, ['config', 'user.name', 'fixture']);
  gitIn(repo, ['config', 'user.email', 'fixture@example.invalid']);
  gitIn(repo, ['add', '.']);
  gitIn(repo, ['commit', '-q', '-m', 'base']);
});

describe('the change report notices a weakened security test', () => {
  it('reports removed cases, an added skip, a removed assertion, and an added mock', () => {
    rmSync(repo, { recursive: true, force: true });
    mkdirSync(join(repo, 'tests', 'authorization'), { recursive: true });
    mkdirSync(join(repo, 'ci', 'configs'), { recursive: true });
    writeFileSync(join(repo, 'tests', 'authorization', 'ownership.test.ts'), ORIGINAL_TEST, 'utf8');
    writeFileSync(join(repo, 'ci', 'configs', 'scan.toml'), '# original\n', 'utf8');
    writeFileSync(join(repo, 'notes.md'), 'initial\n', 'utf8');
    gitIn(repo, ['init', '-q', '-b', 'main']);
    gitIn(repo, ['config', 'user.name', 'fixture']);
    gitIn(repo, ['config', 'user.email', 'fixture@example.invalid']);
    gitIn(repo, ['add', '.']);
    gitIn(repo, ['commit', '-q', '-m', 'base']);

    writeFileSync(join(repo, 'tests', 'authorization', 'ownership.test.ts'), WEAKENED_TEST, 'utf8');
    gitIn(repo, ['add', '.']);
    gitIn(repo, ['commit', '-q', '-m', 'weaken the test']);

    const report = buildChangeReport({ cwd: repo, base: 'HEAD~1', head: 'HEAD' });
    expect(report.requiresReview).toBe(true);

    const kinds = report.findings.map((finding) => finding.kind);
    expect(kinds).toContain('removed_test_case');
    expect(kinds).toContain('added_skip');
    expect(kinds).toContain('removed_assertion');
    expect(kinds).toContain('added_mock');
    expect(kinds).toContain('security_sensitive_path_change');
  });

  it('reports a deleted test file', () => {
    const dir = join(scratch, 'deleted');
    mkdirSync(join(dir, 'tests'), { recursive: true });
    writeFileSync(join(dir, 'tests', 'boundary.test.ts'), ORIGINAL_TEST, 'utf8');
    gitIn(dir, ['init', '-q', '-b', 'main']);
    gitIn(dir, ['config', 'user.name', 'fixture']);
    gitIn(dir, ['config', 'user.email', 'fixture@example.invalid']);
    gitIn(dir, ['add', '.']);
    gitIn(dir, ['commit', '-q', '-m', 'base']);

    rmSync(join(dir, 'tests', 'boundary.test.ts'), { force: true });
    gitIn(dir, ['add', '-A']);
    gitIn(dir, ['commit', '-q', '-m', 'remove the test']);

    const report = buildChangeReport({ cwd: dir, base: 'HEAD~1', head: 'HEAD' });
    expect(report.findings.some((finding) => finding.kind === 'deleted_test_file')).toBe(true);
    expect(report.requiresReview).toBe(true);
  });

  it('does not require review for a change outside the sensitive paths', () => {
    const dir = join(scratch, 'docs-only');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'README.md'), 'one\n', 'utf8');
    gitIn(dir, ['init', '-q', '-b', 'main']);
    gitIn(dir, ['config', 'user.name', 'fixture']);
    gitIn(dir, ['config', 'user.email', 'fixture@example.invalid']);
    gitIn(dir, ['add', '.']);
    gitIn(dir, ['commit', '-q', '-m', 'base']);

    writeFileSync(join(dir, 'README.md'), 'two\n', 'utf8');
    gitIn(dir, ['add', '.']);
    gitIn(dir, ['commit', '-q', '-m', 'docs']);

    const report = buildChangeReport({ cwd: dir, base: 'HEAD~1', head: 'HEAD' });
    expect(report.requiresReview).toBe(false);
    expect(report.findings).toEqual([]);
  });

  it('reports a scan-scope change', () => {
    const dir = join(scratch, 'scope');
    mkdirSync(join(dir, 'ci', 'configs'), { recursive: true });
    writeFileSync(join(dir, 'ci', 'configs', 'scan.toml'), '# original\n', 'utf8');
    gitIn(dir, ['init', '-q', '-b', 'main']);
    gitIn(dir, ['config', 'user.name', 'fixture']);
    gitIn(dir, ['config', 'user.email', 'fixture@example.invalid']);
    gitIn(dir, ['add', '.']);
    gitIn(dir, ['commit', '-q', '-m', 'base']);

    writeFileSync(join(dir, 'ci', 'configs', 'scan.toml'), '# original\nallowlist = ["everything"]\n', 'utf8');
    gitIn(dir, ['add', '.']);
    gitIn(dir, ['commit', '-q', '-m', 'loosen the scan']);

    const report = buildChangeReport({ cwd: dir, base: 'HEAD~1', head: 'HEAD' });
    const entry = report.findings.find((finding) => finding.path === 'ci/configs/scan.toml');
    expect(entry?.kind).toBe('security_sensitive_path_change');
    expect(entry?.detail).toMatch(/scanner_configs/);
  });

  it('states its limitations rather than implying it can judge intent', () => {
    const report = buildChangeReport({ cwd: repo, base: 'HEAD~1', head: 'HEAD' });
    expect(report.limitations.join(' ')).toMatch(/cannot tell whether a removed assertion was wrong or inconvenient/);
  });

  it('reports a clean range as clean, not as approval', () => {
    const report = buildChangeReport({ cwd: repo, base: 'HEAD', head: 'HEAD' });
    expect(report.requiresReview).toBe(false);
    expect(report.limitations.length).toBeGreaterThan(0);
  });

  it('handles an unknown revision without pretending the range was clean', () => {
    const report = buildChangeReport({ cwd: repo, base: 'no-such-ref', head: 'HEAD' });
    expect(report.requiresReview).toBe(false);
    // The distinction that matters: it says it could not tell, rather than reporting no findings.
    expect(report.limitations.join(' ')).toMatch(/git could not be run|could not be run, or one of the revisions/);
  });
});
