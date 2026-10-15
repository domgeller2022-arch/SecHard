import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { CASES } from './rule-twin-cases.js';

/**
 * P3.2 acceptance (A-15/A-16), through the compiled CLI: every rule change lands with its
 * vulnerable shape and its safe twin as a pinned-binary regression. The fixture app is audited
 * once at standard depth; each case asserts the specific rule on the vulnerable file and silence
 * on its safe twin. The manifest (ci/configs/opengrep-rules/manifest.yaml) anchors these cases.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-rule-twins-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

describe('P3.2 rule twins: vulnerable shapes fire and safe twins stay silent, through the compiled CLI (A-15/A-16)', () => {
  const app = join(scratch, 'app');
  const outDir = join(scratch, 'out');

  let findings: readonly { rule_id: string; location?: string }[] = [];

  it('audits the twin fixture app once', () => {
    mkdirSync(join(app, 'src'), { recursive: true });
    // The stack detection needs a package.json: without it the profiles compose no static-analysis
    // check at all, and the twins would be measured against a run that never scanned.
    writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'rule-twins', dependencies: { next: '14.0.0' } }, null, 2));
    for (const twin of CASES) writeFileSync(join(app, 'src', twin.file), twin.content);
    execFileSync('git', ['init', '-q'], { cwd: app });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: app });
    execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: app });
    execFileSync('git', ['add', '-A'], { cwd: app });
    execFileSync('git', ['commit', '-q', '-m', 'rule twins'], { cwd: app });

    const run = (() => {
      try {
        const stdout = execFileSync(process.execPath, [CLI, 'audit', app, '--out', outDir, '--depth', 'standard'], {
          cwd: scratch, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
        });
        return { status: 0, stdout, stderr: '' };
      } catch (error) {
        const failure = error as { status?: number; stdout?: string; stderr?: string };
        return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
      }
    })();
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as {
      check_id: string;
      outcome: string;
      diagnostic?: string;
      findings?: { rule_id: string; location?: string }[];
    }[];
    // A nonzero exit here must name its culprit: without the error rows the failure is
    // undiagnosable once the scratch is removed.
    if (run.status !== 0) {
      const errs = results
        .filter((row) => row.outcome === 'error')
        .map((row) => `${row.check_id}: ${row.diagnostic ?? '(no diagnostic)'}`);
      expect.fail(`audit exited ${String(run.status)}; error rows: ${errs.join(' | ') || '(none in results.json)'}`);
    }
    findings = (results.find((entry) => entry.check_id.includes('opengrep/rules'))?.findings ?? []) as {
      rule_id: string;
      location?: string;
    }[];
    expect(run.status, run.stderr).toBe(0);
  }, 600_000);

  for (const twin of CASES) {
    it(`${twin.expect === 'fires' ? 'reports' : 'stays silent on'} ${twin.name} (${twin.rule})`, () => {
      const hits = findings.filter((f) => f.rule_id === twin.rule && (f.location ?? '').startsWith(`src/${twin.file}`));
      if (twin.expect === 'fires') {
        expect(hits.length, JSON.stringify({ rule: twin.rule, file: twin.file, all: findings.map((f) => f.location) })).toBeGreaterThan(0);
      } else {
        expect(hits, JSON.stringify({ rule: twin.rule, file: twin.file })).toHaveLength(0);
      }
    });
  }
});
