import { execFileSync } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * R6.4: every command the README advertises must actually run.
 *
 * The README's CLI block is executed verbatim, with only the two paths a reader substitutes
 * (`APP`, `POLICY`) replaced and `hardening` pointing at the compiled CLI. If a documented flag,
 * subcommand, or run-directory convention stops working, this fails.
 */
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = join(REPO, 'tests', 'fixtures', 'consumer', '.hardening');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-readme-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function readmeCliBlock(): string {
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  const blocks = [...readme.matchAll(/```bash\n([\s\S]*?)```/g)].map((match) => match[1] ?? '');
  const block = blocks.find((candidate) => candidate.includes('hardening validate'));
  expect(block, 'the README must contain a runnable CLI block').toBeDefined();
  return block as string;
}

describe('every README command runs against a scratch consumer', () => {
  it('runs the CLI block and produces the advertised artefacts', () => {
    const app = join(scratch, 'app');
    mkdirSync(app, { recursive: true });
    // `cpSync` with a non-existent destination copies the source directory itself to that path; the
    // fixture's records land directly in `<app>/.hardening/`, not nested one level deeper.
    cpSync(FIXTURE, join(app, '.hardening'), { recursive: true });

    const bin = join(scratch, 'bin');
    mkdirSync(bin, { recursive: true });
    const shim = join(bin, 'hardening');
    writeFileSync(shim, `#!/bin/sh\nexec "${process.execPath}" "${join(REPO, 'dist', 'cli.js')}" "$@"\n`);
    chmodSync(shim, 0o755);

    // Substitute only the two placeholders the README tells the reader to set, then run the block
    // exactly as printed. No `set -e`: the block intentionally includes commands that exit 1 for a
    // blocked gate, and the last command's status is what a shell would report.
    const script = readmeCliBlock()
      .replace(/^export APP=.*$/m, `export APP="${app}"`)
      .replace(/^export POLICY=.*$/m, `export POLICY="${REPO}"`);

    let status = 0;
    let output = '';
    try {
      output = execFileSync('bash', ['-c', script], {
        cwd: app,
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 16 * 1024 * 1024,
        env: { PATH: `${bin}:${process.env['PATH'] ?? ''}`, HOME: process.env['HOME'] ?? '' },
      });
    } catch (error) {
      status = (error as { status?: number }).status ?? 2;
      output = `${(error as { stdout?: string }).stdout ?? ''}${(error as { stderr?: string }).stderr ?? ''}`;
    }

    // The block ends with `approvals`, which exits 0. Every command before it also had to exist and
    // run; a missing option or renamed flag would surface here.
    expect(status, output).toBe(0);
    expect(output).toContain('validate: OK');
    expect(output).toContain('plan: derived');
    expect(output).toContain('required check(s) did not run');
    expect(output).toContain('gate: blocked');
    expect(output).toContain('Approvals on record');

    const runs = join(app, '.hardening', 'runs');
    const runDirs = readdirSync(runs).filter((entry) => entry.startsWith('pr-'));
    expect(runDirs.length).toBeGreaterThan(0);
    const runDir = join(runs, runDirs.sort().pop() as string);
    for (const artefact of ['plan.json', 'results.json', 'report.json', 'report.md']) {
      expect(() => readFileSync(join(runDir, artefact), 'utf8'), artefact).not.toThrow();
    }
  });

  it('documents the suite split it ships', () => {
    const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
    for (const command of ['pnpm test', 'pnpm run test:scanners', 'pnpm run test:example', 'pnpm run test:integration', 'pnpm run build', 'pnpm run typecheck:tools']) {
      expect(readme, `README must document ${command}`).toContain(command);
    }
  });
});
