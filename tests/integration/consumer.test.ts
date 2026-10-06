import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');
const FIXTURE_RECORDS = join(REPO, 'tests', 'fixtures', 'consumer', '.hardening');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-integration-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

interface RunResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Runs the CLI as a consumer outside this repository would: a separate working directory and a
 * consumer with no path back into the master tree. Publishing a package archive is Step 15; this
 * verifies the compiled CLI does not depend on the source layout at runtime.
 */
function cli(args: readonly string[], cwd: string): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

let created = 0;

function consumer(name = 'consumer'): string {
  created += 1;
  const dir = join(scratch, `${name}-${created}`);
  mkdirSync(join(dir, '.hardening'), { recursive: true });
  cpSync(FIXTURE_RECORDS, join(dir, '.hardening'), { recursive: true });
  return dir;
}

function latestRun(runs: string): string {
  const entries = readdirSync(runs).filter((entry) => entry.startsWith('pr-') || entry.startsWith('release-')).sort();
  expect(entries.length).toBeGreaterThan(0);
  return join(runs, entries.pop() as string);
}

function fullFlow(
  dir: string,
  stage: 'pr' | 'release' = 'pr',
): { readonly runDir: string; readonly gated: RunResult; readonly reported: RunResult } {
  const runs = join(dir, '.hardening', 'runs');
  const environment = stage === 'release' ? 'production' : 'local';
  expect(cli(['plan', '--app', dir, '--policy', REPO, '--stage', stage, '--environment', environment, '--out', runs], dir).status).toBe(0);
  const runDir = latestRun(runs);
  expect(cli(['check', '--app', dir, '--policy', REPO, '--plan', join(runDir, 'plan.json'), '--out', runDir], dir).status).toBe(0);
  const gated = cli(['gate', '--app', dir, '--policy', REPO, '--run', runDir], dir);
  const reported = cli(['report', '--app', dir, '--policy', REPO, '--run', runDir], dir);
  return { runDir, gated, reported };
}

describe('the compiled CLI works from outside the master repository', () => {
  it('validates a consumer in a separate directory', () => {
    const dir = consumer();
    const result = cli(['validate', '--app', dir, '--policy', REPO], dir);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('validate: OK');
  });

  it('runs plan, check, gate, and report end to end', () => {
    const dir = consumer();
    const { runDir, gated, reported } = fullFlow(dir);

    expect(gated.status).toBe(1);
    expect(gated.stdout).toContain('gate: blocked');
    expect(reported.status).toBe(1);

    const markdown = readFileSync(join(runDir, 'report.md'), 'utf8');
    expect(markdown).toContain('# Hardening report');
    // The one real check that ran is recorded as a pass, alongside everything that did not.
    expect(markdown).toMatch(/GOV-02 \| applicable \| satisfied/);
  });

  it('shows unmet manual requirements at release rather than forcing every control to pass', () => {
    const dir = consumer();
    const { runDir } = fullFlow(dir, 'release');
    const markdown = readFileSync(join(runDir, 'report.md'), 'utf8');

    expect(markdown).toContain('manual.missing');
    expect(markdown).toContain('**Decision: blocked**');
    expect(markdown).toMatch(/OPS-02 \| applicable \| unmet/);
    // A release from a directory that is not a git repository has no clean source identity, so every
    // check is additionally unmet on that ground. The manual requirements are still planned.

    // The manual requirement is a planned obligation, visible in the evidence even though no tool
    // result exists for it.
    const evidence = JSON.parse(readFileSync(join(runDir, 'report.json'), 'utf8')) as {
      expected_checks: { check_id: string }[];
      results: { check_id: string }[];
    };
    const manualChecks = evidence.expected_checks.filter((check) => check.check_id.includes('manual_attestation'));
    expect(manualChecks.length).toBeGreaterThan(0);
    for (const check of manualChecks) {
      expect(evidence.results.some((result) => result.check_id === check.check_id)).toBe(false);
    }
  });

  it('never reports application production readiness from a kit result', () => {
    const dir = consumer();
    const { runDir } = fullFlow(dir);
    const evidence = JSON.parse(readFileSync(join(runDir, 'report.json'), 'utf8')) as {
      decision: { kit_readiness: string; application_production_readiness: string };
    };
    expect(evidence.decision.application_production_readiness).toBe('pending');
  });

  it('works with a path containing spaces', () => {
    const dir = consumer('consumer with spaces');
    expect(cli(['validate', '--app', dir, '--policy', REPO], dir).status).toBe(0);
    expect(fullFlow(dir).gated.status).toBe(1);
  });

  it('exits 2 when the policy root is missing instead of reporting success', () => {
    const dir = consumer();
    const result = cli(['validate', '--app', dir, '--policy', join(scratch, 'no-such-policy')], dir);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('input.not_found');
  });

  it('exits 2 when the consumer has no manifest', () => {
    const dir = join(scratch, 'empty-consumer');
    mkdirSync(dir, { recursive: true });
    const result = cli(
      ['plan', '--app', dir, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', join(dir, 'runs')],
      dir,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('manifest');
  });

  it('rejects an unknown environment rather than defaulting one', () => {
    const dir = consumer();
    const result = cli(
      ['plan', '--app', dir, '--policy', REPO, '--stage', 'pr', '--environment', 'moon', '--out', join(dir, 'runs')],
      dir,
    );
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('unknown environment');
  });
});
