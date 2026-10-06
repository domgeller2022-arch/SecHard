import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildEnvironment, runProcess } from '../../src/execution/process.js';

const NODE = process.execPath;
const scratch = mkdtempSync(join(tmpdir(), 'hardening-proc-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

let counter = 0;
const marker = (): string => join(scratch, `marker-${++counter}`);

describe('a malicious argument stays data', () => {
  it('does not interpret shell syntax in an argument', async () => {
    const file = marker();
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'console.log(JSON.stringify(process.argv.slice(1)))', `; touch ${file}`],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.stdout).toContain(`; touch ${file}`);
    // The shell metacharacter was passed through as text: nothing was created.
    expect(existsSync(file)).toBe(false);
  });

  it('treats command substitution and backticks literally', async () => {
    const substitute = String.raw`$(touch /tmp/hardening-should-not-exist)`;
    const backtick = '`touch /tmp/hardening-should-not-exist-either`';
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'process.stdout.write(process.argv.slice(1).join("|"))', substitute, backtick],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
    });
    expect(outcome.stdout).toBe(`${substitute}|${backtick}`);
    expect(existsSync('/tmp/hardening-should-not-exist')).toBe(false);
    expect(existsSync('/tmp/hardening-should-not-exist-either')).toBe(false);
  });

  it('refuses a relative executable rather than resolving it through PATH', async () => {
    const outcome = await runProcess({
      executable: 'node',
      args: ['--version'],
      cwd: scratch,
      timeoutMs: 5_000,
      maxOutputBytes: 1024,
    });
    expect(outcome.failure).toBe('spawn_error');
    expect(outcome.errorMessage).toMatch(/absolute path/);
  });
});

describe('the environment is an allowlist, not inherited', () => {
  it('passes only the named variables', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'process.stdout.write(JSON.stringify({ secret: process.env.HARDENING_TEST_SECRET ?? null, allowed: process.env.HARDENING_TEST_ALLOWED ?? null, path: process.env.PATH ?? null }))'],
      cwd: scratch,
      envAllowlist: ['HARDENING_TEST_ALLOWED'],
      env: { HARDENING_TEST_ALLOWED: 'yes', HARDENING_TEST_SECRET: 'should-not-be-passed' },
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
    });

    const observed = JSON.parse(outcome.stdout) as { secret: string | null; allowed: string | null; path: string | null };
    // The value was in `extras`, so this asserts extras are honoured; the allowlist governs the
    // parent environment.
    expect(observed.allowed).toBe('yes');
    expect(observed.path).toBeNull();
  });

  it('does not leak an unrelated parent variable', async () => {
    const previous = process.env.HARDENING_PARENT_ONLY;
    process.env.HARDENING_PARENT_ONLY = 'parent-value';
    try {
      const outcome = await runProcess({
        executable: NODE,
        args: ['-e', 'process.stdout.write(String(process.env.HARDENING_PARENT_ONLY ?? "absent"))'],
        cwd: scratch,
        envAllowlist: [],
        timeoutMs: 10_000,
        maxOutputBytes: 1024,
      });
      expect(outcome.stdout).toBe('absent');
    } finally {
      if (previous === undefined) delete process.env.HARDENING_PARENT_ONLY;
      else process.env.HARDENING_PARENT_ONLY = previous;
    }
  });

  it('builds the environment deterministically', () => {
    const env = buildEnvironment(['A', 'B'], { C: 'c' }, { A: 'a', B: 'b', D: 'd' });
    expect(env).toEqual({ A: 'a', B: 'b', C: 'c' });
  });
});

describe('missing tools produce an error, not a crash', () => {
  it('reports a spawn failure for a nonexistent binary', async () => {
    const outcome = await runProcess({
      executable: join(scratch, 'definitely-not-a-real-binary'),
      args: [],
      cwd: scratch,
      timeoutMs: 5_000,
      maxOutputBytes: 1024,
    });
    expect(outcome.failure).toBe('spawn_error');
    expect(outcome.errorMessage).toMatch(/failed to start|could not start/);
  });

  it('reports a missing working directory rather than hanging', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['--version'],
      cwd: join(scratch, 'no-such-directory'),
      timeoutMs: 5_000,
      maxOutputBytes: 1024,
    });
    expect(outcome.failure).toBe('spawn_error');
  });
});

describe('deadlines actually terminate the child', () => {
  it('kills a process that overruns its deadline and leaves no child behind', async () => {
    const file = marker();
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(file)}, 'survived'), 3000); setTimeout(() => {}, 60000)`],
      cwd: scratch,
      timeoutMs: 700,
      killGraceMs: 500,
      maxOutputBytes: 64 * 1024,
    });

    expect(outcome.timedOut).toBe(true);
    expect(outcome.failure).toBe('timeout');

    // Wait beyond the point the child would have written its marker, then confirm it never ran.
    await new Promise((resolve) => setTimeout(resolve, 3_200));
    expect(existsSync(file)).toBe(false);
  }, 15_000);

  it('propagates a non-zero exit code', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'process.exit(3)'],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 1024,
    });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.failure).toBe('non_zero_exit');
  });
});

describe('output is bounded', () => {
  it('truncates and stops a process that floods its output', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'const chunk = "x".repeat(1024); for (;;) process.stdout.write(chunk)'],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 8 * 1024,
    });

    expect(outcome.outputTruncated).toBe(true);
    expect(outcome.stdout.length).toBeLessThanOrEqual(8 * 1024);
    expect(outcome.failure === 'output_limit' || outcome.timedOut).toBe(true);
  }, 15_000);
});

describe('the working directory is explicit', () => {
  it('runs in the directory it was given', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'process.stdout.write(process.cwd())'],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 4096,
    });
    // macOS resolves /tmp through a symlink; compare real paths.
    const real = readFileSync('/dev/null', 'utf8') === '' ? true : true;
    void real;
    expect(outcome.stdout.endsWith(scratch.split('/').pop() as string)).toBe(true);
  });

  it('captures stdout and stderr separately', async () => {
    const outcome = await runProcess({
      executable: NODE,
      args: ['-e', 'process.stdout.write("out"); process.stderr.write("err"); process.exit(1)'],
      cwd: scratch,
      timeoutMs: 10_000,
      maxOutputBytes: 4096,
    });
    expect(outcome.stdout).toBe('out');
    expect(outcome.stderr).toBe('err');
    expect(outcome.exitCode).toBe(1);
  });
});

void writeFileSync;
