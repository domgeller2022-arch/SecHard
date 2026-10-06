import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

/**
 * The only place this repository starts an external process.
 *
 * Guarantees, each of which exists because the alternative is a real failure mode:
 *
 * - Arguments are passed as an array with `shell: false`. A value that contains `;`, backticks, or
 *   `$(...)` is data, not syntax. The only way to get a shell here is to make one the executable.
 * - The executable must be an absolute path. A bare name would be resolved through `PATH`, which an
 *   attacker who can influence the environment could redirect.
 * - The environment is built from an allowlist. The parent environment is never inherited wholesale:
 *   it routinely contains credentials, proxy settings, and paths that a tool has no need for.
 * - Output is capped. A process that prints without bound is killed rather than filling memory.
 * - A deadline is enforced with SIGTERM and then SIGKILL. `detached` is used on POSIX so the whole
 *   process group is signalled; killing only the direct child can leave grandchildren running.
 * - Nothing here is called "sandboxing". A spawned process is not isolated, and callers that need
 *   isolation must supply an operator-approved environment.
 */

export interface ProcessSpec {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly envAllowlist?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly stdin?: string;
  /** Grace period between SIGTERM and SIGKILL. */
  readonly killGraceMs?: number;
}

export interface ProcessOutcome {
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly durationMs: number;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly outputTruncated: boolean;
  readonly failure?: 'timeout' | 'output_limit' | 'spawn_error' | 'non_zero_exit';
  readonly errorMessage?: string;
}

export class ProcessError extends Error {
  readonly outcome: ProcessOutcome;

  constructor(message: string, outcome: ProcessOutcome) {
    super(message);
    this.name = 'ProcessError';
    this.outcome = outcome;
  }
}

export function buildEnvironment(
  allowlist: readonly string[],
  extras: Readonly<Record<string, string>> = {},
  parent: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const name of allowlist) {
    const value = parent[name];
    if (value !== undefined) env[name] = value;
  }
  for (const [name, value] of Object.entries(extras)) env[name] = value;
  return env;
}

export async function runProcess(spec: ProcessSpec): Promise<ProcessOutcome> {
  if (!isAbsolute(spec.executable)) {
    const outcome = failedOutcome(`executable must be an absolute path, received '${spec.executable}'`, 'spawn_error');
    return outcome;
  }

  const started = Date.now();
  const env = buildEnvironment(spec.envAllowlist ?? [], spec.env ?? {});
  const maxOutput = spec.maxOutputBytes;

  return await new Promise<ProcessOutcome>((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(spec.executable, [...spec.args], {
        cwd: spec.cwd,
        env,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      });
    } catch (error) {
      resolve(failedOutcome(`could not start '${spec.executable}': ${(error as Error).message}`, 'spawn_error'));
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let outputTruncated = false;
    let timedOut = false;
    let settled = false;
    let graceTimer: NodeJS.Timeout | undefined;

    const terminate = (signal: NodeJS.Signals): void => {
      try {
        if (process.platform !== 'win32' && child.pid !== undefined) {
          // Negative pid signals the whole process group, so grandchildren do not survive.
          process.kill(-child.pid, signal);
        } else {
          child.kill(signal);
        }
      } catch {
        // The process may already be gone; that is not an error worth surfacing.
      }
    };

    const finish = (exitCode: number | null, signal: NodeJS.Signals | null, failure?: ProcessOutcome['failure'], errorMessage?: string): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (graceTimer !== undefined) clearTimeout(graceTimer);

      const finished = Date.now();
      resolve({
        startedAt: new Date(started).toISOString(),
        finishedAt: new Date(finished).toISOString(),
        durationMs: finished - started,
        exitCode,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        outputTruncated,
        ...(failure === undefined ? {} : { failure }),
        ...(errorMessage === undefined ? {} : { errorMessage }),
      });
    };

    const timer = setTimeout(() => {
      timedOut = true;
      terminate('SIGTERM');
      graceTimer = setTimeout(() => terminate('SIGKILL'), spec.killGraceMs ?? 2_000);
    }, spec.timeoutMs);

    const capture = (chunk: Buffer, into: Buffer[], kind: 'stdout' | 'stderr'): void => {
      const used = kind === 'stdout' ? stdoutBytes : stderrBytes;
      const remaining = maxOutput - used;
      if (remaining <= 0) {
        outputTruncated = true;
        terminate('SIGTERM');
        return;
      }
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
      into.push(slice);
      if (kind === 'stdout') stdoutBytes += slice.length;
      else stderrBytes += slice.length;
      if (chunk.length > remaining) {
        outputTruncated = true;
        terminate('SIGTERM');
      }
    };

    child.stdout?.on('data', (chunk: Buffer) => capture(chunk, stdoutChunks, 'stdout'));
    child.stderr?.on('data', (chunk: Buffer) => capture(chunk, stderrChunks, 'stderr'));

    child.on('error', (error) => {
      finish(null, null, 'spawn_error', `'${spec.executable}' failed to start: ${error.message}`);
    });

    child.on('close', (code, signal) => {
      if (timedOut) finish(code, signal, 'timeout', `terminated after ${spec.timeoutMs}ms`);
      else if (outputTruncated) finish(code, signal, 'output_limit', `output exceeded ${maxOutput} bytes`);
      else if (code !== 0) finish(code, signal, 'non_zero_exit', `exited with code ${String(code)}`);
      else finish(code, signal);
    });

    if (spec.stdin !== undefined) {
      child.stdin?.end(spec.stdin);
    } else {
      child.stdin?.end();
    }
  });
}

function failedOutcome(message: string, failure: NonNullable<ProcessOutcome['failure']>): ProcessOutcome {
  const now = new Date().toISOString();
  return {
    startedAt: now,
    finishedAt: now,
    durationMs: 0,
    exitCode: null,
    signal: null,
    stdout: '',
    stderr: '',
    timedOut: false,
    outputTruncated: false,
    failure,
    errorMessage: message,
  };
}
