import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runTool } from '../execution/registry.js';
import { parseGitleaksReport } from './gitleaks.js';
import { parseOpengrepReport } from './opengrep.js';
import { parseOsvReport } from './osv.js';
import { parseZizmorReport } from './zizmor.js';
import type { AdapterOutcome } from './types.js';

/**
 * Running an adapter recipe.
 *
 * Each recipe runs its tool through the reviewed-executable registry, so the binary must have a
 * verified identity and its digest is checked before execution. The tool's exit code is recorded and
 * interpreted per tool, and a non-zero exit that means "findings present" is not treated as failure.
 */

export interface AdapterRun {
  readonly ran: boolean;
  readonly outcome?: AdapterOutcome;
  readonly error?: string;
  readonly exitCode?: number | null;
  readonly stderr?: string;
  readonly durationMs?: number;
  /** SHA-256 of the original report bytes, so evidence can reference exactly what was parsed. */
  readonly reportDigest?: string;
  readonly reportPath?: string;
}

export interface AdapterRecipe {
  readonly name: 'gitleaks' | 'osv_scanner' | 'opengrep' | 'zizmor';
  readonly args: readonly string[];
  /** Exit codes that mean "the scan ran", even when findings were reported. */
  readonly successExitCodes: readonly number[];
}

export async function runAdapter(
  recipe: AdapterRecipe,
  spec: { readonly reportPath: string; readonly cwd: string; readonly intendedScope?: readonly string[]; readonly timeoutMs?: number },
): Promise<AdapterRun> {
  const result = await runTool(recipe.name, recipe.args, {
    cwd: spec.cwd,
    timeoutMs: spec.timeoutMs ?? 600_000,
  });

  if (!result.ran || result.outcome === undefined) {
    const availability = result.availability;
    return {
      ran: false,
      error: availability.available
        ? 'tool did not run'
        : `${availability.reason}: ${availability.message}`,
    };
  }

  if (result.outcome.timedOut) {
    return { ran: false, error: `timed out after ${result.outcome.durationMs}ms`, stderr: result.outcome.stderr };
  }

  const exitCode = result.outcome.exitCode;
  const acceptable = exitCode !== null && recipe.successExitCodes.includes(exitCode);
  if (!acceptable) {
    return {
      ran: false,
      error: `unexpected exit code ${String(exitCode)} (signal ${String(result.outcome.signal)})`,
      exitCode,
      stderr: result.outcome.stderr,
      durationMs: result.outcome.durationMs,
    };
  }

  let reportBytes: Buffer;
  try {
    reportBytes = readFileSync(spec.reportPath);
  } catch {
    return { ran: false, error: `report was not written to ${spec.reportPath}`, exitCode, stderr: result.outcome.stderr };
  }
  const raw = reportBytes.toString('utf8');
  const reportDigest = createHash('sha256').update(reportBytes).digest('hex');

  const parsed = parseFor(recipe.name, raw, {
    ...(spec.intendedScope === undefined ? {} : { intendedScope: spec.intendedScope }),
    ...(result.outcome.stderr.length === 0 ? {} : { stderr: result.outcome.stderr }),
  });
  if ('error' in parsed) {
    return { ran: false, error: parsed.error, exitCode, stderr: result.outcome.stderr, durationMs: result.outcome.durationMs };
  }

  return {
    ran: true,
    outcome: parsed,
    exitCode,
    stderr: result.outcome.stderr,
    durationMs: result.outcome.durationMs,
    reportDigest,
    reportPath: spec.reportPath,
  };
}

function parseFor(
  tool: AdapterRecipe['name'],
  raw: string,
  options: { readonly intendedScope?: readonly string[]; readonly stderr?: string },
): AdapterOutcome | { error: string } {
  switch (tool) {
    case 'gitleaks':
      return parseGitleaksReport(raw, {
        ...(options.intendedScope === undefined ? {} : { intendedScope: options.intendedScope }),
        ...(options.stderr === undefined ? {} : { stderr: options.stderr }),
      });
    case 'zizmor':
      return parseZizmorReport(raw, {
        ...(options.intendedScope === undefined ? {} : { intendedScope: options.intendedScope }),
      });
    case 'osv_scanner':
      return parseOsvReport(raw, {
        ...(options.intendedScope === undefined ? {} : { intendedScope: options.intendedScope }),
      });
    case 'opengrep':
      return parseOpengrepReport(raw, {
        ...(options.intendedScope === undefined ? {} : { intendedScope: options.intendedScope }),
      });
  }
}

export { parseGitleaksReport, parseOpengrepReport, parseOsvReport, parseZizmorReport };
export type { AdapterOutcome };
