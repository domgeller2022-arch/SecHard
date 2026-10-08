import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { packageRoot } from '../validation/schema.js';
import { runProcess, type ProcessOutcome, type ProcessSpec } from './process.js';
import { extractVersion } from './version.js';

/**
 * The reviewed-executable registry.
 *
 * A tool may run only when its identity can be established from reviewed data: an absolute path, a
 * recorded version, and — for anything fetched rather than supplied by the platform — a verified
 * digest. When any of those is missing the answer is `unavailable`, not a guess. Refusing to run an
 * unidentified binary is the control, not an inconvenience.
 *
 * `checking` never installs. A missing binary produces an error; provisioning is a separate,
 * explicit action (see `provision.ts`).
 */

export interface ExecutionIdentity {
  readonly name: string;
  readonly executable: string;
  /** Used when `executable` is absent on this machine. Recorded so no PATH lookup is needed. */
  readonly fallbackExecutable?: string;
  readonly versionArgs?: readonly string[];
  readonly expectedVersion: string;
  readonly digest?: string;
  readonly fetched: boolean;
  readonly identity: 'verified' | 'unverified';
  readonly source?: string;
  readonly licence?: string;
}

export interface ToolchainRecord {
  readonly execution?: {
    readonly require_absolute_path?: boolean;
    readonly require_recorded_version?: boolean;
    readonly require_digest_when_fetched?: boolean;
    readonly default_timeout_ms?: number;
    readonly default_max_output_bytes?: number;
  };
  readonly security_tools?: Record<string, { readonly identity?: string; readonly step?: number; readonly purpose?: string }>;
  /** Optional verified identities. Absent for every scanner today. */
  readonly executables?: Record<string, ExecutionIdentity>;
}

export function loadToolchain(path = join(packageRoot(), 'policy', 'toolchain.yaml')): ToolchainRecord {
  return parse(readFileSync(path, 'utf8')) as ToolchainRecord;
}

export type ToolAvailability =
  | { readonly available: true; readonly identity: ExecutionIdentity }
  | { readonly available: false; readonly reason: UnavailableReason; readonly message: string };

export type UnavailableReason =
  | 'not_recorded'
  | 'identity_unverified'
  | 'not_absolute'
  | 'digest_missing'
  | 'digest_mismatch'
  | 'version_metadata_missing'
  | 'not_executable'
  /** Recorded and verified, but executed through the container runtime rather than as a local binary. */
  | 'container_executed';

/**
 * Resolves a tool against reviewed toolchain data without running it.
 *
 * A recorded-but-unverified tool is refused here. That is the current state of every scanner, and
 * the refusal is the honest answer: executing it would be relying on an identity nobody checked.
 */
export function resolveTool(name: string, toolchain: ToolchainRecord = loadToolchain()): ToolAvailability {
  const identity = toolchain.executables?.[name];

  if (identity === undefined) {
    const declared = toolchain.security_tools?.[name];
    if (declared === undefined) {
      return { available: false, reason: 'not_recorded', message: `tool '${name}' is not recorded in the toolchain` };
    }
    // A tool that runs as a container image is verified through its image digest and observed
    // version, not through this registry. Saying "unverified" here would be wrong; saying "available"
    // would be wrong too, because this registry cannot launch it.
    if (declared.identity === 'verified') {
      return {
        available: false,
        reason: 'container_executed',
        message: `tool '${name}' is recorded with a verified identity but runs through the container runtime, not as a local executable`,
      };
    }
    return {
      available: false,
      reason: 'identity_unverified',
      message: `tool '${name}' has no verified identity; it is selected in Step ${declared.step ?? '?'} and cannot run before then`,
    };
  }

  if (identity.identity !== 'verified') {
    return { available: false, reason: 'identity_unverified', message: `tool '${name}' is recorded with an unverified identity` };
  }
  if (!identity.executable.startsWith('/')) {
    return { available: false, reason: 'not_absolute', message: `tool '${name}' has a non-absolute executable path '${identity.executable}'; PATH lookup is not trusted` };
  }
  if (identity.fetched && (identity.digest === undefined || !/^[0-9a-f]{64}$/.test(identity.digest))) {
    return { available: false, reason: 'digest_missing', message: `tool '${name}' is fetched but has no verified digest` };
  }
  if (identity.expectedVersion.trim().length === 0) {
    return { available: false, reason: 'version_metadata_missing', message: `tool '${name}' has no recorded version` };
  }

  // When a digest is recorded, the binary on disk must match it before it runs. A pin that is never
  // checked detects nothing: the file could have been replaced by anything.
  if (identity.digest !== undefined) {
    const observed = digestOfFile(identity.executable);
    if (observed === undefined) {
      return { available: false, reason: 'not_executable', message: `tool '${name}' is not readable at ${identity.executable}` };
    }
    if (observed !== identity.digest) {
      return {
        available: false,
        reason: 'digest_mismatch',
        message: `tool '${name}' does not match its recorded digest (expected ${identity.digest.slice(0, 12)}…, found ${observed.slice(0, 12)}…)`,
      };
    }
  }

  return { available: true, identity };
}

export function digestOfFile(file: string): string | undefined {
  try {
    return createHash('sha256').update(readFileSync(file)).digest('hex');
  } catch {
    return undefined;
  }
}

export interface ToolRunResult {
  readonly ran: boolean;
  readonly outcome?: ProcessOutcome;
  readonly availability: ToolAvailability;
}

export interface RunToolSpec {
  readonly cwd: string;
  readonly envAllowlist?: readonly string[];
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly toolchain?: ToolchainRecord;
}

/**
 * Runs a tool only after its identity resolves, and only after the installed version matches the
 * recorded one. Both checks happen before the requested arguments are used, and a mismatch returns
 * without running the tool.
 */
export async function runTool(name: string, args: readonly string[], spec: RunToolSpec): Promise<ToolRunResult> {
  const availability = resolveTool(name, spec.toolchain);
  if (!availability.available) return { ran: false, availability };

  const identity = availability.identity;
  const base: ProcessSpec = {
    executable: identity.executable,
    args: [...(identity.versionArgs ?? ['--version'])],
    cwd: spec.cwd,
    timeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ...(spec.envAllowlist === undefined ? {} : { envAllowlist: spec.envAllowlist }),
  };

  const versionOutcome = await runProcess(base);
  const observed = extractVersion(`${versionOutcome.stdout}\n${versionOutcome.stderr}`);
  if (observed === undefined) {
    return {
      ran: false,
      availability: {
        available: false,
        reason: 'version_metadata_missing',
        message: `could not establish the installed version of '${name}'; refusing to treat it as the recorded tool`,
      },
    };
  }
  if (observed !== identity.expectedVersion) {
    return {
      ran: false,
      availability: {
        available: false,
        reason: 'version_metadata_missing',
        message: `'${name}' reports version ${observed}, but the toolchain records ${identity.expectedVersion}`,
      },
    };
  }

  const outcome = await runProcess({
    executable: identity.executable,
    args: [...args],
    cwd: spec.cwd,
    timeoutMs: spec.timeoutMs ?? 600_000,
    maxOutputBytes: spec.maxOutputBytes ?? 8 * 1024 * 1024,
    ...(spec.envAllowlist === undefined ? {} : { envAllowlist: spec.envAllowlist }),
  });

  return { ran: true, outcome, availability };
}
