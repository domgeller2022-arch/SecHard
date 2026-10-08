import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
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
 * Records are platform-aware. A fetched tool is resolved relative to the policy root as
 * `tools/bin/<name>/<version>/<platform>/<binary>`; a platform-provided tool is resolved from its
 * per-platform candidate list. Neither path is ever looked up through `PATH`, and no record contains
 * an absolute path from a particular machine.
 *
 * `checking` never installs. A missing binary produces an error; provisioning is a separate,
 * explicit action (see `provision.ts`).
 */

/** A release asset pinned for one platform. */
export interface PlatformAsset {
  readonly asset: string;
  /** The binary name inside the extracted directory. */
  readonly binary: string;
  readonly archive: 'tar.gz' | 'none';
  /** SHA-256 of the downloaded archive or raw asset, kept as provenance of the download. */
  readonly archiveSha256?: string;
  /** SHA-256 of the executable on disk; this is the pin checked before every run. */
  readonly digest: string;
  readonly expectedVersion: string;
  readonly versionProvenance?: string;
  readonly provenance?: string;
}

export interface ExecutionIdentity {
  readonly name: string;
  readonly kind?: 'platform' | 'fetched';
  /**
   * Direct executable path. Retained for tests and for a record that genuinely pins one path; the
   * reviewed toolchain uses `candidates` and `platforms` instead.
   */
  readonly executable?: string;
  /** Used when `executable` is absent on this machine. Recorded so no PATH lookup is needed. */
  readonly fallbackExecutable?: string;
  /** Platform-provided tools: candidate paths per `<os>-<arch>`, in preference order. */
  readonly candidates?: Readonly<Record<string, readonly string[]>>;
  /** Fetched tools: the pinned asset per `<os>-<arch>`. */
  readonly platforms?: Readonly<Record<string, PlatformAsset>>;
  /** Version directory used to resolve a fetched tool's path. */
  readonly version?: string;
  readonly versionArgs?: readonly string[];
  /** Only present on direct records; platform records carry it per asset. */
  readonly expectedVersion?: string;
  readonly digest?: string;
  readonly fetched: boolean;
  readonly identity: 'verified' | 'unverified';
  readonly source?: string;
  readonly licence?: string;
  readonly provenance?: string;
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
  readonly executables?: Record<string, ExecutionIdentity>;
}

export function loadToolchain(path = join(packageRoot(), 'policy', 'toolchain.yaml')): ToolchainRecord {
  return parse(readFileSync(path, 'utf8')) as ToolchainRecord;
}

/** The platform key used by the toolchain records and provisioning: `<os>-<arch>`. */
export function platformKey(platform: string = process.platform, arch: string = process.arch): string {
  const os = platform === 'darwin' ? 'darwin' : platform === 'linux' ? 'linux' : platform;
  const architecture = arch === 'x64' ? 'x64' : arch === 'arm64' ? 'arm64' : arch;
  return `${os}-${architecture}`;
}

export interface ResolveOptions {
  readonly policyRoot?: string;
  readonly platform?: string;
  /** Injectable for tests: decides whether a candidate path exists on this machine. */
  readonly fileExists?: (path: string) => boolean;
}

export type ToolAvailability =
  | { readonly available: true; readonly identity: ExecutionIdentity; readonly executable: string; readonly expectedVersion: string }
  | { readonly available: false; readonly reason: UnavailableReason; readonly message: string };

export type UnavailableReason =
  | 'not_recorded'
  | 'identity_unverified'
  | 'not_absolute'
  | 'digest_missing'
  | 'digest_mismatch'
  | 'version_metadata_missing'
  | 'not_executable'
  /** The record has no entry for this operating system and architecture. */
  | 'unsupported_platform'
  /** Recorded and verified, but executed through the container runtime rather than as a local binary. */
  | 'container_executed';

/**
 * Resolves a tool against reviewed toolchain data without running it.
 *
 * A recorded-but-unverified tool is refused here. A platform with no pinned asset is refused as
 * `unsupported_platform`: guessing an asset for an unreviewed platform is exactly the kind of
 * inference this registry exists to prevent.
 */
export function resolveTool(name: string, toolchain: ToolchainRecord = loadToolchain(), options: ResolveOptions = {}): ToolAvailability {
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

  const platform = options.platform ?? platformKey();
  const policyRoot = options.policyRoot ?? packageRoot();
  const fileExists = options.fileExists ?? existsSync;

  let executable = identity.executable;
  let expectedVersion = identity.expectedVersion;
  let digest = identity.digest;

  if (identity.candidates !== undefined) {
    const candidates = identity.candidates[platform] ?? [];
    const found = candidates.find((candidate) => fileExists(candidate));
    if (found === undefined) {
      return {
        available: false,
        reason: 'unsupported_platform',
        message: `tool '${name}' has no recorded candidate path on ${platform}; refusal is the correct outcome`,
      };
    }
    executable = found;
  } else if (identity.platforms !== undefined) {
    const asset = identity.platforms[platform];
    if (asset === undefined) {
      return {
        available: false,
        reason: 'unsupported_platform',
        message: `tool '${name}' has no pinned asset for ${platform}; refusing to guess an unreviewed binary`,
      };
    }
    executable = join(policyRoot, 'tools', 'bin', name, identity.version ?? asset.expectedVersion, platform, asset.binary);
    expectedVersion = asset.expectedVersion;
    digest = asset.digest;
  }

  if (executable === undefined || !executable.startsWith('/')) {
    return { available: false, reason: 'not_absolute', message: `tool '${name}' resolves to a non-absolute executable path; PATH lookup is not trusted` };
  }
  if (identity.fetched && (digest === undefined || !/^[0-9a-f]{64}$/.test(digest))) {
    return { available: false, reason: 'digest_missing', message: `tool '${name}' is fetched but has no verified digest` };
  }
  if (expectedVersion === undefined || expectedVersion.trim().length === 0) {
    return { available: false, reason: 'version_metadata_missing', message: `tool '${name}' has no recorded version` };
  }

  // When a digest is recorded, the binary on disk must match it before it runs. A pin that is never
  // checked detects nothing: the file could have been replaced by anything.
  if (digest !== undefined) {
    const observed = digestOfFile(executable);
    if (observed === undefined) {
      return { available: false, reason: 'not_executable', message: `tool '${name}' is not readable at ${executable}` };
    }
    if (observed !== digest) {
      return {
        available: false,
        reason: 'digest_mismatch',
        message: `tool '${name}' does not match its recorded digest (expected ${digest.slice(0, 12)}…, found ${observed.slice(0, 12)}…)`,
      };
    }
  }

  return { available: true, identity, executable, expectedVersion };
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
  /** Platform and policy-root overrides; the reviewed toolchain is resolved relative to the policy root. */
  readonly resolve?: ResolveOptions;
}

/**
 * Runs a tool only after its identity resolves, and only after the installed version matches the
 * recorded one. Both checks happen before the requested arguments are used, and a mismatch returns
 * without running the tool.
 */
export async function runTool(name: string, args: readonly string[], spec: RunToolSpec): Promise<ToolRunResult> {
  const availability = resolveTool(name, spec.toolchain, spec.resolve === undefined ? {} : spec.resolve);
  if (!availability.available) return { ran: false, availability };

  const identity = availability.identity;
  const base: ProcessSpec = {
    executable: availability.executable,
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
  if (observed !== availability.expectedVersion) {
    return {
      ran: false,
      availability: {
        available: false,
        reason: 'version_metadata_missing',
        message: `'${name}' reports version ${observed}, but the toolchain records ${availability.expectedVersion}`,
      },
    };
  }

  const outcome = await runProcess({
    executable: availability.executable,
    args: [...args],
    cwd: spec.cwd,
    timeoutMs: spec.timeoutMs ?? 600_000,
    maxOutputBytes: spec.maxOutputBytes ?? 8 * 1024 * 1024,
    ...(spec.envAllowlist === undefined ? {} : { envAllowlist: spec.envAllowlist }),
  });

  return { ran: true, outcome, availability };
}
