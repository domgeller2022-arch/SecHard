import {
  hasInstallException,
  isInstallHookApproved,
  isRegistryApproved,
  type DependencyPolicy,
} from './policy.js';
import { runProcess, type ProcessOutcome } from './process.js';

/**
 * Provisioning, kept deliberately separate from checking.
 *
 * `check` must never install a missing tool as a side effect: that would turn "the scanner is not
 * available" into a network fetch triggered by whatever code path happened to notice. Provisioning
 * is an explicit action that states what it intends to install, from where, and under which policy,
 * and it refuses when any of those is not satisfied.
 *
 * A provisioning plan is built and validated before anything runs, so an unapproved item fails
 * without having touched the machine.
 */

export interface ProvisionStep {
  readonly kind: 'package' | 'download';
  readonly name: string;
  readonly version: string;
  /** For a download: the approved URL and the digest that must match. */
  readonly url?: string;
  readonly expectedSha256?: string;
  readonly registry?: string;
  readonly installHooks?: readonly string[];
  readonly manager?: 'pnpm';
}

export interface ProvisionPlan {
  readonly steps: readonly ProvisionStep[];
}

export interface ProvisionBlock {
  readonly step: ProvisionStep;
  readonly reason:
    | 'unreviewed_registry'
    | 'version_not_exact'
    | 'age_policy_unverified'
    | 'unapproved_install_hook'
    | 'missing_digest'
    | 'manager_not_permitted';
  readonly message: string;
}

export interface ProvisionValidation {
  readonly ok: boolean;
  readonly blocks: readonly ProvisionBlock[];
}

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/**
 * Validates a provisioning plan against policy without executing anything.
 *
 * The package-manager behaviour that would enforce the release-age delay (pnpm's
 * `minimumReleaseAge`) is a separate, testable setting; see `verifyAgePolicy`. When the manager is
 * not available or its behaviour has not been established, the plan is blocked rather than assumed
 * safe.
 */
export function validateProvisionPlan(
  plan: ProvisionPlan,
  policy: DependencyPolicy,
  options: { readonly now?: Date; readonly managerBehaviourVerified?: boolean } = {},
): ProvisionValidation {
  const now = options.now ?? new Date();
  const blocks: ProvisionBlock[] = [];

  for (const step of plan.steps) {
    if (!EXACT_VERSION.test(step.version)) {
      blocks.push({
        step,
        reason: 'version_not_exact',
        message: `${step.name}@${step.version} is not an exact version; a range cannot be reviewed or excepted`,
      });
      continue;
    }

    if (step.registry !== undefined && !isRegistryApproved(policy, step.registry)) {
      blocks.push({ step, reason: 'unreviewed_registry', message: `registry '${step.registry}' is not in the reviewed registry list` });
      continue;
    }

    // An urgent fix may be younger than the age delay only through an exact, expiring exception.
    // The delay itself is enforced by the package manager; when that behaviour has not been
    // established, the plan is blocked instead of being assumed to have applied.
    if (options.managerBehaviourVerified !== true && !hasInstallException(policy, step.name, step.version, now)) {
      blocks.push({
        step,
        reason: 'age_policy_unverified',
        message: `${step.name}@${step.version} has no install exception and the ${policy.minimum_release_age_minutes}-minute release-age enforcement has not been verified on this machine`,
      });
      continue;
    }

    if (step.kind === 'download' && (step.expectedSha256 === undefined || !/^[0-9a-f]{64}$/.test(step.expectedSha256))) {
      blocks.push({ step, reason: 'missing_digest', message: `${step.name} is downloaded but no SHA-256 digest is recorded` });
      continue;
    }

    for (const hook of step.installHooks ?? []) {
      if (step.kind === 'package' && !isInstallHookApproved(policy, step.name, hook, now)) {
        blocks.push({
          step,
          reason: 'unapproved_install_hook',
          message: `install hook '${hook}' for ${step.name} is not on the reviewed allowlist, so it must not run`,
        });
      }
    }
  }

  return { ok: blocks.length === 0, blocks };
}

export interface ProvisionResult {
  readonly executed: boolean;
  readonly validations: ProvisionValidation;
  readonly outcomes: readonly ProcessOutcome[];
}

/**
 * Executes a validated plan with the approved package manager.
 *
 * Refuses entirely when validation fails, and refuses when the manager's identity has not been
 * established. Nothing here runs a shell.
 */
export async function executeProvisionPlan(
  plan: ProvisionPlan,
  policy: DependencyPolicy,
  spec: {
    readonly cwd: string;
    readonly managerExecutable: string;
    readonly managerVersionArgs?: readonly string[];
    readonly timeoutMs?: number;
    readonly maxOutputBytes?: number;
    readonly now?: Date;
    readonly managerBehaviourVerified?: boolean;
  },
): Promise<ProvisionResult> {
  const validations = validateProvisionPlan(plan, policy, {
    ...(spec.now === undefined ? {} : { now: spec.now }),
    ...(spec.managerBehaviourVerified === undefined ? {} : { managerBehaviourVerified: spec.managerBehaviourVerified }),
  });

  if (!validations.ok) return { executed: false, validations, outcomes: [] };

  const outcomes: ProcessOutcome[] = [];

  const versionOutcome = await runProcess({
    executable: spec.managerExecutable,
    args: [...(spec.managerVersionArgs ?? ['--version'])],
    cwd: spec.cwd,
    timeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  });
  outcomes.push(versionOutcome);
  if (versionOutcome.exitCode !== 0) {
    return { executed: false, validations, outcomes };
  }

  for (const step of plan.steps) {
    if (step.kind !== 'package') continue;
    const args = ['add', '--save-exact', '--frozen-lockfile=false', `${step.name}@${step.version}`];
    outcomes.push(
      await runProcess({
        executable: spec.managerExecutable,
        args,
        cwd: spec.cwd,
        timeoutMs: spec.timeoutMs ?? 600_000,
        maxOutputBytes: spec.maxOutputBytes ?? 8 * 1024 * 1024,
      }),
    );
  }

  return { executed: true, validations, outcomes };
}

/**
 * The install-script decision for a dependency, as data.
 *
 * With `default: disabled`, an unapproved hook must remain disabled. This function is what a caller
 * consults; the package manager's own configuration is verified separately in `verifyInstallPolicy`.
 */
export function installScriptDecision(
  policy: DependencyPolicy,
  packageName: string,
  hook: string,
  now: Date = new Date(),
): 'allowed' | 'blocked' {
  return isInstallHookApproved(policy, packageName, hook, now) ? 'allowed' : 'blocked';
}
