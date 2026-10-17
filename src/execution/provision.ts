import {
  hasInstallException,
  isInstallHookApproved,
  isRegistryApproved,
  type DependencyPolicy,
} from './policy.js';
import { isAbsolute } from 'node:path';
import { runProcess, type ProcessOutcome } from './process.js';
import { downloadVerified, type DownloadOutcome } from './download.js';
import { extractVersion } from './version.js';

/**
 * Provisioning, kept deliberately separate from checking.
 *
 * `check` must never install a missing tool as a side effect: that would turn "the scanner is not
 * available" into a network fetch triggered by whatever code path happened to notice. Provisioning
 * is an explicit action that states what it intends to install, from where, and under which policy,
 * and it refuses when any of those is not satisfied.
 *
 * A provisioning plan is built and validated before anything runs, so an unapproved item fails
 * without having touched the machine. Execution then runs every step for real — package commands
 * and verified downloads alike — and reports per-step outcomes: a failed or omitted install can
 * never yield a completion claim (P4.1).
 */

export interface ProvisionStep {
  readonly kind: 'package' | 'download';
  readonly name: string;
  readonly version: string;
  /** For a download: the approved URL and the digest that must match. */
  readonly url?: string;
  readonly expectedSha256?: string;
  /** For a download: the absolute path the verified artifact is written to. */
  readonly destination?: string;
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
    | 'missing_url'
    | 'missing_destination'
    | 'missing_registry'
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

    // P4.1: an install must state where it would fetch from when the policy requires a reviewed
    // registry — "approve whatever the manager defaults to" is not a reviewed decision.
    if (step.kind === 'package' && policy.provisioning.require_reviewed_registry === true && step.registry === undefined) {
      blocks.push({
        step,
        reason: 'missing_registry',
        message: `${step.name} names no registry while the policy requires a reviewed one; the install cannot state where it would fetch from`,
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

    if (step.kind === 'download') {
      if (step.url === undefined) {
        blocks.push({ step, reason: 'missing_url', message: `${step.name} is downloaded but names no URL to fetch from` });
        continue;
      }
      if (step.expectedSha256 === undefined || !/^[0-9a-f]{64}$/.test(step.expectedSha256)) {
        blocks.push({ step, reason: 'missing_digest', message: `${step.name} is downloaded but no SHA-256 digest is recorded` });
        continue;
      }
      if (step.destination === undefined || !isAbsolute(step.destination)) {
        blocks.push({
          step,
          reason: 'missing_destination',
          message: `${step.name} is downloaded but names no absolute destination for the verified artifact`,
        });
        continue;
      }
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

export interface ProvisionStepResult {
  readonly step: ProvisionStep;
  /** For a package step: the package-manager process outcome and the exact arguments run. */
  readonly process?: ProcessOutcome;
  readonly args?: readonly string[];
  /** For a download step: the verified-download outcome. */
  readonly download?: DownloadOutcome;
  readonly ok: boolean;
  /** Steps after a failure are not run, and the plan cannot claim they were. */
  readonly notRun?: boolean;
}

export interface ProvisionResult {
  /** True only when every step ran and succeeded: a failed or omitted install cannot claim it. */
  readonly executed: boolean;
  readonly validations: ProvisionValidation;
  readonly steps: readonly ProvisionStepResult[];
  /** Flattened package-manager process outcomes, in run order. */
  readonly outcomes: readonly ProcessOutcome[];
  /** Recorded when the spec names an expected manager version. */
  readonly managerVersion?: { readonly expected: string; readonly observed: string | undefined; readonly matched: boolean };
}

/**
 * Executes a validated plan with the approved package manager.
 *
 * Refuses entirely when validation fails, and refuses when the manager's identity has not been
 * established or its observed version does not match the reviewed exact version. Every step runs
 * for real — package commands with the approved registry passed explicitly, downloads through the
 * verified-download primitive — and the first failed step stops the plan: remaining steps are
 * recorded as not run, because a failed or omitted install cannot claim completion (P4.1).
 * Nothing here runs a shell.
 */
export async function executeProvisionPlan(
  plan: ProvisionPlan,
  policy: DependencyPolicy,
  spec: {
    readonly cwd: string;
    readonly managerExecutable: string;
    readonly managerVersionArgs?: readonly string[];
    /** The reviewed exact package-manager version; a mismatch refuses the plan before any step. */
    readonly expectedManagerVersion?: string;
    readonly timeoutMs?: number;
    readonly maxOutputBytes?: number;
    readonly now?: Date;
    readonly managerBehaviourVerified?: boolean;
    /** Injected for tests so download steps run without the network. */
    readonly fetchImpl?: typeof fetch;
  },
): Promise<ProvisionResult> {
  const validations = validateProvisionPlan(plan, policy, {
    ...(spec.now === undefined ? {} : { now: spec.now }),
    ...(spec.managerBehaviourVerified === undefined ? {} : { managerBehaviourVerified: spec.managerBehaviourVerified }),
  });

  if (!validations.ok) return { executed: false, validations, steps: [], outcomes: [] };

  const outcomes: ProcessOutcome[] = [];
  const steps: ProvisionStepResult[] = [];

  const versionOutcome = await runProcess({
    executable: spec.managerExecutable,
    args: [...(spec.managerVersionArgs ?? ['--version'])],
    cwd: spec.cwd,
    timeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
  });
  outcomes.push(versionOutcome);
  if (versionOutcome.exitCode !== 0) {
    return { executed: false, validations, steps, outcomes };
  }

  // P4.1: the observed package-manager version must match the reviewed exact version — a manager
  // that is not the reviewed one is not the manager the policy was written for.
  let managerVersion: ProvisionResult['managerVersion'];
  if (spec.expectedManagerVersion !== undefined) {
    const observed = extractVersion(`${versionOutcome.stdout}\n${versionOutcome.stderr}`);
    const matched = observed === spec.expectedManagerVersion;
    managerVersion = { expected: spec.expectedManagerVersion, observed, matched };
    if (!matched) {
      return { executed: false, validations, steps, outcomes, managerVersion };
    }
  }

  for (let index = 0; index < plan.steps.length; index += 1) {
    const step = plan.steps[index] as ProvisionStep;

    if (step.kind === 'package') {
      // P4.1: the approved registry is passed to the manager explicitly, not left to whatever the
      // manager defaults to.
      const args = [
        'add',
        '--save-exact',
        '--frozen-lockfile=false',
        ...(step.registry === undefined ? [] : ['--registry', step.registry]),
        `${step.name}@${step.version}`,
      ];
      const outcome = await runProcess({
        executable: spec.managerExecutable,
        args,
        cwd: spec.cwd,
        timeoutMs: spec.timeoutMs ?? 600_000,
        maxOutputBytes: spec.maxOutputBytes ?? 8 * 1024 * 1024,
      });
      outcomes.push(outcome);
      const ok = outcome.exitCode === 0 && outcome.failure === undefined;
      steps.push({ step, process: outcome, args, ok });
      if (!ok) {
        for (const remaining of plan.steps.slice(index + 1)) steps.push({ step: remaining, ok: false, notRun: true });
        return { executed: false, validations, steps, outcomes, ...(managerVersion === undefined ? {} : { managerVersion }) };
      }
      continue;
    }

    // P4.1: a download step is executed, never skipped — the verified-download primitive enforces
    // the approved origin, the recorded digest, and the byte bound, and writes the artifact
    // atomically. A failed download stops the plan like a failed install.
    const download = await downloadVerified({
      url: step.url ?? '',
      expectedSha256: step.expectedSha256 ?? '',
      destination: step.destination ?? '',
      policy,
      ...(spec.fetchImpl === undefined ? {} : { fetchImpl: spec.fetchImpl }),
    });
    steps.push({ step, download, ok: download.ok });
    if (!download.ok) {
      for (const remaining of plan.steps.slice(index + 1)) steps.push({ step: remaining, ok: false, notRun: true });
      return { executed: false, validations, steps, outcomes, ...(managerVersion === undefined ? {} : { managerVersion }) };
    }
  }

  return {
    executed: true,
    validations,
    steps,
    outcomes,
    ...(managerVersion === undefined ? {} : { managerVersion }),
  };
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
