import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parse } from 'yaml';
import { issue, type ValidationIssue } from '../validation/errors.js';

/**
 * The reviewed dependency and provisioning policy, loaded from the policy root.
 *
 * Policy files are authored in this repository rather than supplied by an application, so a parse
 * failure is a repository defect. It still fails loudly: a runner with no policy must not behave as
 * though everything is permitted.
 */

export interface RegistryEntry {
  readonly id: string;
  readonly url: string;
  readonly reviewed_at: string;
  readonly notes?: string;
}

export interface InstallHookAllowance {
  readonly package: string;
  readonly hook: string;
  readonly reason: string;
  readonly approved_by: string;
  readonly approved_at: string;
  readonly expires_at: string;
}

export interface InstallException {
  readonly package: string;
  readonly version: string;
  readonly reason: string;
  readonly approved_by: string;
  readonly approved_at: string;
  readonly expires_at: string;
  readonly verification_ref?: string;
}

export interface DependencyPolicy {
  readonly schema: string;
  readonly policy_version: number;
  readonly review_status: 'draft' | 'owner_reviewed';
  readonly minimum_release_age_minutes: number;
  readonly registries: {
    readonly allow_additional_registries: boolean;
    readonly allowed: readonly RegistryEntry[];
  };
  readonly install_scripts: {
    readonly default: 'disabled' | 'enabled';
    readonly allowed_hooks: readonly InstallHookAllowance[];
  };
  readonly install_exceptions: readonly InstallException[];
  readonly urgent_fix_route: {
    readonly permitted: boolean;
    readonly requires_exact_version: boolean;
    readonly requires_expiry: boolean;
    readonly requires_approval: boolean;
    readonly max_exception_days: number;
  };
  readonly provisioning: {
    readonly separate_from_checking: boolean;
    readonly require_digest_for_execution: boolean;
    readonly require_reviewed_registry: boolean;
    readonly require_recorded_identity: boolean;
  };
  readonly application_execution: {
    readonly requires_operator_approved_environment: boolean;
    readonly isolation_is_operator_responsibility: boolean;
    readonly notes?: string;
  };
}

export interface PolicyLoadResult {
  readonly policy?: DependencyPolicy;
  readonly issues: readonly ValidationIssue[];
}

export function loadDependencyPolicy(file: string, now: Date = new Date()): PolicyLoadResult {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return { issues: [issue('input.not_found', 'dependency policy file was not found', file)] };
  }

  let policy: DependencyPolicy;
  try {
    policy = parse(raw) as DependencyPolicy;
  } catch (error) {
    return { issues: [issue('input.parse_error', `dependency policy could not be parsed: ${(error as Error).message}`, file)] };
  }

  return { policy, issues: checkDependencyPolicy(policy, now, file) };
}

/**
 * Semantic checks that a schema would not express: that the age delay is the intended value, that
 * every allowance names a real approver and an expiry, and that no exemption is permanent or
 * package-wide.
 */
export function checkDependencyPolicy(
  policy: DependencyPolicy,
  now: Date,
  file?: string,
): readonly ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (policy.schema !== 'hardening/dependency-policy/v1') {
    issues.push(issue('semantic.missing_field', `unexpected dependency policy schema '${String(policy.schema)}'`, file));
  }

  if (policy.minimum_release_age_minutes !== 10080) {
    issues.push({
      code: 'semantic.missing_field',
      message: `minimum_release_age_minutes is ${policy.minimum_release_age_minutes}; the reviewed policy is 10080 (7 days). A different value is a policy change.`,
      ...(file === undefined ? {} : { file }),
    });
  }

  if (policy.registries.allowed.length === 0) {
    issues.push(issue('semantic.missing_field', 'no reviewed registry is recorded; provisioning would have nowhere approved to fetch from', file));
  }
  for (const registry of policy.registries.allowed) {
    if (!registry.url.startsWith('https://')) {
      issues.push(issue('semantic.missing_field', `registry '${registry.id}' is not served over HTTPS`, file));
    }
    if (Date.parse(registry.reviewed_at) > now.getTime()) {
      issues.push(issue('semantic.invalid_interval', `registry '${registry.id}' records a review date in the future`, file));
    }
  }

  for (const hook of policy.install_scripts.allowed_hooks) {
    if (hook.reason.trim().length < 10 || hook.approved_by.trim().length === 0) {
      issues.push(issue('semantic.missing_field', `install hook for '${hook.package}' needs a reason and an approver`, file));
    }
    if (Date.parse(hook.expires_at) <= now.getTime()) {
      issues.push(issue('semantic.invalid_interval', `install hook allowance for '${hook.package}' has expired`, file));
    }
  }

  for (const exception of policy.install_exceptions) {
    // The whole point of the exception is to be narrow: one exact version, a named approver, a
    // reason, and an expiry. A range or a wildcard would be a permanent blanket exemption.
    if (!/^\d+\.\d+\.\d+/.test(exception.version) || exception.version.includes('*') || exception.version.startsWith('^') || exception.version.startsWith('~')) {
      issues.push(issue('semantic.invalid_exception_scope', `install exception for '${exception.package}' must name an exact version, received '${exception.version}'`, file));
    }
    if (exception.reason.trim().length < 10 || exception.approved_by.trim().length === 0) {
      issues.push(issue('semantic.missing_field', `install exception for '${exception.package}' needs a reason and an approver`, file));
    }
    const expiry = Date.parse(exception.expires_at);
    if (Number.isNaN(expiry) || expiry <= now.getTime()) {
      issues.push(issue('semantic.invalid_interval', `install exception for '${exception.package}' has expired`, file));
    } else {
      const days = (expiry - now.getTime()) / 86_400_000;
      if (days > policy.urgent_fix_route.max_exception_days) {
        issues.push({
          code: 'semantic.invalid_exception_scope',
          message: `install exception for '${exception.package}' runs ${days.toFixed(0)} days, beyond the ${policy.urgent_fix_route.max_exception_days}-day maximum`,
          ...(file === undefined ? {} : { file }),
        });
      }
    }
  }

  return issues;
}

export function isRegistryApproved(policy: DependencyPolicy, url: string): boolean {
  const normalised = url.replace(/\/+$/, '');
  return policy.registries.allowed.some((registry) => registry.url.replace(/\/+$/, '') === normalised);
}

export function isInstallHookApproved(
  policy: DependencyPolicy,
  packageName: string,
  hook: string,
  now: Date,
): boolean {
  if (policy.install_scripts.default !== 'disabled') return false;
  return policy.install_scripts.allowed_hooks.some(
    (allowance) =>
      allowance.package === packageName &&
      allowance.hook === hook &&
      Date.parse(allowance.expires_at) > now.getTime(),
  );
}

export function hasInstallException(
  policy: DependencyPolicy,
  packageName: string,
  version: string,
  now: Date,
): boolean {
  return policy.install_exceptions.some(
    (exception) =>
      exception.package === packageName &&
      exception.version === version &&
      Date.parse(exception.expires_at) > now.getTime(),
  );
}

export function assertAbsoluteExecutable(executable: string): void {
  if (!isAbsolute(executable)) {
    throw new Error(`refusing to execute a non-absolute path '${executable}': PATH lookup is not trusted`);
  }
}
