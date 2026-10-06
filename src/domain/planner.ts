import { canonicalDigest } from '../evidence/digest.js';
import type { Profile } from './definitions.js';
import { evaluateApplicability, coverageGap, type ApplicabilityRule, type ManifestLike } from './applicability.js';
import type {
  Environment,
  ExecutionPlan,
  ExpectedCheck,
  GatePolicy,
  ManifestRecord,
  Stage,
} from './types.js';

export interface PlanInput {
  readonly stage: Stage;
  readonly environment: Environment;
  readonly manifest: ManifestRecord;
  readonly profiles: readonly Profile[];
  readonly controls: readonly {
    readonly definition_version?: number;
    readonly id: string;
    readonly applicability: ApplicabilityRule;
    readonly verification: readonly {
      readonly method: string;
      readonly recipe?: string;
      readonly recipe_version?: string;
      readonly coverage: 'automated' | 'mixed' | 'manual_only';
    }[];
  }[];
  readonly policy: GatePolicy;
  readonly policyCommit: string;
  readonly policyDigests: {
    readonly controlCatalogue: string;
    readonly gatePolicy: string;
    readonly profiles: Readonly<Record<string, string>>;
  };
  readonly sourceCommit: string;
  readonly sourceDirty: boolean;
  readonly now: Date;
  readonly planId: string;
  readonly appManifestDigest?: string;
  readonly targets?: ExecutionPlan['inputs']['targets'];
}

const STAGE_METHODS: Readonly<Record<string, readonly string[]>> = {
  pr: ['schema_validation', 'policy_consistency', 'secret_scan', 'dependency_scan', 'static_analysis', 'workflow_analysis', 'authorization_test', 'functional_test', 'build_check', 'client_asset_inspection', 'live_http_check', 'tls_check', 'manual_attestation'],
  release: ['schema_validation', 'policy_consistency', 'secret_scan', 'dependency_scan', 'static_analysis', 'workflow_analysis', 'authorization_test', 'functional_test', 'build_check', 'client_asset_inspection', 'live_http_check', 'tls_check', 'manual_attestation'],
  operations: ['schema_validation', 'policy_consistency', 'dependency_scan', 'manual_attestation'],
};

/**
 * Derives the expected check list before anything runs.
 *
 * The plan's own identity is a digest over its policy inputs, so an altered plan is detectable. It
 * cannot remove a required check: requiredness comes from the profile and gate policy, never from
 * the consumer's configuration.
 */
export function buildPlan(input: PlanInput): ExecutionPlan {
  const controlById = new Map(input.controls.map((control) => [control.id, control]));
  const selected = new Map<string, { profile: string; required: boolean }>();

  for (const profile of input.profiles) {
    for (const entry of profile.controls) {
      const existing = selected.get(entry.control);
      const required = entry.required ?? true;
      if (existing) {
        existing.required = existing.required || required;
        continue;
      }
      selected.set(entry.control, { profile: profile.id, required });
    }
  }

  const stagePolicy = input.policy.stages[input.stage];
  if (stagePolicy === undefined) {
    throw new Error(`unknown stage '${input.stage}': no requirements are defined for it`);
  }

  const requiredMethods = new Set<string>(STAGE_METHODS[input.stage] ?? []);
  for (const profile of input.profiles) {
    for (const method of profile.stage_requirements[input.stage]?.required_methods ?? []) {
      requiredMethods.add(method);
    }
  }

  const checks: ExpectedCheck[] = [];
  for (const [controlId, selection] of selected) {
    const control = controlById.get(controlId);
    if (control === undefined) continue;

    // Applicability is evaluated for the plan's environment. `unknown` still plans checks: an
    // undeclared feature keeps its obligation and makes the result visible as unknown later.
    const applicability = evaluateApplicability(
      control.applicability as ApplicabilityRule,
      input.manifest as ManifestLike,
      input.environment,
    );
    if (applicability === 'not_applicable') continue;

    for (const method of control.verification) {
      if (method.coverage === 'manual_only') continue;
      if (!requiredMethods.has(method.method)) continue;

      checks.push({
        // A control may declare the same method twice for different recipes (SEC-01 scans the repository
        // and the history separately), so the recipe is part of the identity.
        check_id: `${controlId}:${method.method}:${method.recipe ?? "unimplemented"}:${input.stage}`,
        control_ids: [controlId],
        method: method.method,
        recipe: method.recipe ?? `${method.method}/unimplemented`,
        // A planned check always records a recipe version. "1" is this build's version for every
        // recipe; an unimplemented recipe reports 0 when it runs.
        recipe_version: method.recipe_version ?? '1',
        stage: input.stage,
        environment: input.environment,
        required: selection.required,
        identity: {
          source_commit: input.sourceCommit,
          policy_commit: input.policyCommit,
          ...(input.appManifestDigest === undefined ? {} : { configuration_digest: input.appManifestDigest }),
        },
        expected_scope: scopeFor(method.method, input.environment),
        execution: {
          mode: 'internal',
          timeout_ms: 600_000,
          max_output_bytes: 8 * 1024 * 1024,
          requires_isolation: false,
        },
        required_coverage: method.coverage === 'automated' ? 'complete' : 'partial',
        evidence_freshness: {
          ...(stagePolicy.advisory_snapshot_max_age_hours === undefined
            ? {}
            : { advisory_max_age_hours: stagePolicy.advisory_snapshot_max_age_hours }),
        },
      });
    }
  }

  checks.sort((a, b) => (a.check_id < b.check_id ? -1 : a.check_id > b.check_id ? 1 : 0));

  const plan: ExecutionPlan = {
    schema_version: 'execution-plan/v1',
    plan_id: input.planId,
    stage: input.stage,
    environment: input.environment,
    created_at: input.now.toISOString(),
    policy_identity: {
      commit: input.policyCommit,
      control_catalogue_digest: input.policyDigests.controlCatalogue,
      gate_policy_digest: input.policyDigests.gatePolicy,
      profile_digests: input.policyDigests.profiles,
    },
    inputs: {
      app_id: input.manifest.id,
      ...(input.appManifestDigest === undefined ? {} : { app_manifest_digest: input.appManifestDigest }),
      source_commit: input.sourceCommit,
      source_dirty: input.sourceDirty,
      profiles: input.manifest.profiles,
      ...(input.targets === undefined ? {} : { targets: input.targets }),
    },
    expected_checks: checks,
  };

  return plan;
}

/**
 * Identity of a plan's policy inputs. Recomputed and compared when results are evaluated, so a plan
 * edited to drop a required check no longer matches the policy it claims to implement.
 */
export function planIdentity(plan: ExecutionPlan): string {
  return canonicalDigest({
    stage: plan.stage,
    environment: plan.environment,
    policy_identity: plan.policy_identity,
    inputs: plan.inputs,
    expected_checks: plan.expected_checks.map((check) => ({
      check_id: check.check_id,
      control_ids: check.control_ids,
      method: check.method,
      recipe: check.recipe,
      required: check.required,
      required_coverage: check.required_coverage,
    })),
  });
}

function scopeFor(method: string, environment: Environment): ExpectedCheck['expected_scope'] {
  switch (method) {
    case 'secret_scan':
      return { min_files: 1, description: 'Every tracked file plus recorded history scope' };
    case 'dependency_scan':
      return { require_lockfile: true, min_files: 1, description: 'The committed lockfile and its full graph' };
    case 'static_analysis':
      return { min_languages: ['typescript'], min_files: 1, description: 'Expected source languages and rule pack' };
    case 'workflow_analysis':
      return { min_files: 1, description: 'Every workflow file under .github/workflows' };
    case 'client_asset_inspection':
      return { min_files: 1, description: 'Browser-shipped bundle output' };
    case 'live_http_check':
      return { min_routes: 1, description: 'Approved route inventory for the target' };
    case 'tls_check':
      return { min_routes: 1, description: 'The approved production host' };
    case 'authorization_test':
      // An authorization test is scoped by actor and operation combinations, not by HTTP routes. The
      // owning control is what decides the combinations, so the scope records examined cases.
      return { min_files: 1, description: 'Owner, non-owner, and anonymous actor combinations with verified data effects' };
    case 'build_check':
      return { min_files: 1, description: 'The production build output' };
    case 'schema_validation':
    case 'policy_consistency':
      return { min_files: 1, description: 'Application and policy records' };
    default:
      return { min_files: 1, description: `Scope established by recipe ${method} in ${environment}` };
  }
}

export function profileCoverageGaps(
  profiles: readonly Profile[],
  manifest: ManifestLike,
): readonly string[] {
  const excluded = new Set<string>();
  for (const profile of profiles) {
    for (const feature of profile.excluded_features ?? []) excluded.add(feature);
  }
  return coverageGap(manifest, [...excluded]);
}
