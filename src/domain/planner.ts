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
  readonly runId: string;
  readonly attempt?: number;
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

  // Profiles are authoritative for what a stage requires. The constant is only a fallback for a
  // profile that does not define the stage at all.
  const profileMethods = new Set<string>();
  for (const profile of input.profiles) {
    for (const method of profile.stage_requirements[input.stage]?.required_methods ?? []) {
      profileMethods.add(method);
    }
  }
  const requiredMethods =
    profileMethods.size > 0 ? profileMethods : new Set<string>(STAGE_METHODS[input.stage] ?? []);

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

    const companionRecipes = new Set<string>();
    for (const method of control.verification) {
      if (!requiredMethods.has(method.method)) continue;

      // A human attestation is not a tool run, so it is planned as a manual requirement rather than
      // silently skipped. Skipping it would let an applicable control such as OPS-02 (restore
      // exercise) or PRIV-01 (retention review) never be evaluated at all.
      const manual = method.method === 'manual_attestation' || method.coverage === 'manual_only';

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
          run_id: input.runId,
          attempt: input.attempt ?? 1,
          ...(input.appManifestDigest === undefined ? {} : { configuration_digest: input.appManifestDigest }),
        },
        expected_scope: scopeFor(method.method, input.environment),
        execution: manual
          ? { mode: 'manual' }
          : {
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

      // "Mixed" means tool evidence **plus** reviewed manual evidence (fix brief F-03): a mixed
      // method that only checks the tool result silently accepts partial work. Every mixed method
      // gets its manual companion, so the control is never satisfied by the tool half alone. A
      // control that declares its own manual_attestation method already names the human half —
      // that check covers every mixed method on the control, and a second companion would only
      // duplicate the obligation.
      if (method.coverage !== 'mixed' || manual) continue;
      const declaredManual = control.verification.find((entry) => entry.method === 'manual_attestation');
      const declaredManualPlanned = declaredManual !== undefined && requiredMethods.has('manual_attestation');
      const companionRecipe = declaredManual?.recipe ?? `${method.recipe ?? method.method}/review`;
      if (declaredManualPlanned || companionRecipes.has(companionRecipe)) continue;
      companionRecipes.add(companionRecipe);

      // O-10 stage behaviour, adopted as the recommended default: release gates on the human half,
      // because an obligation that blocks every pull request is one nobody keeps; elsewhere it is
      // recorded and does not block unless the profile opts in.
      const companionRequired = selection.required && (input.stage === 'release' || requiredMethods.has('manual_attestation'));

      checks.push({
        check_id: `${controlId}:manual_attestation:${companionRecipe}:${input.stage}`,
        control_ids: [controlId],
        method: 'manual_attestation',
        recipe: companionRecipe,
        recipe_version: '1',
        stage: input.stage,
        environment: input.environment,
        required: companionRequired,
        identity: {
          source_commit: input.sourceCommit,
          policy_commit: input.policyCommit,
          run_id: input.runId,
          attempt: input.attempt ?? 1,
          ...(input.appManifestDigest === undefined ? {} : { configuration_digest: input.appManifestDigest }),
        },
        expected_scope: scopeFor('manual_attestation', input.environment),
        execution: { mode: 'manual' },
        required_coverage: 'partial',
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
    run_id: input.runId,
    attempt: input.attempt ?? 1,
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
    run_id: plan.run_id,
    attempt: plan.attempt,
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
