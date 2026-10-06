import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { loadCatalogue, loadProfile } from '../../src/domain/definitions.js';
import { buildPlan, planIdentity, type PlanInput } from '../../src/domain/planner.js';
import { evaluate } from '../../src/domain/evaluator.js';
import { definitionContentDigest, type ApprovalRecord } from '../../src/domain/approval.js';
import type {
  CheckResult,
  ExceptionRecord,
  ExecutionPlan,
  GatePolicy,
  ManifestRecord,
  ManualEvidence,
  Profile,
} from '../../src/domain/types.js';
import type { ControlDefinition } from '../../src/domain/definitions.js';
import type { ApplicabilityRule } from '../../src/domain/applicability.js';

export const NOW = new Date('2026-10-06T12:00:00Z');
export const SOURCE_COMMIT = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const RUN_ID = 'run-1';
export const POLICY_COMMIT = 'f0e1d2c3b4a5968778695a4b3c2d1e0f99887766';

export const policy: GatePolicy = (() => {
  const raw = readFileSync(join(import.meta.dirname, '..', '..', 'policy', 'gate-policy.yaml'), 'utf8');
  return parse(raw) as GatePolicy;
})();

export const catalogue: readonly ControlDefinition[] = loadCatalogue().controls;
export const coreProfile: Profile = loadProfile('core');
export const referenceProfile: Profile = loadProfile('nextjs-supabase');

export function manifest(overrides: Partial<ManifestRecord['features']> = {}): ManifestRecord {
  const disabled = { state: 'disabled' } as const;
  const enabled = { state: 'enabled' } as const;

  return {
    id: 'demo',
    features: {
      accounts: enabled,
      private_resources: enabled,
      roles: disabled,
      tenancy: disabled,
      recovery: enabled,
      payments: disabled,
      webhooks: disabled,
      uploads: disabled,
      outbound_requests: disabled,
      personal_data: disabled,
      runtime_ai: disabled,
      hosting: enabled,
      interfaces: enabled,
      environments: enabled,
      persistent_storage: enabled,
      ...overrides,
    },
    environments: [
      { name: 'local', kind: 'local', internet_facing: false, separated: true },
      { name: 'production', kind: 'production', internet_facing: true, separated: true },
    ],
    profiles: ['nextjs-supabase'],
    policy_lock: {
      repository: 'example/hardening',
      commit: POLICY_COMMIT,
      policy_digest: 'b'.repeat(64),
    },
  };
}

export function planFor(
  stage: 'pr' | 'release' | 'operations' = 'pr',
  options: { profiles?: readonly Profile[]; manifest?: ManifestRecord; sourceDirty?: boolean } = {},
): ExecutionPlan {
  const selected = options.profiles ?? [referenceProfile];
  return buildPlan({
    stage,
    environment: stage === 'release' ? 'production' : 'local',
    manifest: options.manifest ?? manifest(),
    profiles: selected,
    controls: catalogue as unknown as PlanInput["controls"],
    policy,
    policyCommit: POLICY_COMMIT,
    policyDigests: {
      controlCatalogue: 'c'.repeat(64),
      gatePolicy: 'd'.repeat(64),
      profiles: Object.fromEntries(selected.map((profile) => [profile.id, 'e'.repeat(64)])),
    },
    sourceCommit: SOURCE_COMMIT,
    sourceDirty: options.sourceDirty ?? false,
    now: NOW,
    planId: `plan-${stage}-demo`,
    runId: RUN_ID,
    appManifestDigest: 'f'.repeat(64),
  });
}

/** A result that genuinely satisfies its planned check: right identity, real tool, examined scope. */
export function passingResult(
  check: {
    check_id: string;
    control_ids: readonly string[];
    recipe: string;
    stage?: CheckResult['stage'];
    environment?: CheckResult['environment'];
    identity: {
      source_commit: string;
      policy_commit: string;
      configuration_digest?: string;
      run_id?: string;
      attempt?: number;
    };
  },
  overrides: Partial<CheckResult> = {},
): CheckResult {
  return {
    schema_version: 'check-result/v1',
    run_id: 'run-1',
    check_id: check.check_id,
    control_ids: check.control_ids,
    recipe: check.recipe,
    stage: check.stage ?? 'pr',
    environment: check.environment ?? 'local',
    required: true,
    outcome: 'pass',
    coverage: 'complete',
    tool: { name: 'internal', observed_version: '1', rule_pack: 'typescript' },
    identity: {
      source_commit: SOURCE_COMMIT,
      policy_commit: POLICY_COMMIT,
      run_id: check.identity.run_id ?? RUN_ID,
      attempt: check.identity.attempt ?? 1,
      ...(check.identity.configuration_digest === undefined ? {} : { configuration_digest: check.identity.configuration_digest }),
    },
    started_at: '2026-10-06T11:55:00Z',
    finished_at: '2026-10-06T11:56:00Z',
    scope: { expected: 1, observed: 12, files: ['a.ts', 'b.ts'], routes: ['/notes'] },
    findings: [],
    evidence_origin: 'actual_tool',
    ...overrides,
  };
}

export function allPassing(plan: ExecutionPlan, overrides: Partial<CheckResult> = {}): CheckResult[] {
  return plan.expected_checks.map((check) => passingResult(check, overrides));
}

export function evaluateWith(input: {
  plan: ExecutionPlan;
  results: readonly CheckResult[];
  manualEvidence?: readonly ManualEvidence[];
  exceptions?: readonly ExceptionRecord[];
  stage?: 'pr' | 'release' | 'operations';
  environment?: 'local' | 'preview' | 'staging' | 'production';
  manifest?: ManifestRecord;
  profiles?: readonly Profile[];
  now?: Date;
  expectedPlanIdentity?: string;
  approvals?: readonly ApprovalRecord[];
}) {
  const stage = input.stage ?? 'pr';
  const environment = input.environment ?? 'local';
  const profiles = input.profiles ?? [referenceProfile];

  return evaluate({
    stage,
    environment,
    manifest: input.manifest ?? manifest(),
    controls: catalogue.map((control) => ({
      id: control.id,
      definition_version: control.definition_version,
      applicability: control.applicability as ApplicabilityRule,
    })),
    plan: input.plan,
    results: input.results,
    manualEvidence: input.manualEvidence ?? [],
    exceptions: input.exceptions ?? [],
    approvals: input.approvals ?? [],
    controlDefinitions: catalogue,
    policy,
    now: input.now ?? NOW,
    planIdentity: planIdentity(input.plan),
    ...(input.expectedPlanIdentity === undefined ? {} : { expectedPlanIdentity: input.expectedPlanIdentity }),
    excludedFeatures: profiles.flatMap((profile) => profile.excluded_features ?? []),
  });
}

export const manualEvidence = (overrides: Partial<ManualEvidence> = {}): ManualEvidence => ({
  schema_version: 'manual-evidence/v1',
  id: 'ME-TEST-1',
  control: 'CTX-01',
  recipe: 'inventory/review',
  operator: { identity: 'operator', independent_of_owner: false },
  observed_at: '2026-10-01T00:00:00Z',
  target: { environment: 'local' },
  scope_fingerprint: 'fp-1',
  outcome: 'pass',
  expires_at: '2026-11-01T00:00:00Z',
  ...overrides,
});

/** An approval for a control as it currently exists, at its current content digest. */
export function approvalFor(id: string, overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  const definition = catalogue.find((control) => control.id === id);
  if (definition === undefined) throw new Error(`no such control ${id}`);
  return {
    control: id,
    definition_version: definition.definition_version,
    content_digest: definitionContentDigest(definition),
    reviewer: 'owner',
    reviewed_at: '2026-10-05T00:00:00Z',
    kind: 'owner',
    ...overrides,
  };
}

export const exceptionFor = (overrides: Partial<ExceptionRecord> = {}): ExceptionRecord => ({
  schema_version: 'exception/v1',
  id: 'EXC-0001',
  status: 'active',
  scope: { control: 'SEC-01', check_id: 'SEC-01:secret_scan:pr', environment: 'production' },
  reason: 'accepted for a recorded reason',
  risk: 'residual risk is recorded',
  compensating_measures: ['monitoring in place'],
  owner: 'maintainer',
  approver: 'maintainer',
  self_review: true,
  expires_at: '2026-12-01T00:00:00Z',
  ...overrides,
});
