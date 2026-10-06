import type {
  CheckResult,
  ExceptionRecord,
  ExecutionPlan,
  GateDecision,
  ManualEvidence,
  ReleaseEvidence,
  Severity,
} from '../domain/types.js';

const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

const sortBySeverity = (a: { severity: Severity }, b: { severity: Severity }): number =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

export interface ReportInput {
  readonly decision: GateDecision;
  readonly plan: ExecutionPlan;
  readonly results: readonly CheckResult[];
  readonly manualEvidence: readonly ManualEvidence[];
  readonly exceptions: readonly ExceptionRecord[];
  readonly appId: string;
  readonly appName?: string;
  readonly sourceCommit: string;
  readonly sourceClean: boolean;
  readonly policyRepository: string;
  readonly policyCommit: string;
  readonly controlCatalogueDigest: string;
  readonly gatePolicyDigest: string;
  readonly generatedAt: Date;
  readonly runId: string;
}

export interface OutstandingItem {
  readonly id: string;
  readonly severity: Severity;
  readonly summary: string;
  readonly control_ids: readonly string[];
  readonly exception_ref?: string;
}

export interface BuiltReport {
  readonly evidence: ReleaseEvidence;
  readonly outstanding: readonly OutstandingItem[];
}

/**
 * Assembles release evidence from the evaluation.
 *
 * Kit readiness and application production readiness are reported separately and are never inferred
 * from each other. A local example passing the kit's own tests is not an application release
 * approval, and this function cannot produce one from a kit result.
 */
export function buildReport(input: ReportInput): BuiltReport {
  const outstanding: OutstandingItem[] = input.results.flatMap((result) =>
    (result.findings ?? []).map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      summary: finding.title ?? `${finding.rule_id} reported by ${finding.tool}`,
      control_ids: finding.control_ids ?? result.control_ids,
      ...(finding.exception_ref === undefined ? {} : { exception_ref: finding.exception_ref }),
    })),
  );

  const evidence: ReleaseEvidence = {
    schema_version: 'release-evidence/v1',
    application: {
      id: input.appId,
      ...(input.appName === undefined ? {} : { name: input.appName }),
      profiles: input.plan.inputs.profiles,
    },
    stage: input.plan.stage,
    environment: input.plan.environment,
    generated_at: input.generatedAt.toISOString(),
    source: {
      commit: input.sourceCommit,
      clean: input.sourceClean,
      build_identity: input.runId,
    },
    policy: {
      repository: input.policyRepository,
      commit: input.policyCommit,
      control_catalogue_digest: input.controlCatalogueDigest,
      gate_policy_digest: input.gatePolicyDigest,
    },
    expected_checks: input.plan.expected_checks.map((check) => ({
      check_id: check.check_id,
      control_ids: check.control_ids,
      required: check.required,
      method: check.method,
      recipe: check.recipe,
    })),
    results: input.results.map((result) => ({
      check_id: result.check_id,
      outcome: result.outcome,
      coverage: result.coverage,
      evidence_origin: result.evidence_origin,
      ...(result.tool?.observed_version === undefined ? {} : { tool_version: result.tool.observed_version }),
      scope_observed: result.scope?.observed ?? 0,
      scope_expected: result.scope?.expected ?? 0,
      ...(result.report?.raw_digest === undefined ? {} : { report_digest: result.report.raw_digest }),
      finished_at: result.finished_at,
      reasons: [],
    })),
    control_outcomes: input.decision.control_outcomes.map((outcome) => ({
      control: outcome.control,
      definition_version: outcome.definition_version,
      applicability: outcome.applicability,
      outcome: outcome.outcome,
      coverage: outcome.coverage,
      required_checks: outcome.required_checks,
      satisfied_checks: outcome.satisfied_checks,
      reasons: outcome.reasons.map((item) => `${item.code}: ${item.message}`),
      waiver_refs: outcome.waiver_refs,
    })),
    manual_verification: input.manualEvidence.map((record) => ({
      id: record.id,
      control: record.control,
      operator: record.operator.identity,
      observed_at: record.observed_at,
      expires_at: record.expires_at,
      outcome: record.outcome,
      scope_fingerprint: record.scope_fingerprint,
      fresh: Date.parse(record.expires_at) > input.generatedAt.getTime(),
    })),
    exceptions: input.exceptions.map((exception) => ({
      id: exception.id,
      control: exception.scope.control ?? exception.id,
      scope: JSON.stringify(exception.scope),
      status: exception.status,
      approver: exception.approver,
      self_review: exception.self_review ?? false,
      expires_at: exception.expires_at,
    })),
    outstanding: outstanding
      .slice()
      .sort(sortBySeverity)
      .map((item) => ({
        id: item.id,
        severity: item.severity,
        summary: item.summary,
        control_ids: item.control_ids,
        ...(item.exception_ref === undefined ? {} : { exception_ref: item.exception_ref }),
        first_seen: input.generatedAt.toISOString(),
      })),
    unsupported_scope: input.decision.unsupported_scope.map((area) => ({ area, reason: area })),
    decision: {
      outcome: input.decision.satisfied ? 'satisfied' : 'blocked',
      reasons: input.decision.reasons.map((item) => `${item.code}: ${item.message}`),
      blocking_reason_codes: [...new Set(input.decision.reasons.map((item) => item.code))],
      // A kit result says nothing about whether a deployed application met its release requirements.
      kit_readiness: input.decision.satisfied ? 'verified' : 'pending',
      application_production_readiness:
        input.decision.satisfied && input.sourceClean && input.plan.stage === 'release' ? 'verified' : 'pending',
    },
  };

  return { evidence, outstanding };
}
