import { evaluateApplicability, type ApplicabilityRule, type ManifestLike } from './applicability.js';
import { approvalsRequiredForRelease, resolveApprovals, type ApprovalRecord, type ApprovalState, type DefinitionLike } from './approval.js';
import type {
  CheckResult,
  ControlEvaluation,
  ControlOutcome,
  Coverage,
  ExceptionRecord,
  ExpectedCheck,
  Finding,
  GateDecision,
  Environment,
  GatePolicy,
  ManualEvidence,
  Reason,
  Severity,
  Stage,
  ExecutionPlan,
} from './types.js';

export interface EvaluationInput {
  readonly stage: Stage;
  readonly environment: Environment;
  readonly manifest: {
    readonly features: Readonly<Record<string, { readonly state: 'enabled' | 'disabled' | 'unknown' } | undefined>>;
  };
  readonly controls: readonly {
    readonly id: string;
    readonly definition_version: number;
    readonly applicability: ApplicabilityRule;
  }[];
  readonly plan: ExecutionPlan;
  readonly results: readonly CheckResult[];
  readonly manualEvidence: readonly ManualEvidence[];
  readonly exceptions: readonly ExceptionRecord[];
  /**
   * Owner approvals for the control definitions in use. Only release evaluation requires them.
   * Approval metadata is not present in reports written during development.
   */
  readonly approvals?: readonly ApprovalRecord[];
  /**
   * The application's own assessment records. Read for justification and to surface contradictions,
   * never as proof: a recorded `pass` has no effect on a derived outcome, and a recorded
   * `not_applicable` cannot override applicability computed from the manifest.
   */
  readonly assessments?: readonly {
    readonly control: string;
    readonly definition_version: number;
    readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
    readonly applicability_reason?: string;
    readonly status: CheckResult['outcome'];
    readonly owner: string;
    readonly assessed_at: string;
  }[];
  readonly policy: GatePolicy;
  readonly now: Date;
  readonly planIdentity: string;
  /** Control definitions, needed to compute their reviewed-content digest. */
  readonly controlDefinitions?: readonly DefinitionLike[];
  /** Identity of the plan recomputed from validated policy plus the manifest. */
  readonly expectedPlanIdentity?: string;
  /** Features the selected profiles exclude, used to surface coverage gaps. */
  readonly excludedFeatures?: readonly string[];
}

type StagePolicy = {
  readonly require_clean_source?: boolean;
  readonly require_actual_tool_origin?: boolean;
  readonly advisory_snapshot_max_age_hours?: number;
};

const BLOCKING_SEVERITIES: ReadonlySet<Severity> = new Set<Severity>(['critical', 'high']);

const COVERAGE_ORDER: Record<Coverage, number> = { complete: 0, partial: 1, unknown: 2 };

const worse = (a: Coverage, b: Coverage): Coverage =>
  COVERAGE_ORDER[a] <= COVERAGE_ORDER[b] ? a : b;

const reason = (code: string, message: string, extra: Partial<Reason> = {}): Reason => ({
  code,
  message,
  ...extra,
});

/**
 * Derives the current decision from validated inputs.
 *
 * A pure function. It reads records and returns reasons; it never runs a tool, reads an environment
 * variable, or consults a stored `status`. An application's recorded `status: pass` is a claim and
 * has no effect on the outcome.
 */
export function evaluate(input: EvaluationInput): GateDecision {
  const stagePolicy = input.policy.stages[input.stage];
  if (stagePolicy === undefined) {
    return {
      satisfied: false,
      stage: input.stage,
      environment: input.environment,
      reasons: [reason('gate.unknown_stage', `no requirements are defined for stage '${input.stage}'`)],
      control_outcomes: [],
      coverage_gaps: [],
      unsupported_scope: [],
    };
  }

  const reasons: Reason[] = [
    ...validatePlan(input),
    ...validateResultSet(input),
  ];

  const resultsByCheck = groupBy(input.results, (result) => result.check_id);
  const usableExceptions = resolveExceptions(input.exceptions, input.now);
  const manualByControl = groupBy(input.manualEvidence, (record) => record.control);
  const controlsById = new Map(input.controls.map((control) => [control.id, control]));

  const controlOutcomes: ControlEvaluation[] = [];
  const unsupportedScope: string[] = [];

  for (const check of input.plan.expected_checks) {
    const controlId = check.control_ids[0];
    if (controlId === undefined) continue;

    const definition = controlsById.get(controlId);
    if (definition === undefined) {
      reasons.push(
        reason('gate.forged_control', `plan references unknown control '${controlId}'`, {
          control_ids: [controlId],
          check_id: check.check_id,
        }),
      );
      continue;
    }

    const outcome = evaluateCheck(check, definition, {
      results: resultsByCheck.get(check.check_id) ?? [],
      applicability: evaluateApplicability(definition.applicability, input.manifest as ManifestLike, input.environment),
      manual: manualByControl.get(controlId) ?? [],
      exceptions: usableExceptions,
      stagePolicy,
      policy: input.policy,
      now: input.now,
      sourceDirty: input.plan.inputs.source_dirty === true,
    });

    controlOutcomes.push(outcome);
    reasons.push(...outcome.reasons);
    if (outcome.outcome === 'unsupported') {
      unsupportedScope.push(`${controlId}: ${outcome.reasons.map((item) => item.message).join('; ')}`);
    }
  }

  reasons.push(...rejectUnusableExceptions(input.exceptions, input.now, usableExceptions));
  reasons.push(...assessmentContradictions(input));
  const gaps = featureGaps(input);
  for (const gap of gaps) {
    reasons.push(reason('coverage.feature_gap', gap));
  }

  // Approval is a release obligation, not a development one. Draft policy may be exercised locally
  // and in a pull request; it cannot carry a release.
  const approvalReasons = evaluateApprovals(input);
  reasons.push(...approvalReasons.reasons);

  return {
    satisfied: reasons.length === 0 && controlOutcomes.every(isAcceptable),
    stage: input.stage,
    environment: input.environment,
    reasons,
    control_outcomes: controlOutcomes,
    coverage_gaps: gaps,
    unsupported_scope: unsupportedScope,
    ...(approvalReasons.states === undefined ? {} : { approval_states: approvalReasons.states }),
  };
}

/**
 * Release evaluation requires a valid owner approval for every applicable control definition.
 *
 * An approval that names a different content digest, a different version, or no reviewer is invalid
 * rather than absent: it must surface as a problem to fix, not as "reviewed".
 */
function evaluateApprovals(input: EvaluationInput): { reasons: Reason[]; states?: readonly ApprovalState[] } {
  if (input.stage !== 'release') return { reasons: [] };
  if (input.controlDefinitions === undefined) {
    return {
      reasons: [
        reason('policy.approval_unverifiable', 'release evaluation requires control definitions so their reviewed content can be digested; none were supplied'),
      ],
    };
  }

  const states = resolveApprovals(input.controlDefinitions, input.approvals ?? [], input.now);
  const applicable = new Set(
    input.plan.expected_checks.flatMap((check) => [...check.control_ids]),
  );
  const missing = approvalsRequiredForRelease(states, applicable);

  return {
    states,
    reasons: missing.map((state) =>
      reason(
        state.problem === 'not_approved' ? 'policy.control_not_approved' : 'policy.approval_invalid',
        `${state.control} is ${describeApprovalProblem(state)}`,
        { control_ids: [state.control] },
      ),
    ),
  };
}

function describeApprovalProblem(state: ApprovalState): string {
  switch (state.problem) {
    case 'content_changed':
      return 'owner_reviewed but the reviewed content digest changed since approval, so the approval no longer applies';
    case 'version_changed':
      return 'owner_reviewed but its definition version differs from the approval';
    case 'different_control':
      return 'approved under a different control id';
    case 'missing_reviewer':
      return 'recorded an approval with no reviewer';
    default:
      return 'still draft; only the owner may mark a definition owner_reviewed';
  }
}

const isAcceptable = (outcome: ControlEvaluation): boolean =>
  outcome.outcome === 'satisfied' || outcome.outcome === 'not_applicable';

interface CheckContext {
  readonly results: readonly CheckResult[];
  readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
  readonly manual: readonly ManualEvidence[];
  readonly exceptions: ReadonlyMap<string, ExceptionRecord>;
  readonly stagePolicy: StagePolicy;
  readonly policy: GatePolicy;
  readonly now: Date;
  readonly sourceDirty: boolean;
}

function evaluateCheck(
  check: ExpectedCheck,
  definition: { readonly id: string; readonly definition_version: number },
  context: CheckContext,
): ControlEvaluation {
  const controlId = definition.id;

  if (context.applicability === 'not_applicable') {
    return {
      control: controlId,
      definition_version: definition.definition_version,
      applicability: 'not_applicable',
      outcome: 'not_applicable',
      coverage: 'unknown',
      required_checks: [check.check_id],
      satisfied_checks: [],
      reasons: [],
      waiver_refs: [],
    };
  }

  const reasons: Reason[] = [];
  const waiverRefs: string[] = [];
  const satisfiedChecks: string[] = [];

  if (context.applicability === 'unknown') {
    reasons.push(
      reason('control.applicability_unknown', `applicability of ${controlId} cannot be determined from the manifest, so it cannot be treated as absent`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
  }

  if (context.results.length === 0) {
    reasons.push(
      reason('check.missing', `no result was produced for required check ${check.check_id}`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
    return build(controlId, definition, 'unmet', 'unknown', satisfiedChecks, reasons, waiverRefs);
  }

  if (context.results.length > 1) {
    reasons.push(
      reason('check.duplicate_result', `${context.results.length} results exist for ${check.check_id}; a required check must have exactly one`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
  }

  const result = context.results[0] as CheckResult;

  reasons.push(...identityReasons(check, result));
  reasons.push(...freshnessReasons(check, result, context));

  if (context.stagePolicy.require_clean_source === true && context.sourceDirty) {
    reasons.push(
      reason('source.dirty', `${check.check_id} cannot support a release decision from a dirty working tree`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
  }

  if (result.outcome === 'pass') {
    if (result.coverage !== 'complete') {
      reasons.push(
        reason('coverage.incomplete_pass', `${check.check_id} claims pass with ${result.coverage} coverage`, {
          control_ids: [controlId],
          check_id: check.check_id,
        }),
      );
    }
    reasons.push(...scopeReasons(check, result));

    const requireActual = context.stagePolicy.require_actual_tool_origin === true;
    if (result.evidence_origin === 'fixture') {
      reasons.push(
        reason(
          requireActual ? 'evidence.fixture_origin' : 'evidence.fixture_origin_noted',
          requireActual
            ? `${check.check_id} claims pass from fixture data, which cannot satisfy this stage`
            : `${check.check_id} used fixture evidence; it does not count as real evidence`,
          { control_ids: [controlId], check_id: check.check_id },
        ),
      );
    }
  }

  for (const finding of result.findings ?? []) {
    const evaluated = evaluateFinding(finding, check, context.exceptions);
    reasons.push(...evaluated.reasons);
    waiverRefs.push(...evaluated.waiver_refs);
  }

  reasons.push(...manualReasons(context, controlId));

  if (waiverRefs.length > 0 && reasons.every((item) => item.code === 'waiver.applied')) {
    return build(controlId, definition, 'waived', result.coverage, satisfiedChecks, reasons, waiverRefs);
  }

  const hasFailure = reasons.some((item) => item.code !== 'evidence.fixture_origin_noted');
  if (hasFailure || result.outcome !== 'pass') {
    if (!hasFailure) {
      reasons.push(
        reason('check.not_passed', `${check.check_id} outcome is '${result.outcome}'`, {
          control_ids: [controlId],
          check_id: check.check_id,
        }),
      );
    }
    return build(controlId, definition, outcomeFor(result.outcome), result.coverage, satisfiedChecks, reasons, waiverRefs);
  }

  satisfiedChecks.push(check.check_id);
  return build(controlId, definition, 'satisfied', result.coverage, satisfiedChecks, reasons, waiverRefs);
}

function build(
  control: string,
  definition: { readonly definition_version: number },
  outcome: ControlOutcome,
  coverage: Coverage,
  satisfiedChecks: readonly string[],
  reasons: readonly Reason[],
  waiverRefs: readonly string[],
): ControlEvaluation {
  return {
    control,
    definition_version: definition.definition_version,
    applicability: reasons.some((item) => item.code === 'control.applicability_unknown') ? 'unknown' : 'applicable',
    outcome,
    coverage: reasons.length > 0 ? worse(coverage, 'unknown') : coverage,
    required_checks: [],
    satisfied_checks: satisfiedChecks,
    reasons,
    waiver_refs: waiverRefs,
  };
}

const outcomeFor = (outcome: CheckResult['outcome']): ControlOutcome => {
  switch (outcome) {
    case 'unsupported':
      return 'unsupported';
    case 'pending':
    case 'skipped':
      return 'unknown';
    case 'not_applicable':
      return 'not_applicable';
    default:
      return 'unmet';
  }
};

function identityReasons(check: ExpectedCheck, result: CheckResult): Reason[] {
  const reasons: Reason[] = [];
  const short = (commit: string): string => commit.slice(0, 12);

  if (result.identity.source_commit !== check.identity.source_commit) {
    reasons.push(
      reason('identity.source_mismatch', `${result.check_id} was produced for source ${short(result.identity.source_commit)}, not ${short(check.identity.source_commit)}`, {
        control_ids: check.control_ids,
        check_id: check.check_id,
      }),
    );
  }
  if (result.identity.policy_commit !== check.identity.policy_commit) {
    reasons.push(
      reason('identity.policy_mismatch', `${result.check_id} was produced under policy ${short(result.identity.policy_commit)}, not ${short(check.identity.policy_commit)}`, {
        control_ids: check.control_ids,
        check_id: check.check_id,
      }),
    );
  }
  if (check.identity.target !== undefined && result.identity.target !== check.identity.target) {
    reasons.push(reason('identity.target_mismatch', `${result.check_id} targeted a different target`, { control_ids: check.control_ids, check_id: check.check_id }));
  }
  if (check.identity.configuration_digest !== undefined && result.identity.configuration_digest !== check.identity.configuration_digest) {
    reasons.push(reason('identity.configuration_mismatch', `${result.check_id} used a different configuration`, { control_ids: check.control_ids, check_id: check.check_id }));
  }

  // Matching commits is not enough. The same commit can be scanned twice with different tools,
  // rules, or results, so a result is only evidence for the run and attempt it belongs to unless
  // reviewed policy explicitly permits reuse.
  if (result.identity.run_id !== check.identity.run_id) {
    reasons.push(
      reason('identity.run_mismatch', `${result.check_id} belongs to run ${result.identity.run_id}, not ${check.identity.run_id}`, {
        control_ids: check.control_ids,
        check_id: check.check_id,
      }),
    );
  } else if (result.identity.attempt !== check.identity.attempt) {
    reasons.push(
      reason('identity.attempt_mismatch', `${result.check_id} belongs to attempt ${result.identity.attempt}, not ${check.identity.attempt}`, {
        control_ids: check.control_ids,
        check_id: check.check_id,
      }),
    );
  }

  return reasons;
}

function freshnessReasons(check: ExpectedCheck, result: CheckResult, context: CheckContext): Reason[] {
  const reasons: Reason[] = [];
  const limitHours = check.evidence_freshness?.advisory_max_age_hours ?? context.stagePolicy.advisory_snapshot_max_age_hours;

  /**
   * An online advisory query and an offline database scan are different evidence, so their age is
   * measured differently.
   *
   * For an offline scan the thing that ages is the *database*, not the scan. Re-running the scanner
   * today over a database fetched last month produces a fresh-looking scan of stale data. The
   * upstream database timestamp is used when the interface supplies one; when it does not, the
   * retrieval time is used and the absence of upstream metadata is recorded rather than invented.
   */
  const mode = result.tool?.advisory_mode;
  const provenance = result.tool?.advisory_provenance;
  const onlineAt = provenance?.queried_at ?? (mode === undefined ? result.tool?.advisory_snapshot_at : undefined);
  const offlineAt = provenance?.upstream_updated_at ?? provenance?.database_retrieved_at ?? result.tool?.advisory_snapshot_at;

  const advice = mode === 'offline_database' ? offlineAt : onlineAt;
  const label = mode === 'offline_database' ? 'advisory database' : 'advisory data';

  if (advice !== undefined && limitHours !== undefined) {
    const at = Date.parse(advice);
    if (Number.isNaN(at)) {
      reasons.push(reason('freshness.unparsable', `${result.check_id} has an unparsable ${label} time`, { control_ids: check.control_ids, check_id: check.check_id }));
    } else {
      const ageHours = (context.now.getTime() - at) / 3_600_000;
      if (ageHours > limitHours) {
        const detail =
          mode === 'offline_database' && provenance?.database_retrieved_at !== undefined
            ? `; the scan itself ran at ${provenance.queried_at ?? result.finished_at} but the database is ${ageHours.toFixed(1)}h old`
            : '';
        reasons.push(
          reason('freshness.advisory_stale', `${label} for ${result.check_id} is ${ageHours.toFixed(1)}h old; the limit for this stage is ${limitHours}h${detail}`, {
            control_ids: check.control_ids,
            check_id: check.check_id,
          }),
        );
      }
    }
  }

  const skewMinutes = context.policy.freshness.max_clock_skew_minutes ?? 0;
  const timestamps = [
    ['started_at', result.started_at],
    ['finished_at', result.finished_at],
  ] as const;

  for (const [label, value] of timestamps) {
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) {
      reasons.push(reason('freshness.unparsable', `${result.check_id} has an unparsable ${label}`, { control_ids: check.control_ids, check_id: check.check_id }));
      continue;
    }
    const aheadMinutes = (parsed - context.now.getTime()) / 60_000;
    if (context.policy.freshness.reject_future_evidence !== false && aheadMinutes > skewMinutes) {
      reasons.push(
        reason('freshness.future_evidence', `${result.check_id} ${label} is ${aheadMinutes.toFixed(1)} minutes in the future`, {
          control_ids: check.control_ids,
          check_id: check.check_id,
        }),
      );
    }
  }

  return reasons;
}

function scopeReasons(check: ExpectedCheck, result: CheckResult): Reason[] {
  const expected = check.expected_scope;
  const observed = result.scope?.observed ?? 0;
  const reasonFor = (message: string): Reason[] => [
    reason('scope.incomplete', message, { control_ids: check.control_ids, check_id: check.check_id }),
  ];

  if (expected.min_files !== undefined && observed < expected.min_files) {
    return reasonFor(`${result.check_id} examined ${observed} items but at least ${expected.min_files} were required, so zero findings prove nothing`);
  }
  if (expected.min_routes !== undefined && (result.scope?.routes ?? []).length < expected.min_routes) {
    return reasonFor(`${result.check_id} covered ${(result.scope?.routes ?? []).length} routes, fewer than the required ${expected.min_routes}`);
  }
  if (expected.min_languages !== undefined && result.tool?.rule_pack === undefined) {
    return reasonFor(`${result.check_id} did not record which languages or rule pack it covered`);
  }
  if (expected.require_lockfile === true && (result.scope?.files ?? []).length === 0) {
    return reasonFor(`${result.check_id} did not examine a lockfile`);
  }
  return [];
}

function evaluateFinding(
  finding: Finding,
  check: ExpectedCheck,
  exceptions: ReadonlyMap<string, ExceptionRecord>,
): { reasons: Reason[]; waiver_refs: string[] } {
  const controlIds = finding.control_ids ?? check.control_ids;
  const exception = findException(finding, exceptions);

  if (exception !== undefined) {
    return {
      reasons: [
        reason('waiver.applied', `${finding.id} is waived by ${exception.id}, which expires ${exception.expires_at}; the finding remains visible`, {
          control_ids: controlIds,
          check_id: check.check_id,
          finding_id: finding.id,
          severity: finding.severity,
          waived_by: [exception.id],
        }),
      ],
      waiver_refs: [exception.id],
    };
  }

  // A triage label with no stated reason is not triage. This applies whatever the severity is.
  if (finding.triage === 'false_positive' && (finding.triage_reason ?? '').length < 10) {
    return {
      reasons: [
        reason('finding.false_positive_unsupported', `${finding.id} is marked a false positive without a stated reason`, {
          control_ids: controlIds,
          check_id: check.check_id,
          finding_id: finding.id,
          severity: finding.severity,
        }),
      ],
      waiver_refs: [],
    };
  }

  if (finding.severity === 'unknown') {
    // Unknown severity stays unknown. It becomes acceptable only when someone explicitly triaged it;
    // it is never quietly treated as low.
    if (finding.triage !== undefined && finding.triage !== 'unresolved') {
      return { reasons: [], waiver_refs: [] };
    }
    return {
      reasons: [
        reason('finding.unknown_severity_untriaged', `${finding.id} has unknown severity and has not been triaged`, {
          control_ids: controlIds,
          check_id: check.check_id,
          finding_id: finding.id,
          severity: 'unknown',
        }),
      ],
      waiver_refs: [],
    };
  }

  if (BLOCKING_SEVERITIES.has(finding.severity) && finding.triage !== 'fixed') {
    return {
      reasons: [
        reason('finding.blocking', `${finding.id} (${finding.severity}): ${finding.title ?? finding.rule_id}`, {
          control_ids: controlIds,
          check_id: check.check_id,
          finding_id: finding.id,
          severity: finding.severity,
        }),
      ],
      waiver_refs: [],
    };
  }

  return { reasons: [], waiver_refs: [] };
}

function findException(finding: Finding, exceptions: ReadonlyMap<string, ExceptionRecord>): ExceptionRecord | undefined {
  const explicit = finding.exception_ref === undefined ? undefined : exceptions.get(finding.exception_ref);
  if (explicit !== undefined) return explicit;

  for (const exception of exceptions.values()) {
    if (exception.scope.finding_id === finding.id) return exception;
    if (exception.scope.rule_id !== undefined && exception.scope.rule_id === finding.rule_id) return exception;
  }
  return undefined;
}

function manualReasons(context: CheckContext, controlId: string): Reason[] {
  const reasons: Reason[] = [];
  for (const record of context.manual) {
    if (record.outcome === 'pass') continue;
    reasons.push(
      reason('manual.negative', `manual evidence ${record.id} for ${controlId} recorded outcome '${record.outcome}'`, {
        control_ids: [controlId],
      }),
    );
  }
  return reasons;
}

/**
 * Only permitted, current, precisely scoped exceptions resolve. A blanket scope is rejected, as is
 * an exception over an execution error: an error means no answer was produced, which is different
 * from an accepted risk.
 */
function resolveExceptions(exceptions: readonly ExceptionRecord[], now: Date): Map<string, ExceptionRecord> {
  const usable = new Map<string, ExceptionRecord>();
  for (const exception of exceptions) {
    if (exception.status !== 'active') continue;

    const expires = Date.parse(exception.expires_at);
    if (Number.isNaN(expires) || expires <= now.getTime()) continue;
    if (!isPreciselyScoped(exception)) continue;

    usable.set(exception.id, exception);
  }
  return usable;
}

function isPreciselyScoped(exception: ExceptionRecord): boolean {
  const scope = exception.scope;
  if (Object.keys(scope).length === 0) return false;
  return (
    scope.check_id !== undefined ||
    scope.finding_id !== undefined ||
    scope.rule_id !== undefined ||
    (scope.control !== undefined && scope.environment !== undefined)
  );
}

function rejectUnusableExceptions(
  exceptions: readonly ExceptionRecord[],
  now: Date,
  usable: ReadonlyMap<string, ExceptionRecord>,
): Reason[] {
  return exceptions
    .filter((exception) => !usable.has(exception.id))
    .map((exception) => {
      let why: string;
      if (exception.status !== 'active') {
        why = `status is '${exception.status}'`;
      } else {
        const expires = Date.parse(exception.expires_at);
        why = Number.isNaN(expires) || expires <= now.getTime() ? 'expired' : 'scope is not precise enough to apply';
      }
      return reason('exception.invalid', `exception ${exception.id} cannot be applied: ${why}; the underlying issue stays visible`, {
        ...(exception.scope.control === undefined ? {} : { control_ids: [exception.scope.control] }),
        ...(exception.scope.check_id === undefined ? {} : { check_id: exception.scope.check_id }),
      });
    });
}

/**
 * Surfaces where a stored assessment contradicts what the manifest and results actually show. The
 * record is never allowed to change an outcome; a contradiction is reported so it gets fixed.
 */
function assessmentContradictions(input: EvaluationInput): Reason[] {
  const reasons: Reason[] = [];
  for (const assessment of input.assessments ?? []) {
    if (assessment.applicability === 'unknown') {
      reasons.push(
        reason('assessment.applicability_unknown', `${assessment.control} applicability is recorded as unknown; it must be decided against the manifest`, {
          control_ids: [assessment.control],
        }),
      );
      continue;
    }
    if (assessment.applicability === 'not_applicable' && (assessment.applicability_reason ?? '').trim().length < 10) {
      reasons.push(
        reason('assessment.not_applicable_unjustified', `${assessment.control} is recorded not applicable without a reason tied to the manifest`, {
          control_ids: [assessment.control],
        }),
      );
    }
  }
  return reasons;
}

function featureGaps(input: EvaluationInput): string[] {
  const excluded = new Set(input.excludedFeatures ?? []);
  const gaps: string[] = [];
  for (const feature of excluded) {
    if (input.manifest.features[feature]?.state === 'enabled') {
      gaps.push(
        `feature '${feature}' is enabled but is excluded by the selected profile; additional maintained verification is required and no implied pass is available`,
      );
    }
  }
  return gaps;
}

function validatePlan(input: EvaluationInput): Reason[] {
  const reasons: Reason[] = [];

  if (input.expectedPlanIdentity !== undefined && input.expectedPlanIdentity !== input.planIdentity) {
    reasons.push(
      reason('plan.identity_mismatch', 'the execution plan does not match the plan derived from the current policy and manifest; an altered plan cannot reduce required work'),
    );
  }

  const seen = new Set<string>();
  for (const check of input.plan.expected_checks) {
    if (seen.has(check.check_id)) {
      reasons.push(reason('plan.duplicate_check_id', `plan contains duplicate check id '${check.check_id}'`, { check_id: check.check_id }));
    }
    seen.add(check.check_id);
  }

  return reasons;
}

function validateResultSet(input: EvaluationInput): Reason[] {
  const planned = new Set(input.plan.expected_checks.map((check) => check.check_id));
  return input.results
    .filter((result) => !planned.has(result.check_id))
    .map((result) =>
      reason('result.unplanned', `result ${result.check_id} corresponds to no planned check and is ignored`, { check_id: result.check_id }),
    );
}

function groupBy<T, K>(items: readonly T[], key: (item: T) => K): Map<K, T[]> {
  const grouped = new Map<K, T[]>();
  for (const item of items) {
    const k = key(item);
    const existing = grouped.get(k);
    if (existing === undefined) grouped.set(k, [item]);
    else existing.push(item);
  }
  return grouped;
}
