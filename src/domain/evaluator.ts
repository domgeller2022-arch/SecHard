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
    /** Per-control manual-evidence interval, from the control's own evidence requirements. */
    readonly manual_max_age_days?: number;
  }[];
  /**
   * What the selected profiles permit. An exception for a control a profile marks `never` does not
   * apply, however well formed the record is: the profile is the authority on what may be excepted.
   */
  readonly exceptionPolicy?: Readonly<Record<string, 'permitted' | 'never'>>;
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
  const controlVersions: Record<string, number> = {};
  for (const control of input.controls) controlVersions[control.id] = control.definition_version;

  // A control is never waivable when either its profile or the gate policy says so. Both sources are
  // enforced: the profile is per-selection policy, and the gate-policy list is a global floor that a
  // profile edit cannot remove.
  const neverControls = resolveNeverControls(input);
  const usableExceptions = resolveExceptions(input.exceptions, input.now, {
    ...(input.exceptionPolicy === undefined ? {} : { exceptionPolicy: input.exceptionPolicy }),
    neverControls,
    controlVersions,
  });
  const manualByControl = groupBy(input.manualEvidence, (record) => record.control);
  const controlsById = new Map(input.controls.map((control) => [control.id, control]));

  const waiverContext: WaiverContext = {
    neverControls,
    controlVersions,
    stage: input.stage,
    blockingSeverities: resolveBlockingSeverities(input.policy),
    criticalNeverWaivable: input.policy.exceptions?.critical_findings_never_waivable !== false,
    highRequiresNonSelfAtRelease: input.policy.exceptions?.high_findings_require_non_self_approver_at_release !== false,
  };

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
      waiver: waiverContext,
    });

    controlOutcomes.push(outcome);
    reasons.push(...outcome.reasons);
    if (outcome.outcome === 'unsupported') {
      unsupportedScope.push(`${controlId}: ${outcome.reasons.map((item) => item.message).join('; ')}`);
    }
  }

  reasons.push(
    ...rejectUnusableExceptions(input.exceptions, input.now, usableExceptions, {
      ...(input.exceptionPolicy === undefined ? {} : { exceptionPolicy: input.exceptionPolicy }),
      neverControls,
      controlVersions,
    }),
  );
  reasons.push(...assessmentContradictions(input));
  const gaps = featureGaps(input);
  for (const gap of gaps) {
    reasons.push(reason('coverage.feature_gap', gap));
  }

  // Approval is a release obligation, not a development one. Draft policy may be exercised locally
  // and in a pull request; it cannot carry a release.
  const approvalReasons = evaluateApprovals(input);
  reasons.push(...approvalReasons.reasons);

  // One outcome per control, not one per check. A control with two checks (SEC-01 scans repository
  // and history separately) previously produced two rows and its summary count was really a check
  // count. The worst check outcome governs; a waiver is acceptable only when no check is unmet.
  const aggregated = aggregateControlOutcomes(controlOutcomes);

  return {
    // A decision can be satisfied with waivers, but only waivers: every other reason blocks, and a
    // waived control is never reported as a pass.
    satisfied: reasons.every((item) => item.code === 'waiver.applied') && aggregated.every(isAcceptable),
    stage: input.stage,
    environment: input.environment,
    reasons,
    control_outcomes: aggregated,
    coverage_gaps: gaps,
    unsupported_scope: unsupportedScope,
    ...(approvalReasons.states === undefined ? {} : { approval_states: approvalReasons.states }),
  };
}

/** The global floor from `risk.blocking_severities`, falling back to the restrictive default. */
function resolveBlockingSeverities(policy: GatePolicy): ReadonlySet<Severity> {
  const configured = policy.risk.blocking_severities.filter((severity) => severity === 'critical' || severity === 'high');
  return new Set(configured.length > 0 ? configured : ['critical', 'high']);
}

/** Every control that can never be excepted: the profile's `never` entries plus the policy floor. */
function resolveNeverControls(input: EvaluationInput): ReadonlySet<string> {
  const never = new Set<string>(input.policy.control_categories.never_exceptable);
  if (input.exceptionPolicy !== undefined) {
    for (const [control, policy] of Object.entries(input.exceptionPolicy)) {
      if (policy === 'never') never.add(control);
    }
  }
  return never;
}

const OUTCOME_RANK: Readonly<Record<ControlOutcome, number>> = {
  unmet: 0,
  unsupported: 1,
  unknown: 2,
  waived: 3,
  satisfied: 4,
  not_applicable: 5,
};

/**
 * Collapses per-check outcomes into per-control outcomes. The control's outcome is the worst of its
 * checks, its coverage the worst coverage, and its reasons the union. Required and satisfied checks
 * list every check that contributed, so a report can show what a control actually depended on.
 */
function aggregateControlOutcomes(evaluations: readonly ControlEvaluation[]): ControlEvaluation[] {
  const order: string[] = [];
  const groups = new Map<string, ControlEvaluation[]>();
  for (const evaluation of evaluations) {
    const existing = groups.get(evaluation.control);
    if (existing === undefined) {
      groups.set(evaluation.control, [evaluation]);
      order.push(evaluation.control);
    } else {
      existing.push(evaluation);
    }
  }

  return order.map((control) => {
    const group = groups.get(control) as ControlEvaluation[];
    const first = group[0] as ControlEvaluation;
    const outcome = group.reduce<ControlOutcome>(
      (worst, item) => (OUTCOME_RANK[item.outcome] < OUTCOME_RANK[worst] ? item.outcome : worst),
      'not_applicable',
    );
    const applicability = group.every((item) => item.applicability === 'not_applicable')
      ? 'not_applicable'
      : group.some((item) => item.applicability === 'unknown')
        ? 'unknown'
        : 'applicable';
    const coverage = group.reduce<Coverage>((worst, item) => worse(worst, item.coverage), 'complete');

    return {
      control,
      definition_version: first.definition_version,
      applicability,
      outcome,
      coverage,
      required_checks: [...new Set(group.flatMap((item) => [...item.required_checks]))].sort(),
      satisfied_checks: [...new Set(group.flatMap((item) => [...item.satisfied_checks]))].sort(),
      reasons: group.flatMap((item) => [...item.reasons]),
      waiver_refs: [...new Set(group.flatMap((item) => [...item.waiver_refs]))],
    };
  });
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
  outcome.outcome === 'satisfied' || outcome.outcome === 'not_applicable' || outcome.outcome === 'waived';

interface WaiverContext {
  /** Controls that can never be waived, from the profiles and the gate policy together. */
  readonly neverControls: ReadonlySet<string>;
  readonly controlVersions: Readonly<Record<string, number>>;
  readonly stage: Stage;
  readonly blockingSeverities: ReadonlySet<Severity>;
  readonly criticalNeverWaivable: boolean;
  readonly highRequiresNonSelfAtRelease: boolean;
}

interface CheckContext {
  readonly results: readonly CheckResult[];
  readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
  readonly manual: readonly ManualEvidence[];
  readonly exceptions: ReadonlyMap<string, ExceptionRecord>;
  readonly stagePolicy: StagePolicy;
  readonly policy: GatePolicy;
  readonly now: Date;
  readonly sourceDirty: boolean;
  readonly waiver: WaiverContext;
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

  // A manual requirement is satisfied by a current operator attestation, never by a tool result and
  // never by its absence.
  if (check.execution?.mode === 'manual') {
    return evaluateManualCheck(check, definition, controlId, reasons, context);
  }

  if (context.results.length === 0) {
    reasons.push(
      reason('check.missing', `no result was produced for required check ${check.check_id}`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
    return build(controlId, check.check_id, definition, 'unmet', 'unknown', satisfiedChecks, reasons, waiverRefs);
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

  // A waiver may only be applied to a result that produced an answer. An error, unsupported,
  // skipped, pending, or stale result has no finding to accept; converting one into a waiver would
  // turn "we could not tell" into "we accepted the risk".
  const waivable = result.outcome === 'pass' || result.outcome === 'fail';

  for (const finding of result.findings ?? []) {
    const evaluated = evaluateFinding(finding, check, waivable ? context.exceptions : NO_EXCEPTIONS, context.waiver);
    reasons.push(...evaluated.reasons);
    waiverRefs.push(...evaluated.waiver_refs);
  }

  if (waiverRefs.length > 0 && reasons.every((item) => item.code === 'waiver.applied')) {
    return build(controlId, check.check_id, definition, 'waived', result.coverage, satisfiedChecks, reasons, waiverRefs);
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
    return build(controlId, check.check_id, definition, outcomeFor(result.outcome), result.coverage, satisfiedChecks, reasons, waiverRefs);
  }

  satisfiedChecks.push(check.check_id);
  return build(controlId, check.check_id, definition, 'satisfied', result.coverage, satisfiedChecks, reasons, waiverRefs);
}

/**
 * Evaluates a manual requirement against operator attestations.
 *
 * A record satisfies it only when it names the same recipe, records a `pass`, and is current: its
 * own expiry has not passed and its observation is not older than the policy interval. A missing,
 * expired, pending, or negative record leaves the requirement unmet, and the record is never
 * converted into a tool result.
 */
function evaluateManualCheck(
  check: ExpectedCheck,
  definition: { readonly definition_version: number; readonly manual_max_age_days?: number },
  controlId: string,
  existingReasons: readonly Reason[],
  context: CheckContext,
): ControlEvaluation {
  const reasons: Reason[] = [...existingReasons];
  const forRecipe = context.manual.filter((record) => record.recipe === check.recipe);

  // The interval is the control's own when it declares one; otherwise the policy default, with the
  // longer exercise interval for restore and response drills. Per-control intervals are the point:
  // a credential inventory ages differently from a restore drill.
  const isExercise = /exercise|restore|rollback/i.test(check.recipe);
  const maxAgeDays =
    definition.manual_max_age_days ??
    (isExercise
      ? context.policy.freshness.manual_evidence_exercise_max_age_days
      : context.policy.freshness.manual_evidence_default_max_age_days);

  const staleReasons: Reason[] = [];
  const current = forRecipe.filter((record) => {
    const expires = Date.parse(record.expires_at);
    const observed = Date.parse(record.observed_at);
    if (Number.isNaN(expires) || Number.isNaN(observed)) return false;
    if (expires <= context.now.getTime()) return false;
    const ageDays = (context.now.getTime() - observed) / 86_400_000;
    if (ageDays > maxAgeDays) return false;
    if (observed > context.now.getTime() + (context.policy.freshness.max_clock_skew_minutes ?? 0) * 60_000) return false;

    // Reuse across a source change is allowed only when the record also pins the external
    // configuration it was observed against. An operational fact stays true across unrelated code
    // changes; it does not stay true across a storage migration, and the fingerprint is how that is
    // distinguished without demanding a fresh drill for every commit.
    if (record.source_commit !== undefined && record.source_commit !== check.identity.source_commit) {
      if (record.target.configuration_fingerprint === undefined) {
        staleReasons.push(
          reason(
            'manual.reuse_without_scope',
            `manual evidence ${record.id} was observed at a different source and records no configuration fingerprint, so its continuing validity cannot be shown`,
            { control_ids: [controlId], check_id: check.check_id },
          ),
        );
        return false;
      }
    }
    return true;
  });

  if (current.length === 0 && staleReasons.length > 0) {
    return build(controlId, check.check_id, definition, 'unmet', 'unknown', [], [...reasons, ...staleReasons], []);
  }

  const passing = current.filter((record) => record.outcome === 'pass');
  if (passing.length > 0) {
    return build(controlId, check.check_id, definition, 'satisfied', 'complete', passing.map((record) => record.id), reasons, []);
  }

  if (forRecipe.length === 0) {
    reasons.push(
      reason('manual.missing', `no manual evidence exists for ${controlId} recipe '${check.recipe}'`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
  } else if (current.length === 0) {
    reasons.push(
      reason('manual.stale', `manual evidence for ${controlId} recipe '${check.recipe}' is expired or older than ${maxAgeDays} days`, {
        control_ids: [controlId],
        check_id: check.check_id,
      }),
    );
  } else {
    for (const record of current) {
      if (record.outcome === 'pass') continue;
      reasons.push(
        reason(`manual.${record.outcome}`, `manual evidence ${record.id} for ${controlId} recorded outcome '${record.outcome}'`, {
          control_ids: [controlId],
          check_id: check.check_id,
        }),
      );
    }
  }

  return build(controlId, check.check_id, definition, 'unmet', 'unknown', [], reasons, []);
}

function build(
  control: string,
  checkId: string,
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
    required_checks: [checkId],
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

const NO_EXCEPTIONS: ReadonlyMap<string, ExceptionRecord> = new Map();

interface FindingWaiver {
  readonly exception?: ExceptionRecord;
  /** Why a matching exception may not be applied; the finding then stays blocking. */
  readonly forbidden?: string;
}

function evaluateFinding(
  finding: Finding,
  check: ExpectedCheck,
  exceptions: ReadonlyMap<string, ExceptionRecord>,
  waiver: WaiverContext,
): { reasons: Reason[]; waiver_refs: string[] } {
  const controlIds = finding.control_ids ?? check.control_ids;
  const found = findException(finding, check, controlIds, exceptions, waiver);

  if (found.exception !== undefined) {
    const exception = found.exception;
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

  // A matching exception that policy refuses to apply is reported, not silently ignored: the owner
  // should see that a waiver was attempted and why it does not hold.
  const forbidden: Reason[] =
    found.forbidden === undefined
      ? []
      : [
          reason('waiver.forbidden', `${finding.id} cannot be waived: ${found.forbidden}; the finding stays blocking`, {
            control_ids: controlIds,
            check_id: check.check_id,
            finding_id: finding.id,
            severity: finding.severity,
          }),
        ];

  // A triage label with no stated reason is not triage. This applies whatever the severity is.
  if (finding.triage === 'false_positive' && (finding.triage_reason ?? '').length < 10) {
    return {
      reasons: [
        ...forbidden,
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
        ...forbidden,
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

  if (waiver.blockingSeverities.has(finding.severity) && finding.triage !== 'fixed') {
    return {
      reasons: [
        ...forbidden,
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

/**
 * Finds the exception that applies to this finding, if any, and decides whether policy permits it.
 *
 * The policy checks are all resolved from the *finding's* control, never from the exception's own
 * scope: otherwise naming an exceptable control in the scope would launder a finding on a
 * never-exceptable one. A scope that names another check does not match at all.
 */
function findException(
  finding: Finding,
  check: ExpectedCheck,
  controlIds: readonly string[],
  exceptions: ReadonlyMap<string, ExceptionRecord>,
  waiver: WaiverContext,
): FindingWaiver {
  const matched: ExceptionRecord[] = [];
  if (finding.exception_ref !== undefined) {
    const explicit = exceptions.get(finding.exception_ref);
    if (explicit !== undefined) matched.push(explicit);
  }
  for (const exception of exceptions.values()) {
    if (exception.scope.finding_id !== undefined && exception.scope.finding_id === finding.id) matched.push(exception);
    if (exception.scope.rule_id !== undefined && exception.scope.rule_id === finding.rule_id) matched.push(exception);
  }

  let forbidden: string | undefined;
  for (const exception of matched) {
    const scope = exception.scope;

    // The record must actually be about this item. A check-scoped exception for another check, or a
    // control-scoped exception naming a control this finding does not belong to, does not apply.
    if (scope.check_id !== undefined && scope.check_id !== check.check_id) continue;
    if (scope.control !== undefined && !controlIds.includes(scope.control)) continue;

    const never = controlIds.find((id) => waiver.neverControls.has(id));
    if (never !== undefined) {
      forbidden = `the control ${never} is never exceptable, whatever scope the exception uses`;
      continue;
    }

    // Definition-version invalidation applies to the control the exception is about: the scope's own
    // control when it names one, otherwise the finding's controls.
    const grantedAgainst = scope.control_definition_version;
    if (grantedAgainst !== undefined) {
      const ids = scope.control !== undefined ? [scope.control] : controlIds;
      const changed = ids.find((id) => waiver.controlVersions[id] !== undefined && waiver.controlVersions[id] !== grantedAgainst);
      if (changed !== undefined) {
        forbidden = `it was granted against definition version ${grantedAgainst}, but ${changed} is now version ${waiver.controlVersions[changed]}`;
        continue;
      }
    }

    if (waiver.criticalNeverWaivable && finding.severity === 'critical') {
      forbidden = 'a critical finding can never be waived; it needs containment and remediation';
      continue;
    }
    if (
      waiver.highRequiresNonSelfAtRelease &&
      finding.severity === 'high' &&
      waiver.stage === 'release' &&
      exception.self_review !== false
    ) {
      forbidden = `a high finding at release requires a non-self approver, and ${exception.id} is not independently approved`;
      continue;
    }

    return { exception };
  }

  return forbidden === undefined ? {} : { forbidden };
}

/**
 * Only permitted, current, precisely scoped exceptions resolve. A blanket scope is rejected, as is
 * an exception over an execution error: an error means no answer was produced, which is different
 * from an accepted risk.
 */
interface ExceptionContext {
  readonly exceptionPolicy?: Readonly<Record<string, 'permitted' | 'never'>>;
  /** The gate-policy floor, unioned with every profile's `never` list. */
  readonly neverControls: ReadonlySet<string>;
  readonly controlVersions: Readonly<Record<string, number>>;
}

function resolveExceptions(
  exceptions: readonly ExceptionRecord[],
  now: Date,
  context: ExceptionContext,
): Map<string, ExceptionRecord> {
  const usable = new Map<string, ExceptionRecord>();
  for (const exception of exceptions) {
    if (exception.status !== 'active') continue;

    const expires = Date.parse(exception.expires_at);
    if (Number.isNaN(expires) || expires <= now.getTime()) continue;
    if (!isPreciselyScoped(exception)) continue;
    if (exceptionBlockedBy(context, exception) !== undefined) continue;

    usable.set(exception.id, exception);
  }
  return usable;
}

/**
 * Returns why an exception may not be applied at all, ignoring its own contents.
 *
 * Two cases: a control the profiles or the gate policy mark `never` exceptable has already decided,
 * and an exception granted against an older definition version does not survive the definition
 * changing — the acceptance criteria it accepted are not the ones now in force. When the scope does
 * not name a control, the apply-time check resolves the target control from the finding itself.
 */
function exceptionBlockedBy(context: ExceptionContext, exception: ExceptionRecord): string | undefined {
  const control = exception.scope.control;
  if (control === undefined) return undefined;

  if (context.neverControls.has(control) || context.exceptionPolicy?.[control] === 'never') {
    return `profile or gate policy marks ${control} as not exceptable`;
  }

  const grantedAgainst = exception.scope.control_definition_version;
  const current = context.controlVersions[control];
  if (grantedAgainst !== undefined && current !== undefined && grantedAgainst !== current) {
    return `granted against definition version ${grantedAgainst}, but the catalogue defines version ${current}`;
  }

  return undefined;
}

function isPreciselyScoped(exception: ExceptionRecord): boolean {
  const scope = exception.scope;
  if (Object.keys(scope).length === 0) return false;
  // A rule_id on its own is not precise: it would waive that rule across every check. It must be
  // anchored to the control or the check it is about.
  if (scope.rule_id !== undefined && scope.control === undefined && scope.check_id === undefined) return false;
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
  context: ExceptionContext,
): Reason[] {
  return exceptions
    .filter((exception) => !usable.has(exception.id))
    .map((exception) => {
      let why: string;
      const blocked = exceptionBlockedBy(context, exception);
      if (exception.status !== 'active') {
        why = `status is '${exception.status}'`;
      } else if (blocked !== undefined) {
        why = blocked;
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
