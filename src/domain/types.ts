import type { ControlDefinition, Profile as ProfileDefinition } from './definitions.js';

export type Stage = 'adoption' | 'local' | 'pr' | 'build' | 'release' | 'staging' | 'deployment' | 'operations';
export type Environment = 'local' | 'preview' | 'staging' | 'production';
export type Outcome =
  | 'pending'
  | 'pass'
  | 'fail'
  | 'error'
  | 'skipped'
  | 'unsupported'
  | 'stale'
  | 'not_applicable'
  | 'waived';
export type Coverage = 'complete' | 'partial' | 'unknown';
export type EvidenceOrigin = 'actual_tool' | 'manual_attestation' | 'fixture';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type ControlOutcome =
  | 'satisfied'
  | 'unmet'
  | 'waived'
  | 'not_applicable'
  | 'unsupported'
  | 'unknown';

export type ReleaseEvidence = {
  readonly schema_version: 'release-evidence/v1';
  readonly application: { readonly id: string; readonly name?: string; readonly profiles: readonly string[] };
  readonly stage: Stage;
  readonly environment: Environment;
  readonly generated_at: string;
  readonly source: {
    readonly commit: string;
    readonly clean: boolean;
    readonly build_identity?: string;
    readonly deliverable_digest?: string;
    readonly deploy_identity?: string;
  };
  readonly policy: { readonly repository: string; readonly commit: string; readonly control_catalogue_digest?: string; readonly gate_policy_digest?: string };
  readonly expected_checks: readonly {
    readonly check_id: string;
    readonly control_ids: readonly string[];
    readonly required: boolean;
    readonly method?: string;
    readonly recipe?: string;
  }[];
  readonly results: readonly {
    readonly check_id: string;
    readonly outcome: Outcome;
    readonly coverage: Coverage;
    readonly evidence_origin: EvidenceOrigin;
    readonly tool_version?: string;
    readonly scope_observed?: number;
    readonly scope_expected?: number;
    readonly report_digest?: string;
    readonly finished_at?: string;
    readonly reasons?: readonly string[];
  }[];
  readonly control_outcomes?: readonly {
    readonly control: string;
    readonly definition_version: number;
    readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
    readonly outcome: ControlOutcome;
    readonly coverage: Coverage;
    readonly required_checks?: readonly string[];
    readonly satisfied_checks?: readonly string[];
    readonly reasons?: readonly string[];
    readonly waiver_refs?: readonly string[];
  }[];
  readonly manual_verification: readonly {
    readonly id: string;
    readonly control: string;
    readonly operator: string;
    readonly observed_at: string;
    readonly expires_at: string;
    readonly outcome: string;
    readonly scope_fingerprint?: string;
    readonly fresh?: boolean;
  }[];
  readonly exceptions?: readonly {
    readonly id: string;
    readonly control: string;
    readonly scope?: string;
    readonly status: string;
    readonly approver?: string;
    readonly self_review?: boolean;
    readonly expires_at: string;
  }[];
  /**
   * Reviewed false-positive records (F-02/A-4). Reported as their own section: a cleared finding
   * stays visible with the record that cleared it, and a record with no current finding is shown
   * as stale rather than silently dropped.
   */
  readonly recorded_false_positives?: readonly {
    readonly id: string;
    readonly rule_id: string;
    readonly file: string;
    readonly reviewer: string;
    readonly reason: string;
    readonly reviewed_at: string;
    readonly matched_finding?: string;
  }[];
  readonly outstanding: readonly {
    readonly id: string;
    readonly severity: Severity;
    readonly summary: string;
    readonly control_ids?: readonly string[];
    readonly exception_ref?: string;
    readonly first_seen?: string;
  }[];
  readonly unsupported_scope?: readonly { readonly area: string; readonly reason: string; readonly control_ids?: readonly string[] }[];
  readonly decision: {
    readonly outcome: 'satisfied' | 'blocked';
    readonly reasons: readonly string[];
    readonly blocking_reason_codes?: readonly string[];
    readonly kit_readiness?: 'verified' | 'pending' | 'not_applicable';
    readonly application_production_readiness?: 'verified' | 'pending' | 'not_applicable';
  };
};

export interface ExpectedCheck {
  readonly check_id: string;
  readonly control_ids: readonly string[];
  readonly method: string;
  readonly recipe: string;
  readonly recipe_version?: string;
  readonly stage: Stage;
  readonly environment: Environment;
  readonly required: boolean;
  readonly optional?: boolean;
  readonly identity: {
    readonly source_commit: string;
    readonly policy_commit: string;
    readonly configuration_digest?: string;
    readonly target?: string;
    readonly run_id: string;
    readonly attempt: number;
  };
  readonly expected_scope: {
    readonly min_files?: number;
    readonly min_languages?: readonly string[];
    readonly min_routes?: number;
    readonly require_lockfile?: boolean;
    readonly description?: string;
  };
  readonly execution?: {
    readonly mode?: 'internal' | 'process' | 'manual';
    readonly executable?: string;
    readonly arguments?: readonly string[];
    readonly env_allowlist?: readonly string[];
    readonly working_directory?: string;
    readonly timeout_ms?: number;
    readonly max_output_bytes?: number;
    readonly requires_isolation?: boolean;
  };
  readonly required_coverage: Coverage;
  readonly evidence_freshness?: {
    readonly advisory_max_age_hours?: number;
    readonly manual_max_age_days?: number;
  };
}

export interface ExecutionPlan {
  readonly schema_version: 'execution-plan/v1';
  readonly plan_id: string;
  readonly run_id: string;
  readonly attempt: number;
  readonly stage: Stage;
  readonly environment: Environment;
  readonly created_at: string;
  readonly policy_identity: {
    readonly commit: string;
    readonly control_catalogue_digest: string;
    readonly gate_policy_digest: string;
    readonly profile_digests: Readonly<Record<string, string>>;
  };
  readonly inputs: {
    readonly app_id: string;
    readonly app_manifest_digest?: string;
    readonly source_commit: string;
    readonly source_dirty?: boolean;
    readonly profiles: readonly string[];
    readonly targets?: readonly PlanTarget[];
  };
  readonly expected_checks: readonly ExpectedCheck[];
}

export interface PlanTarget {
  readonly id: string;
  readonly scheme: 'http' | 'https';
  readonly host: string;
  readonly port?: number;
  readonly environment: Environment;
  readonly routes?: readonly string[];
  readonly approved_redirect_hosts?: readonly string[];
}

export interface Finding {
  readonly id: string;
  readonly tool: string;
  readonly rule_id: string;
  readonly severity: Severity;
  readonly title?: string;
  readonly location?: string;
  readonly resource?: string;
  readonly detail?: string;
  readonly redacted?: boolean;
  readonly control_ids?: readonly string[];
  /** Marks a finding as an exposure of credential material, whatever tool produced it. */
  readonly category?: 'secret';
  /** SHA-256 of the matched text, never the matched text itself. Identifies the same secret across scans and triage revalidation. */
  readonly secret_digest?: string;
  /** The commit a history scan found the secret in; repository findings leave it unset. */
  readonly commit?: string;
  readonly triage?: 'unresolved' | 'false_positive' | 'accepted' | 'fixed';
  readonly triage_reason?: string;
  readonly exception_ref?: string;
}

export interface CheckResult {
  readonly schema_version: 'check-result/v1';
  readonly run_id: string;
  readonly check_id: string;
  readonly control_ids: readonly string[];
  readonly recipe: string;
  readonly recipe_version?: string;
  readonly stage: Stage;
  readonly environment: Environment;
  readonly required?: boolean;
  readonly outcome: Outcome;
  readonly coverage: Coverage;
  readonly tool?: {
    readonly name?: string;
    readonly observed_version?: string;
    readonly expected_version?: string;
    readonly rule_pack?: string;
    readonly advisory_snapshot_at?: string;
    readonly binary_digest?: string;
    readonly advisory_mode?: 'online_query' | 'offline_database';
    readonly advisory_provenance?: {
      readonly queried_at?: string;
      readonly endpoint?: string;
      readonly database_id?: string;
      readonly database_digest?: string;
      readonly database_retrieved_at?: string;
      readonly upstream_updated_at?: string;
      readonly notes?: string;
    };
  };
  readonly identity: {
    readonly source_commit: string;
    readonly policy_commit: string;
    readonly source_dirty?: boolean;
    readonly target?: string;
    readonly configuration_digest?: string;
    readonly run_id: string;
    readonly attempt: number;
  };
  readonly started_at: string;
  readonly finished_at: string;
  readonly duration_ms?: number;
  readonly exit_code?: number | null;
  readonly signal?: string | null;
  readonly timed_out?: boolean;
  readonly scope?: {
    readonly expected?: number;
    readonly observed?: number;
    readonly files?: readonly string[];
    readonly truncated?: boolean;
    readonly routes?: readonly string[];
    readonly fingerprint?: string;
    readonly notes?: string;
  };
  readonly findings?: readonly Finding[];
  readonly report?: { readonly path?: string; readonly raw_digest?: string; readonly bytes?: number };
  readonly evidence_origin: EvidenceOrigin;
  readonly diagnostic?: string;
  readonly notes?: string;
}

export interface ManualEvidence {
  readonly schema_version: 'manual-evidence/v1';
  readonly id: string;
  readonly control: string;
  readonly recipe: string;
  readonly recipe_version?: string;
  readonly operator: { readonly identity: string; readonly role?: string; readonly independent_of_owner?: boolean };
  readonly observed_at: string;
  readonly target: { readonly environment: Environment; readonly identifier?: string; readonly configuration_fingerprint?: string };
  readonly scope_fingerprint: string;
  readonly observed_configuration?: string;
  readonly supporting_refs?: readonly string[];
  readonly supporting_digests?: readonly string[];
  readonly outcome: 'pending' | 'pass' | 'fail' | 'unsupported' | 'partial';
  readonly notes?: string;
  readonly expires_at: string;
  readonly reassessment_trigger?: string;
  readonly source_commit?: string;
}

export interface ExceptionRecord {
  readonly schema_version: 'exception/v1';
  readonly id: string;
  readonly status: 'active' | 'expired' | 'revoked' | 'pending_approval';
  readonly scope: {
    readonly control?: string;
    readonly control_definition_version?: number;
    readonly check_id?: string;
    readonly finding_id?: string;
    readonly rule_id?: string;
    readonly profile?: string;
    readonly environment?: Environment;
    readonly source_ref?: string;
  };
  readonly reason: string;
  readonly risk: string;
  readonly compensating_measures: readonly string[];
  readonly owner: string;
  readonly approver: string;
  readonly self_review?: boolean;
  readonly expires_at: string;
  readonly remediation_ref?: string;
  readonly created_at?: string;
  readonly revoked_at?: string;
}

export type Profile = ProfileDefinition;

/**
 * A reviewed false-positive record (fix brief F-02/A-4). The only way a false-positive label
 * clears a finding: labels in result files are not accepted, and the fingerprint revalidates, so
 * a changed file brings the finding back.
 */
export interface TriageRecord {
  readonly schema_version: 'triage/v1';
  readonly id: string;
  readonly finding_fingerprint: string;
  readonly rule_id: string;
  readonly file: string;
  readonly triage: 'false_positive';
  readonly reason: string;
  readonly reviewer: string;
  readonly reviewed_at: string;
}

export interface AssessmentRecord {
  readonly control: string;
  readonly definition_version: number;
  readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
  readonly applicability_reason?: string;
  readonly status: Outcome;
  readonly owner: string;
  readonly implementation_refs?: readonly string[];
  readonly evidence_refs?: readonly string[];
  readonly exception_refs?: readonly string[];
  readonly assessed_at: string;
}

export interface ManifestRecord {
  readonly id: string;
  readonly features: Readonly<Record<string, { readonly state: 'enabled' | 'disabled' | 'unknown' } | undefined>>;
  readonly environments: readonly {
    readonly name: string;
    readonly kind: Environment;
    readonly internet_facing?: boolean;
    readonly separated?: boolean;
  }[];
  readonly profiles: readonly string[];
  readonly policy_lock: { readonly repository: string; readonly commit: string; readonly policy_digest: string };
}

export interface GatePolicy {
  readonly policy_version: number;
  readonly review_status: string;
  readonly stages: Readonly<Record<string, {
    readonly description?: string;
    readonly require_clean_source?: boolean;
    readonly advisory_snapshot_max_age_hours?: number;
    readonly require_actual_tool_origin?: boolean;
  }>>;
  readonly freshness: {
    readonly allow_cross_run_reuse?: boolean;
    readonly manual_evidence_default_max_age_days: number;
    readonly manual_evidence_exercise_max_age_days: number;
    readonly max_clock_skew_minutes?: number;
    readonly reject_future_evidence?: boolean;
  };
  readonly risk: {
    readonly blocking_severities: readonly Severity[];
    readonly unknown_severity_requires_triage: boolean;
  };
  readonly coverage: { readonly require_expected_scope_for_pass: boolean; readonly empty_scope_blocks: boolean };
  readonly evidence: { readonly fixture_origin_can_satisfy_release: boolean; readonly duplicate_check_ids_block: boolean };
  readonly control_categories: { readonly error_not_exceptable: readonly string[]; readonly never_exceptable: readonly string[] };
  /** Ceilings on what an exception may waive. Absent fields default to the restrictive setting. */
  readonly exceptions?: {
    readonly critical_findings_never_waivable?: boolean;
    readonly high_findings_require_non_self_approver_at_release?: boolean;
  };
  /**
   * Secret-exposure policy. `secret_scanners` names the tools whose findings are secret exposures
   * even if a classification step failed to set `category`; `findings_never_waivable` bans
   * waiving secret findings of any severity — a leaked credential needs rotation, not
   * acceptance. Absent fields default to the restrictive setting.
   */
  readonly secrets?: {
    readonly secret_scanners?: readonly string[];
    readonly findings_never_waivable?: boolean;
  };
}

export interface Reason {
  readonly code: string;
  readonly message: string;
  readonly control_ids?: readonly string[];
  readonly check_id?: string;
  readonly finding_id?: string;
  readonly severity?: Severity;
  readonly waived_by?: readonly string[];
}

export interface ControlEvaluation {
  readonly control: string;
  readonly definition_version: number;
  readonly applicability: 'applicable' | 'not_applicable' | 'unknown';
  readonly outcome: ControlOutcome;
  readonly coverage: Coverage;
  readonly required_checks: readonly string[];
  readonly satisfied_checks: readonly string[];
  readonly reasons: readonly Reason[];
  readonly waiver_refs: readonly string[];
}

export interface GateDecision {
  readonly satisfied: boolean;
  readonly stage: Stage;
  readonly environment: Environment;
  readonly reasons: readonly Reason[];
  readonly control_outcomes: readonly ControlEvaluation[];
  readonly coverage_gaps: readonly string[];
  readonly unsupported_scope: readonly string[];
  /** Present when the stage requires approval; absent for development stages. */
  readonly approval_states?: readonly {
    readonly control: string;
    readonly definition_version: number;
    readonly approved: boolean;
    readonly self_review: boolean;
    readonly problem?: string;
  }[];
}

export interface EvaluationInput {
  readonly stage: Stage;
  readonly environment: Environment;
  readonly manifest: ManifestRecord;
  readonly profiles: readonly ProfileDefinition[];
  readonly controls: readonly ControlDefinition[];
  readonly plan: ExecutionPlan;
  readonly results: readonly CheckResult[];
  readonly manualEvidence: readonly ManualEvidence[];
  readonly exceptions: readonly ExceptionRecord[];
  readonly assessments: readonly AssessmentRecord[];
  readonly policy: GatePolicy;
  readonly now: Date;
}
