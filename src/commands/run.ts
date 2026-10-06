import { basename, join } from 'node:path';
import { buildPlan, planIdentity } from '../domain/planner.js';
import { makeResult, runConsistencyCheck } from './check.js';
import { loadDocument } from '../validation/loader.js';
import { validateAgainstSchema } from '../validation/schema.js';
import { ValidationError, type ValidationIssue } from '../validation/errors.js';
import { evaluate } from '../domain/evaluator.js';
import { loadConsumer, loadPolicy, resolveSourceIdentity, type LoadedPolicy, type Paths } from './io.js';
import { buildReport } from './report.js';
import type { ApplicabilityRule } from '../domain/applicability.js';
import type { PlanInput } from '../domain/planner.js';
import type { CheckResult, ExecutionPlan, GateDecision, ManifestRecord, ReleaseEvidence } from '../domain/types.js';

export interface CommandOutcome {
  readonly exitCode: 0 | 1 | 2;
  readonly stdout: readonly string[];
  readonly stderr: readonly string[];
}

export interface PlanOutcome extends CommandOutcome {
  readonly plan?: ExecutionPlan;
  readonly source?: { readonly commit: string; readonly dirty: boolean };
}

export interface CheckOutcome extends CommandOutcome {
  readonly results?: readonly CheckResult[];
}

export interface GateOutcome extends CommandOutcome {
  readonly decision?: GateDecision;
}

const formatIssues = (issues: readonly ValidationIssue[]): string[] =>
  issues.map((item) => `  ${item.code}${item.file === undefined ? '' : ` ${item.file}${item.path === undefined ? '' : item.path}`}: ${item.message}`);

export function validateCommand(paths: Paths): CommandOutcome {
  const policyOutcome = loadPolicy(paths);
  const profileIds = policyOutcome.value?.profiles.map((profile) => profile.id) ?? [];
  const consumer = loadConsumer(paths, profileIds);
  const manifest = consumer.value?.manifest;

  const issues = [
    ...policyOutcome.issues,
    ...consumer.issues,
    // A record can be well formed on its own and still contradict another record. Reference
    // integrity is checked, not just individual shapes.
    ...(policyOutcome.value !== undefined && manifest !== undefined
      ? crossCheck(policyOutcome.value, manifest)
      : []),
  ];

  if (issues.length === 0) {
    return {
      exitCode: 0,
      stdout: ['validate: OK', `  policy records: ${policyOutcome.value?.profiles.length ?? 0} profiles, ${policyOutcome.value?.controls.length ?? 0} controls`],
      stderr: [],
    };
  }

  return {
    exitCode: 2,
    stdout: [],
    stderr: [`validate: ${issues.length} issue(s)`, ...formatIssues(issues)],
  };
}

export function planCommand(
  paths: Paths,
  options: { stage: ExecutionPlan['stage']; environment: ExecutionPlan['environment']; runId: string; now: Date },
): CommandOutcome {
  const policyOutcome = loadPolicy(paths);
  if (policyOutcome.value === undefined || policyOutcome.issues.length > 0) {
    return {
      exitCode: 2,
      stdout: [],
      stderr: ['plan: policy inputs are invalid', ...formatIssues(policyOutcome.issues)],
    };
  }
  const policy = policyOutcome.value;

  const consumer = loadConsumer(paths, policy.profiles.map((profile) => profile.id));
  const manifest = consumer.value?.manifest;

  // The manifest is named first so the error names what is actually missing, rather than listing
  // every derived complaint that follows from it.
  if (manifest === undefined) {
    const causes = consumer.issues.filter((item) => item.code === 'input.not_found');
    return {
      exitCode: 2,
      stdout: [],
      stderr: [
        'plan: an application manifest is required',
        ...(causes.length > 0 ? formatIssues(causes) : ['  input.not_found .hardening/app.yaml: no manifest found']),
      ],
    };
  }

  if (consumer.issues.length > 0) {
    return { exitCode: 2, stdout: [], stderr: ['plan: consumer records are invalid', ...formatIssues(consumer.issues)] };
  }

  if (manifest.policy_lock.commit !== policy.policyCommit) {
    return {
      exitCode: 2,
      stdout: [],
      stderr: [
        'plan: the policy lock does not match the supplied policy root',
        `  locked   ${manifest.policy_lock.commit}`,
        `  supplied ${policy.policyCommit}`,
        '  Re-lock to the reviewed commit or point --policy at the locked one.',
      ],
    };
  }

  const requested = manifest.profiles
    .map((id) => policy.profiles.find((profile) => profile.id === id))
    .filter((profile): profile is NonNullable<typeof profile> => profile !== undefined);

  if (requested.length === 0) {
    return {
      exitCode: 2,
      stdout: [],
      stderr: ['plan: none of the selected profiles exist in the policy root'],
    };
  }

  const source = resolveSourceIdentity(paths.appRoot);
  const now = options.now;

  const plan = buildPlan({
    stage: options.stage,
    environment: options.environment,
    manifest,
    profiles: requested,
    controls: policy.controls as unknown as PlanInput['controls'],
    policy: policy.policy,
    policyCommit: policy.policyCommit,
    policyDigests: {
      controlCatalogue: policy.controlCatalogueDigest,
      gatePolicy: policy.gatePolicyDigest,
      profiles: Object.fromEntries(requested.map((profile) => [profile.id, policy.profileDigests[profile.id] ?? ''])),
    },
    sourceCommit: source.commit,
    sourceDirty: source.dirty,
    now,
    planId: options.runId,
    ...(consumer.value?.manifestDigest === undefined ? {} : { appManifestDigest: consumer.value.manifestDigest }),
  });

  return {
    exitCode: 0,
    stdout: [
      `plan: derived ${plan.expected_checks.length} expected check(s) for stage ${plan.stage} in ${plan.environment}`,
      `  source commit ${plan.inputs.source_commit}${plan.inputs.source_dirty === true ? ' (working tree dirty)' : ''}`,
      `  policy commit ${plan.policy_identity.commit}`,
      ...plan.expected_checks.map((check) => `  - ${check.check_id}${check.required ? '' : ' (optional)'}`),
    ],
    stderr: [],
    plan,
    policy,
    manifest,
    source,
  } as PlanOutcome;
}

export function checkCommand(
  paths: Paths,
  options: { planPath: string; runId: string; now: Date },
): CheckOutcome {
  const planLoad = loadPlanFile(options.planPath);
  if (planLoad === undefined) {
    return { exitCode: 2, stdout: [], stderr: [`check: no usable plan at ${options.planPath}`] };
  }
  const { plan } = planLoad;

  const policyOutcome = loadPolicy(paths);
  if (policyOutcome.value === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['check: policy inputs are invalid', ...formatIssues(policyOutcome.issues)] };
  }

  const consumer = loadConsumer(paths, policyOutcome.value.profiles.map((profile) => profile.id));
  const manifest = consumer.value?.manifest;
  if (manifest === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['check: an application manifest is required'] };
  }

  const source = resolveSourceIdentity(paths.appRoot);
  const results: CheckResult[] = [];

  for (const check of plan.expected_checks) {
    if (check.recipe !== 'policy/record-consistency') {
      // Every other recipe belongs to a later batch. Reporting `unsupported` is the honest outcome;
      // claiming a pass would be a fabricated result.
      results.push(
        makeResult(
          check,
          plan,
          {
            outcome: 'unsupported',
            coverage: 'unknown',
            observed: 0,
            files: [],
            findings: [],
            diagnostic: `recipe ${check.recipe} is not implemented in this build; it is selected by the profile and will run once implemented`,
          },
          options.runId,
          source.commit,
          options.now,
          options.now,
        ),
      );
      continue;
    }

    results.push(
      makeResult(
        check,
        plan,
        runConsistencyCheck({
          check,
          plan,
          digests: {
            control_catalogue: plan.policy_identity.control_catalogue_digest,
            observed_control_catalogue: policyOutcome.value.controlCatalogueDigest,
          },
          sourceCommit: source.commit,
          now: options.now,
        }),
        options.runId,
        source.commit,
        options.now,
        options.now,
      ),
    );
  }

  return {
    exitCode: 0,
    stdout: [
      `check: produced ${results.length} result(s)`,
      ...results.map((result) => `  - ${result.check_id}: ${result.outcome} (${result.coverage})`),
    ],
    stderr: [],
    results,
  } as CheckOutcome;
}

export function gateCommand(
  paths: Paths,
  options: { planPath: string; resultsPath?: string; now: Date },
): GateOutcome {
  const planLoad = loadPlanFile(options.planPath);
  if (planLoad === undefined) {
    return { exitCode: 2, stdout: [], stderr: [`gate: no usable plan at ${basename(options.planPath)}`] };
  }
  const { plan, identity } = planLoad;

  const policyOutcome = loadPolicy(paths);
  if (policyOutcome.value === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['gate: policy inputs are invalid', ...formatIssues(policyOutcome.issues)] };
  }
  const policy = policyOutcome.value;

  const consumer = loadConsumer(paths, policy.profiles.map((profile) => profile.id));
  const manifest = consumer.value?.manifest;
  if (manifest === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['gate: an application manifest is required'] };
  }

  const results = options.resultsPath === undefined ? [] : loadResults(options.resultsPath);

  const selectedProfiles = policy.profiles.filter((profile) => manifest.profiles.includes(profile.id));
  const expectedIdentity = planIdentity(
    buildPlan({
      stage: plan.stage,
      environment: plan.environment,
      manifest,
      profiles: selectedProfiles,
      controls: policy.controls as unknown as PlanInput['controls'],
      policy: policy.policy,
      policyCommit: policy.policyCommit,
      policyDigests: {
        controlCatalogue: policy.controlCatalogueDigest,
        gatePolicy: policy.gatePolicyDigest,
        profiles: Object.fromEntries(selectedProfiles.map((profile) => [profile.id, policy.profileDigests[profile.id] ?? ''])),
      },
      sourceCommit: plan.inputs.source_commit,
      sourceDirty: plan.inputs.source_dirty ?? false,
      now: options.now,
      planId: plan.plan_id,
      ...(manifest === undefined || consumer.value?.manifestDigest === undefined ? {} : { appManifestDigest: consumer.value.manifestDigest }),
    }),
  );

  const decision: GateDecision = evaluate({
    stage: plan.stage,
    environment: plan.environment,
    manifest,
    controls: policy.controls.map((control) => ({
      id: control.id,
      definition_version: control.definition_version,
      applicability: control.applicability as ApplicabilityRule,
    })),
    plan,
    results,
    manualEvidence: consumer.value?.manualEvidence ?? [],
    exceptions: consumer.value?.exceptions ?? [],
    policy: policy.policy,
    now: options.now,
    planIdentity: identity,
    expectedPlanIdentity: expectedIdentity,
    excludedFeatures: selectedProfiles.flatMap((profile) => profile.excluded_features ?? []),
  });

  const stdout = [
    decision.satisfied ? 'gate: satisfied' : `gate: blocked (${decision.reasons.length} reason(s))`,
    `  stage ${decision.stage} / ${decision.environment}`,
    `  controls satisfied: ${decision.control_outcomes.filter((item) => item.outcome === 'satisfied').length}/${decision.control_outcomes.length}`,
    `  waived: ${decision.control_outcomes.filter((item) => item.outcome === 'waived').length}`,
    ...decision.reasons.map((item) => `  - ${item.code}: ${item.message}`),
  ];

  return {
    exitCode: decision.satisfied ? 0 : 1,
    stdout,
    stderr: [],
    decision,
  } as GateOutcome;
}

/** Contradictions between records that no single schema can catch on its own. */
function crossCheck(policy: LoadedPolicy, manifest: ManifestRecord): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const profileId of manifest.profiles) {
    if (!policy.profiles.some((profile) => profile.id === profileId)) {
      issues.push({
        code: 'semantic.unknown_reference',
        message: `application selects unknown profile '${profileId}'`,
        file: '.hardening/app.yaml',
      });
    }
  }

  if (manifest.policy_lock.commit !== policy.policyCommit) {
    issues.push({
      code: 'semantic.version_conflict',
      message: `policy lock pins commit ${manifest.policy_lock.commit} but the supplied policy root is at ${policy.policyCommit}`,
      file: '.hardening/app.yaml',
      path: '/policy_lock/commit',
    });
  }

  const controlsById = new Map(policy.controls.map((control) => [control.id, control]));
  for (const profileId of manifest.profiles) {
    for (const entry of policy.profiles.find((profile) => profile.id === profileId)?.controls ?? []) {
      const control = controlsById.get(entry.control);
      if (control === undefined) {
        issues.push({
          code: 'semantic.unknown_reference',
          message: `profile ${profileId} selects unknown control '${entry.control}'`,
          file: `profiles/${profileId}.yaml`,
        });
        continue;
      }
      if (control.verification.length === 0) {
        issues.push({
          code: 'semantic.missing_field',
          message: `control ${entry.control} has no verification method and cannot be selected`,
          file: 'controls/controls.yaml',
        });
      }
    }
  }

  return issues;
}

export interface ReportResult extends CommandOutcome {
  readonly json: ReleaseEvidence;
  readonly markdown: string;
}

export function reportCommand(
  paths: Paths,
  options: { planPath: string; resultsPath?: string; now: Date; appName?: string },
): ReportResult {
  const gated = gateCommand(paths, options);
  if (gated.decision === undefined) {
    return {
      exitCode: gated.exitCode,
      stdout: [],
      stderr: gated.stderr,
      json: emptyEvidence(),
      markdown: '',
    };
  }

  const planLoad = loadPlanFile(options.planPath);
  if (planLoad === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['report: no usable plan'], json: emptyEvidence(), markdown: '' };
  }
  const { plan } = planLoad;
  const policyOutcome = loadPolicy(paths);
  if (policyOutcome.value === undefined) {
    return { exitCode: 2, stdout: [], stderr: ['report: policy inputs are invalid'], json: emptyEvidence(), markdown: '' };
  }

  const consumer = loadConsumer(paths, policyOutcome.value.profiles.map((profile) => profile.id));
  const results = options.resultsPath === undefined ? [] : loadResults(options.resultsPath);
  const decision = gated.decision;

  const { evidence, outstanding } = buildReport({
    decision,
    plan,
    results,
    manualEvidence: consumer.value?.manualEvidence ?? [],
    exceptions: consumer.value?.exceptions ?? [],
    appId: consumer.value?.manifest?.id ?? 'unknown',
    ...(options.appName === undefined ? {} : { appName: options.appName }),
    sourceCommit: plan.inputs.source_commit,
    sourceClean: plan.inputs.source_dirty !== true,
    policyRepository: consumer.value?.manifest?.policy_lock.repository ?? 'unknown',
    policyCommit: plan.policy_identity.commit,
    controlCatalogueDigest: plan.policy_identity.control_catalogue_digest,
    gatePolicyDigest: plan.policy_identity.gate_policy_digest,
    generatedAt: options.now,
    runId: plan.plan_id,
  });

  const markdown = renderMarkdown(evidence, outstanding.length);

  return {
    exitCode: decision.satisfied ? 0 : 1,
    stdout: [
      `report: ${evidence.decision.outcome}`,
      `  ${evidence.expected_checks.length} expected check(s), ${evidence.results.length} result(s)`,
      `  ${outstanding.length} outstanding finding(s)`,
      '  See report.json and report.md in the run directory.',
    ],
    stderr: [],
    json: evidence,
    markdown,
  };
}

/**
 * Formats the same evaluation the gate produced. Markdown and JSON therefore cannot disagree: this
 * function takes the finished evidence object and does no further evaluation.
 */
function renderMarkdown(evidence: ReleaseEvidence, outstandingCount: number): string {
  const lines: string[] = [
    `# Hardening report — ${evidence.application.id}`,
    '',
    `**Decision: ${evidence.decision.outcome}** · stage ${evidence.stage} · environment ${evidence.environment}`,
    '',
    `| | |`,
    `| --- | --- |`,
    `| Source commit | \`${evidence.source.commit}\`${evidence.source.clean ? '' : ' (working tree dirty)'} |`,
    `| Policy commit | \`${evidence.policy.commit}\` |`,
    `| Profiles | ${evidence.application.profiles.map((profile) => `\`${profile}\``).join(', ')} |`,
    `| Expected checks | ${evidence.expected_checks.length} |`,
    `| Results | ${evidence.results.length} |`,
    `| Outstanding findings | ${outstandingCount} |`,
    '',
    '## Decision',
    '',
  ];

  if (evidence.decision.reasons.length === 0) {
    lines.push('No blocking reasons.');
  } else {
    for (const item of evidence.decision.reasons) lines.push(`- ${escape(item)}`);
  }

  lines.push(
    '',
    '## Readiness',
    '',
    `- Kit readiness: **${evidence.decision.kit_readiness ?? 'pending'}**`,
    `- Application production readiness: **${evidence.decision.application_production_readiness ?? 'pending'}**`,
    '',
    'Kit readiness describes this repository and its verification facilities. Application production',
    'readiness describes a deployed application. One does not imply the other.',
    '',
    '## Control outcomes',
    '',
    '| Control | Applicability | Outcome | Coverage | Reasons |',
    '| --- | --- | --- | --- | --- |',
  );

  for (const outcome of evidence.control_outcomes ?? []) {
    lines.push(
      `| ${escape(outcome.control)} | ${outcome.applicability} | ${outcome.outcome} | ${outcome.coverage} | ${escape((outcome.reasons ?? []).join('; ') || '-')} |`,
    );
  }

  lines.push('', '## Outstanding findings', '');
  if (evidence.outstanding.length === 0) {
    lines.push('None reported.');
  } else {
    lines.push('| Severity | Finding | Controls |', '| --- | --- | --- |');
    for (const item of evidence.outstanding) {
      lines.push(`| ${item.severity} | ${escape(item.summary)} (\`${escape(item.id)}\`) | ${item.control_ids?.join(', ') ?? '-'} |`);
    }
  }

  if ((evidence.unsupported_scope ?? []).length > 0) {
    lines.push('', '## Unsupported scope', '');
    for (const item of evidence.unsupported_scope ?? []) lines.push(`- ${escape(item.area)}: ${escape(item.reason)}`);
  }

  if ((evidence.exceptions ?? []).length > 0) {
    lines.push('', '## Exceptions', '', '| Exception | Control | Status | Expires | Self-review |', '| --- | --- | --- | --- | --- |');
    for (const item of evidence.exceptions ?? []) {
      lines.push(`| ${escape(item.id)} | ${escape(item.control)} | ${item.status} | ${item.expires_at} | ${item.self_review === true ? 'yes' : 'no'} |`);
    }
  }

  lines.push('', '---', '', 'Generated from the same evaluation as the gate. Formatting does not change the decision.');
  return `${lines.join('\n')}\n`;
}

function escape(value: string): string {
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function loadPlanFile(planPath: string): { plan: ExecutionPlan; identity: string } | undefined {
  const loaded = loadDocument<ExecutionPlan>(planPath);
  if (loaded.data === undefined) return undefined;
  const result = validateAgainstSchema('execution-plan', loaded.data, planPath);
  if (!result.valid) return undefined;
  return { plan: loaded.data, identity: planIdentity(loaded.data) };
}

function loadResults(resultsPath: string): CheckResult[] {
  const loaded = loadDocument<CheckResult[]>(resultsPath, { requireObject: false });
  if (!Array.isArray(loaded.data)) return [];
  return loaded.data;
}

function emptyEvidence(): ReleaseEvidence {
  return {
    schema_version: 'release-evidence/v1',
    application: { id: 'unknown', profiles: [] },
    stage: 'pr',
    environment: 'local',
    generated_at: new Date(0).toISOString(),
    source: { commit: '0'.repeat(40), clean: false },
    policy: { repository: 'unknown', commit: '0'.repeat(40) },
    expected_checks: [],
    results: [],
    manual_verification: [],
    outstanding: [],
    decision: { outcome: 'blocked', reasons: ['report could not be produced'] },
  };
}

export { join, ValidationError };
