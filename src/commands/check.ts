import { basename } from 'node:path';
import type { CheckResult, ExecutionPlan, ExpectedCheck, Finding } from '../domain/types.js';
import { redactSecrets, relativizeLocation } from '../evidence/redaction.js';

/**
 * The one built-in recipe in Batch A.
 *
 * It re-reads the policy and consumer records the plan depends on and confirms they still hash to
 * what the plan recorded. That is a real check against a real failure mode: a plan derived from
 * policy that changed underneath it. It is deliberately narrow. It is not a scanner, it inspects no
 * application source, and it establishes no coverage over anything beyond the records it read.
 */
export const RECIPE = 'policy/record-consistency';

export interface InternalCheckOutcome {
  readonly outcome: CheckResult['outcome'];
  readonly coverage: CheckResult['coverage'];
  readonly observed: number;
  readonly files: readonly string[];
  readonly findings: readonly Finding[];
  readonly diagnostic?: string;
  /** Scope routes, for a live HTTP recipe. */
  readonly routes?: readonly string[];
  readonly tool?: CheckResult['tool'];
  /** Raw report, recorded as a basename within the run directory plus its digest. */
  readonly reportPath?: string;
  readonly reportDigest?: string;
}

export interface ConsistencyInput {
  readonly check: ExpectedCheck;
  readonly plan: ExecutionPlan;
  readonly digests: Readonly<Record<string, string>>;
  readonly sourceCommit: string;
  readonly now: Date;
}

export function runConsistencyCheck(input: ConsistencyInput): InternalCheckOutcome {
  const expected = input.digests['control_catalogue'];
  const actual = input.digests['observed_control_catalogue'];

  const files = Object.keys(input.digests).length === 0 ? [] : Object.keys(input.digests).sort();

  if (expected === undefined) {
    return {
      outcome: 'unsupported',
      coverage: 'unknown',
      observed: 0,
      files: [],
      findings: [],
      diagnostic: 'the plan recorded no control-catalogue digest, so consistency cannot be established',
    };
  }

  if (actual === undefined) {
    return {
      outcome: 'error',
      coverage: 'partial',
      observed: files.length,
      files,
      findings: [],
      diagnostic: 'could not compute the current control-catalogue digest',
    };
  }

  if (expected !== actual) {
    return {
      outcome: 'fail',
      coverage: 'complete',
      observed: files.length,
      files,
      findings: [
        {
          id: 'consistency.catalogue_changed',
          tool: 'internal',
          rule_id: 'control_catalogue_digest',
          severity: 'high',
          title: 'control catalogue changed after the plan was derived',
          detail: `plan recorded ${expected.slice(0, 12)}, found ${actual.slice(0, 12)}`,
        },
      ],
      diagnostic: 'policy inputs changed between planning and checking',
    };
  }

  return {
    outcome: 'pass',
    coverage: 'complete',
    observed: Math.max(1, files.length),
    files,
    findings: [],
  };
}

/**
 * A diagnostic is free text from a recipe or a tool and often quotes paths ("no browser build
 * output found under <appRoot>"). The audit root inside it is the auditing host's layout, which
 * a published report must not carry, so the root is scrubbed the same way locations are
 * relativized. A path outside the root is untouched.
 */
const scrubRoot = (text: string, appRoot: string): string =>
  appRoot === '' ? text : text.split(`${appRoot}/`).join('').split(appRoot).join('.');

export function makeResult(
  check: ExpectedCheck,
  plan: ExecutionPlan,
  outcome: InternalCheckOutcome,
  runId: string,
  sourceCommit: string,
  startedAt: Date,
  finishedAt: Date,
  appRoot: string,
): CheckResult {
  return {
    schema_version: 'check-result/v1',
    run_id: runId,
    check_id: check.check_id,
    control_ids: check.control_ids,
    recipe: check.recipe,
    stage: check.stage,
    environment: check.environment,
    required: check.required,
    outcome: outcome.outcome,
    coverage: outcome.coverage,
    tool: outcome.tool ?? { name: 'internal', observed_version: '1' },
    identity: {
      source_commit: sourceCommit,
      policy_commit: plan.policy_identity.commit,
      run_id: check.identity.run_id,
      attempt: check.identity.attempt,
      ...(check.identity.configuration_digest === undefined ? {} : { configuration_digest: check.identity.configuration_digest }),
    },
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    duration_ms: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
    exit_code: outcome.outcome === 'pass' ? 0 : 1,
    scope: {
      expected: 1,
      observed: outcome.observed,
      files: outcome.files.map((file) => redactSecrets(relativizeLocation(file, appRoot))),
      ...(outcome.routes === undefined ? {} : { routes: outcome.routes.map((route) => redactSecrets(route)) }),
    },
    ...(outcome.reportDigest === undefined
      ? {}
      : { report: { ...(outcome.reportPath === undefined ? {} : { path: basename(outcome.reportPath) }), raw_digest: outcome.reportDigest } }),
    findings: outcome.findings.map((finding) => ({
      ...finding,
      // Titles and details come from tools and application files. A title can carry a secret just as
      // a detail can, and a report is published; redaction happens once, at the boundary. Locations
      // are relativized here for the same reason: this is the one place every result is created.
      ...(finding.location === undefined ? {} : { location: relativizeLocation(finding.location, appRoot) }),
      ...(finding.title === undefined ? {} : { title: redactSecrets(finding.title) }),
      ...(finding.detail === undefined ? {} : { detail: redactSecrets(finding.detail) }),
    })),
    evidence_origin: 'actual_tool',
    ...(outcome.diagnostic === undefined ? {} : { diagnostic: redactSecrets(scrubRoot(outcome.diagnostic, appRoot)) }),
  };
}
