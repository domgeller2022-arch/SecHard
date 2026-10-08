#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createRunDirectory, environmentIdentity, writeAtomic, writeJson, type RunRecord } from './evidence/store.js';
import {
  approvalsCommand,
  checkCommand,
  gateCommand,
  planCommand,
  reportCommand,
  validateCommand,
  type CheckOutcome,
  type CommandOutcome,
  type PlanOutcome,
} from './commands/run.js';

const STAGES = ['adoption', 'local', 'pr', 'build', 'release', 'staging', 'deployment', 'operations'] as const;
const ENVIRONMENTS = ['local', 'preview', 'staging', 'production'] as const;

const USAGE = `hardening - versioned control catalogue, verification checks, and release evidence

Usage:
  hardening validate  --app APP_ROOT --policy POLICY_ROOT
  hardening plan      --app APP_ROOT --policy POLICY_ROOT --stage STAGE --environment ENV --out RUN_DIR
  hardening check     --app APP_ROOT --policy POLICY_ROOT --plan RUN_DIR/plan.json --out RUN_DIR
  hardening gate      --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
  hardening report    --app APP_ROOT --policy POLICY_ROOT --run RUN_DIR
  hardening approvals --policy POLICY_ROOT
  hardening help
  hardening version

Stages:      ${STAGES.join(', ')}
Environments: ${ENVIRONMENTS.join(', ')}

Exit codes:
  0  decision satisfied
  1  valid execution with a blocking finding or unmet requirement
  2  invalid inputs, or execution/evidence errors

Both nonzero outcomes block a required CI check.
`;

interface Options {
  app?: string;
  policy?: string;
  stage?: string;
  environment?: string;
  out?: string;
  plan?: string;
  run?: string;
}

/**
 * Writes to a file descriptor synchronously.
 *
 * `process.stdout.write` is asynchronous on a pipe, and `process.exit()` does not wait for it: a
 * CI job capturing the CLI through a pipe can silently lose the first commands' output. `writeSync`
 * flushes before returning, so every branch below can exit immediately without truncating.
 */
function out(text: string): void {
  writeSync(1, text);
}

function err(text: string): void {
  writeSync(2, text);
}

function fail(message: string, stderr: readonly string[] = []): never {
  err(`hardening: ${message}\n`);
  for (const line of stderr) err(`${line}\n`);
  process.exit(2);
}

function emit(outcome: CommandOutcome): void {
  for (const line of outcome.stdout) out(`${line}\n`);
  for (const warning of outcome.warnings ?? []) out(`warning: ${warning}\n`);
  for (const line of outcome.stderr) err(`${line}\n`);
}

function required(options: Options, name: keyof Options): string {
  const value = options[name];
  if (typeof value !== 'string' || value.length === 0) {
    fail(`missing required option --${name}. Run \`hardening help\`.`);
  }
  return value;
}

function readVersion(): string {
  const manifest: unknown = JSON.parse(readSync('../package.json'));
  const version = (manifest as { version?: unknown }).version;
  if (typeof version !== 'string') fail('package.json has no version field');
  return version;
}

function readSync(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {
    app: { type: 'string' },
    policy: { type: 'string' },
    stage: { type: 'string' },
    environment: { type: 'string' },
    out: { type: 'string' },
    plan: { type: 'string' },
    run: { type: 'string' },
  },
  strict: true,
});

const command = positionals[0] ?? 'help';
const options = values as Options;

if (command === 'help') {
  out(USAGE);
  process.exit(0);
}

if (command === 'version') {
  out(`${readVersion()}\n`);
  process.exit(0);
}

if (!['validate', 'plan', 'check', 'gate', 'report', 'approvals'].includes(command)) {
  fail(`unknown command '${command}'. Run \`hardening help\`.`);
}

if (command === 'approvals') {
  const policyRoot = resolve(required(options, 'policy'));
  const outcome = approvalsCommand({ appRoot: policyRoot, policyRoot }, { now: new Date() });
  emit(outcome);
  process.exit(outcome.exitCode);
}

const appRoot = resolve(required(options, 'app'));
const policyRoot = resolve(required(options, 'policy'));
const now = new Date();

function newRunId(prefix: string): string {
  // Sortable and unique per invocation; the plan identity is what actually binds a run.
  return `${prefix}-${now.toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`;
}

if (command === 'validate') {
  const validated = validateCommand({ appRoot, policyRoot });
  emit(validated);
  process.exit(validated.exitCode);
}

if (command === 'plan') {
  const stage = required(options, 'stage');
  const environment = required(options, 'environment');

  if (!STAGES.includes(stage as (typeof STAGES)[number])) {
    fail(`unknown stage '${stage}'. Expected one of: ${STAGES.join(', ')}`);
  }
  if (!ENVIRONMENTS.includes(environment as (typeof ENVIRONMENTS)[number])) {
    fail(`unknown environment '${environment}'. Expected one of: ${ENVIRONMENTS.join(', ')}`);
  }

  const outDir = resolve(required(options, 'out'));
  const runId = newRunId(stage);
  const planned: PlanOutcome = planCommand({ appRoot, policyRoot }, { stage: stage as (typeof STAGES)[number], environment: environment as (typeof ENVIRONMENTS)[number], runId, now });

  if (planned.plan === undefined) {
    emit(planned);
    process.exit(planned.exitCode);
  }

  const run = createRunDirectory(outDir, runId);
  writeJson(run.planPath, planned.plan);

  const record: RunRecord = {
    schema: 'hardening/run-record/v1',
    run_id: runId,
    started_at: now.toISOString(),
    stage,
    environment,
    app_root: appRoot,
    policy_root: policyRoot,
    source_commit: planned.plan.inputs.source_commit,
    source_dirty: planned.plan.inputs.source_dirty ?? false,
    ...environmentIdentity(),
    plan_digest: planned.plan.policy_identity.control_catalogue_digest,
  };
  writeJson(run.runRecordPath, record);

out(`  plan written to ${run.planPath}\n`);
emit(planned);
process.exit(planned.exitCode);
}

const runDir = resolve(options.run ?? options.out ?? required(options, 'run'));
const run = {
  planPath: join(runDir, 'plan.json'),
  resultsPath: join(runDir, 'results.json'),
  reportJsonPath: join(runDir, 'report.json'),
  reportMarkdownPath: join(runDir, 'report.md'),
  runRecordPath: join(runDir, 'run.json'),
};
const explicitPlan = options.plan;
const planPath = explicitPlan === undefined ? run.planPath : resolve(explicitPlan);

if (command === 'check') {
  mkdirSync(runDir, { recursive: true });
  const checked: CheckOutcome = await checkCommand({ appRoot, policyRoot }, { planPath, runId: basename(runDir), outDir: runDir, now });

  if (checked.results !== undefined) {
    writeJson(run.resultsPath, checked.results);
    out(`  results written to ${run.resultsPath}\n`);
  }

  emit(checked);

  // A required check that fails still produces a runnable diagnostic record, so the user can see
  // what happened rather than an exit code alone.
  const failed = (checked.results ?? []).some((result) => result.outcome === 'error');
  process.exit(failed ? 2 : checked.exitCode);
}

if (command === 'gate') {
  const gated = gateCommand({ appRoot, policyRoot }, { planPath, resultsPath: run.resultsPath, now });
  emit(gated);
  process.exit(gated.exitCode);
}

const report = reportCommand({ appRoot, policyRoot }, { planPath, resultsPath: run.resultsPath, now });

mkdirSync(runDir, { recursive: true });
writeJson(run.reportJsonPath, report.json);
writeAtomic(run.reportMarkdownPath, report.markdown);
out(`  report written to ${run.reportJsonPath}\n`);
out(`  report written to ${run.reportMarkdownPath}\n`);
emit(report);
process.exit(report.exitCode);
