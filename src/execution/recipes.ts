import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parseGitleaksReport } from '../adapters/gitleaks.js';
import { loadTargetInventory, runHttpChecks } from '../adapters/http.js';
import { parseOpengrepReport } from '../adapters/opengrep.js';
import { parseOsvReport } from '../adapters/osv.js';
import { parseZizmorReport } from '../adapters/zizmor.js';
import { inspectBrowserAssets } from '../build/client-assets.js';
import { analyzeDependencyHealth, analyzeRepoHygiene } from '../quality/hygiene.js';
import { analyzeStrictCorrectness, analyzeTestQuality } from '../quality/correctness.js';
import { analyzeVibeTells } from '../quality/tells.js';
import { loadQualityThresholds } from '../quality/thresholds.js';
import { resolveTool, runTool, type ToolAvailability } from './registry.js';
import type { CheckResult, Coverage, Environment, ExpectedCheck, Finding } from '../domain/types.js';

/**
 * The recipe registry: what `hardening check` can actually run.
 *
 * A recipe is "done" only when the CLI produces a real result for it against a real target. Each
 * handler runs its tool through the reviewed-executable registry (identity, version, and digest
 * checked before execution), parses the real report with the adapter for that tool, and states the
 * scope the tool reported.
 *
 * Three outcomes are possible:
 *   - `pass` — the tool ran and its findings are carried for the evaluator to judge. A scan with
 *     findings still counts as a completed execution: severity decides whether it blocks, and the
 *     gate is where that decision belongs.
 *   - `error` — the tool is missing, the report was unreadable, or the process failed. Never a pass.
 *   - `unsupported` — the recipe cannot apply here (no git worktree, no lockfile, no workflows, no
 *     build output). The reason is recorded and the required check stays unmet.
 */

export interface RecipeContext {
  readonly appRoot: string;
  readonly policyRoot: string;
  /** Where consumer records (including the approved-target inventory) live. */
  readonly recordsRoot?: string;
  readonly environment: Environment;
  readonly check: ExpectedCheck;
  /** Directory for raw reports. Written with digests recorded in the result. */
  readonly rawDir: string;
  readonly now: Date;
}

export interface RecipeOutcome {
  readonly outcome: 'pass' | 'error' | 'unsupported';
  readonly coverage: Coverage;
  readonly observed: number;
  readonly files: readonly string[];
  readonly routes?: readonly string[];
  readonly findings: readonly Finding[];
  readonly diagnostic?: string;
  readonly tool?: CheckResult['tool'];
  readonly reportPath?: string;
  readonly reportDigest?: string;
}

export type RecipeHandler = (context: RecipeContext) => Promise<RecipeOutcome>;

const MAX_FILES_RECORDED = 5000;

function unsupported(diagnostic: string): RecipeOutcome {
  return { outcome: 'unsupported', coverage: 'unknown', observed: 0, files: [], findings: [], diagnostic };
}

function errored(diagnostic: string): RecipeOutcome {
  return { outcome: 'error', coverage: 'unknown', observed: 0, files: [], findings: [], diagnostic };
}

function unavailable(availability: ToolAvailability): RecipeOutcome {
  if (availability.available) return errored('tool did not run');
  return errored(`${availability.reason}: ${availability.message}`);
}

function toolIdentity(name: string): CheckResult['tool'] {
  const availability = resolveTool(name);
  return {
    name,
    ...(availability.available ? { observed_version: availability.expectedVersion } : {}),
  };
}

function digestOf(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function gitOutput(cwd: string, args: readonly string[]): string | undefined {
  const git = resolveTool('git');
  if (!git.available) return undefined;
  try {
    const stdout = execFileSync(git.executable, [...args], {
      cwd,
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { PATH: process.env['PATH'] ?? '' },
    }).trim();
    return stdout.length === 0 ? undefined : stdout;
  } catch {
    return undefined;
  }
}

const worktreeRoot = (appRoot: string): string | undefined => gitOutput(appRoot, ['rev-parse', '--show-toplevel']);

async function runGitleaks(context: RecipeContext, headOnly: boolean): Promise<RecipeOutcome> {
  const worktree = worktreeRoot(context.appRoot);
  if (worktree === undefined) {
    return unsupported('the application root is not inside a git worktree, so a repository or history secret scan cannot run');
  }

  const files = (gitOutput(worktree, ['ls-files']) ?? '').split('\n').filter((line) => line.length > 0);
  mkdirSync(context.rawDir, { recursive: true });
  const reportPath = join(context.rawDir, headOnly ? 'gitleaks-repository.json' : 'gitleaks-history.json');
  const args = [
    'git',
    worktree,
    '--report-format', 'json',
    '--report-path', reportPath,
    '--no-banner',
    '--redact',
    '--exit-code', '0',
    '--config', join(context.policyRoot, 'ci', 'configs', 'gitleaks.toml'),
  ];
  if (headOnly) args.push('--log-opts', '-1');

  // Gitleaks shells out to `git` for a git-mode scan. The child PATH names only the reviewed git's
  // directory plus the system basics, so the internal lookup cannot be redirected by the caller's
  // environment; the parent environment is still not inherited wholesale.
  const git = resolveTool('git');
  const env = git.available ? { PATH: [dirname(git.executable), '/usr/bin', '/bin'].join(':') } : undefined;
  const run = await runTool('gitleaks', args, { cwd: worktree, timeoutMs: 600_000, ...(env === undefined ? {} : { env }) });
  if (!run.ran || run.outcome === undefined) return unavailable(run.availability);
  if (run.outcome.exitCode !== 0) {
    return errored(`gitleaks exited ${String(run.outcome.exitCode)}: ${run.outcome.stderr.slice(-400).trim() || '(no stderr)'}`);
  }

  let raw: string;
  try {
    raw = readFileSync(reportPath, 'utf8');
  } catch {
    return errored(`gitleaks did not write a report to ${reportPath}`);
  }

  const parsed = parseGitleaksReport(raw, { stderr: run.outcome.stderr, intendedScope: files.slice(0, MAX_FILES_RECORDED) });
  if ('error' in parsed) return errored(`${parsed.error}; the raw report digest is ${digestOf(raw).slice(0, 12)}…`);

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    // The scope record is the tracked-file inventory the scan was scoped to. Gitleaks reports bytes,
    // not files, so coverage stays partial: this is why the control is classified `mixed`.
    observed: files.length,
    files: files.slice(0, MAX_FILES_RECORDED),
    findings: parsed.findings,
    tool: toolIdentity('gitleaks'),
    reportPath,
    reportDigest: digestOf(raw),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

const LOCKFILE_NAMES = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json', 'requirements.txt', 'go.mod', 'Cargo.lock', 'composer.lock'] as const;

function findLockfile(root: string): string | undefined {
  for (const name of LOCKFILE_NAMES) {
    const candidate = join(root, name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

/** The lockfile's package count, when it can be established. Used to judge OSV coverage honestly. */
export function countLockfilePackages(lockfile: string): number | undefined {
  try {
    if (lockfile.endsWith('package-lock.json') || lockfile.endsWith('npm-shrinkwrap.json')) {
      const parsed = JSON.parse(readFileSync(lockfile, 'utf8')) as { packages?: Record<string, unknown> };
      if (parsed.packages === undefined) return undefined;
      return Object.keys(parsed.packages).filter((key) => key.length > 0).length;
    }
    if (lockfile.endsWith('pnpm-lock.yaml')) {
      const parsed = parseYaml(readFileSync(lockfile, 'utf8')) as { packages?: Record<string, unknown> };
      return parsed.packages === undefined ? undefined : Object.keys(parsed.packages).length;
    }
    if (lockfile.endsWith('yarn.lock')) {
      return readFileSync(lockfile, 'utf8').split('\n').filter((line) => /^\S.*:$/.test(line)).length || undefined;
    }
    if (lockfile.endsWith('requirements.txt')) {
      return readFileSync(lockfile, 'utf8').split('\n').filter((line) => line.trim().length > 0 && !line.trim().startsWith('#')).length || undefined;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function runOsv(context: RecipeContext): Promise<RecipeOutcome> {
  const root = worktreeRoot(context.appRoot) ?? context.appRoot;
  const lockfile = findLockfile(context.appRoot) ?? (root === context.appRoot ? undefined : findLockfile(root));
  if (lockfile === undefined) {
    return unsupported(`no supported lockfile found in ${context.appRoot}${root === context.appRoot ? '' : ` or ${root}`}; looked for ${LOCKFILE_NAMES.join(', ')}`);
  }

  mkdirSync(context.rawDir, { recursive: true });
  const reportPath = join(context.rawDir, 'osv-lockfile.json');
  const args = ['scan', 'source', '-L', lockfile, '--format', 'json', '--output-file', reportPath];
  const run = await runTool('osv_scanner', args, { cwd: root, timeoutMs: 300_000 });
  if (!run.ran || run.outcome === undefined) return unavailable(run.availability);
  const exitCode = run.outcome.exitCode;
  if (exitCode !== 0 && exitCode !== 1) return errored(`osv-scanner exited ${String(exitCode)}: ${run.outcome.stderr.slice(-400).trim() || '(no stderr)'}`);

  let raw: string;
  try {
    raw = readFileSync(reportPath, 'utf8');
  } catch {
    return errored(`osv-scanner did not write a report to ${reportPath}`);
  }

  const packageCount = countLockfilePackages(lockfile);
  const parsed = parseOsvReport(raw, {
    intendedScope: [lockfile],
    ...(packageCount === undefined ? {} : { expectedPackages: packageCount }),
  });
  if ('error' in parsed) return errored(parsed.error);

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    observed: parsed.scope.observed,
    files: [lockfile],
    findings: parsed.findings,
    tool: {
      ...toolIdentity('osv_scanner'),
      // The default scan queries osv.dev; the query time is the freshness measurement.
      advisory_mode: 'online_query',
      advisory_provenance: { queried_at: context.now.toISOString(), endpoint: 'https://api.osv.dev' },
    },
    reportPath,
    reportDigest: digestOf(raw),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

async function runOpengrepWithPack(context: RecipeContext, packRelativePath: string, packRuleId: string): Promise<RecipeOutcome> {
  const configPath = join(context.policyRoot, 'ci', 'configs', 'opengrep-rules', packRelativePath);
  if (!existsSync(configPath)) return errored(`the reviewed rule pack is missing at ${configPath}`);

  const args = [
    'scan',
    '--config', configPath,
    '--json',
    '--quiet',
    '--exclude', 'node_modules',
    '--exclude', '.next',
    '--exclude', 'dist',
    '--exclude', '.git',
    context.appRoot,
  ];
  const run = await runTool('opengrep', args, { cwd: context.appRoot, timeoutMs: 600_000 });
  if (!run.ran || run.outcome === undefined) return unavailable(run.availability);
  if (run.outcome.exitCode !== 0) return errored(`opengrep exited ${String(run.outcome.exitCode)}: ${run.outcome.stderr.slice(-400).trim() || '(no stderr)'}`);

  const parsed = parseOpengrepReport(run.outcome.stdout, { appRoot: context.appRoot });
  if ('error' in parsed) return errored(parsed.error);
  if (parsed.scope.observed === 0) {
    return unsupported(`opengrep scanned no files in the application root; there is nothing for the ${packRuleId} rules to analyse`);
  }

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    observed: parsed.scope.observed,
    files: (parsed.scope.files ?? []).slice(0, MAX_FILES_RECORDED),
    findings: parsed.findings,
    tool: { ...toolIdentity('opengrep'), rule_pack: `ci/configs/opengrep-rules/${packRelativePath}` },
    reportDigest: digestOf(run.outcome.stdout),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

const runOpengrep = (context: RecipeContext): Promise<RecipeOutcome> =>
  runOpengrepWithPack(context, 'hardening-core.yaml', 'security');

/**
 * The console-log rule scopes to production source directories by convention (src, app, lib,
 * pages, components, server, api at the audited root). A semgrep `paths` filter proved unreliable
 * here — relative include patterns matched a `.` target and silently matched nothing against an
 * absolute target — so the reviewed scoping lives in this code, where it is tested.
 */
const PRODUCTION_SOURCE_DIRS = new Set(['src', 'app', 'lib', 'pages', 'components', 'server', 'api']);

const runQualityErrors = async (context: RecipeContext): Promise<RecipeOutcome> => {
  const outcome = await runOpengrepWithPack(context, 'quality-errors.yaml', 'error-handling');
  if (outcome.outcome !== 'pass') return outcome;

  const filtered = outcome.findings.filter((finding) => {
    if (finding.rule_id !== 'hardening.quality-console-log-production') return true;
    const firstSegment = (finding.location ?? '').split(/[/:\\]/)[0] ?? '';
    return PRODUCTION_SOURCE_DIRS.has(firstSegment);
  });
  const dropped = outcome.findings.length - filtered.length;

  return {
    ...outcome,
    findings: filtered,
    ...(dropped === 0 ? {} : { diagnostic: `${outcome.diagnostic ?? ''}; ${String(dropped)} console.log finding(s) outside production source directories were held back by the reviewed scoping`.trimStart() }),
  };
};

async function runZizmor(context: RecipeContext): Promise<RecipeOutcome> {
  const root = worktreeRoot(context.appRoot) ?? context.appRoot;
  const workflowsDir = join(root, '.github', 'workflows');
  if (!existsSync(workflowsDir)) {
    return unsupported(`no workflow directory at ${workflowsDir}; there is nothing for zizmor to analyse`);
  }
  let workflowFiles: string[];
  try {
    workflowFiles = readdirSync(workflowsDir).filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'));
  } catch {
    return unsupported(`${workflowsDir} could not be listed`);
  }
  if (workflowFiles.length === 0) return unsupported(`${workflowsDir} contains no workflow files`);

  const run = await runTool('zizmor', ['--format', 'json', '--no-progress', workflowsDir], { cwd: root, timeoutMs: 120_000 });
  if (!run.ran || run.outcome === undefined) return unavailable(run.availability);
  // zizmor exits 14 when it reports findings; both are completed executions.
  if (run.outcome.exitCode !== 0 && run.outcome.exitCode !== 14) {
    return errored(`zizmor exited ${String(run.outcome.exitCode)}: ${run.outcome.stderr.slice(-400).trim() || '(no stderr)'}`);
  }

  const parsed = parseZizmorReport(run.outcome.stdout, {
    intendedScope: workflowFiles.map((name) => join(workflowsDir, name)),
    appRoot: context.appRoot,
  });
  if ('error' in parsed) return errored(parsed.error);

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    observed: parsed.scope.observed,
    files: (parsed.scope.files ?? []).slice(0, MAX_FILES_RECORDED),
    findings: parsed.findings,
    tool: toolIdentity('zizmor'),
    reportDigest: digestOf(run.outcome.stdout),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

const BUILD_OUTPUT_CANDIDATES = ['.next/static', '.output/public', 'dist', 'build', 'out'] as const;

async function runClientAssets(context: RecipeContext): Promise<RecipeOutcome> {
  const inspected = BUILD_OUTPUT_CANDIDATES.map((candidate) => join(context.appRoot, candidate)).find((candidate) => existsSync(candidate));
  if (inspected === undefined) {
    return unsupported(`no browser build output found under ${context.appRoot}; looked for ${BUILD_OUTPUT_CANDIDATES.join(', ')}. Run the application build first`);
  }

  const report = inspectBrowserAssets(inspected);
  return {
    outcome: 'pass',
    coverage: report.coverage,
    observed: report.files.length,
    files: report.files.map((entry) => entry.path).slice(0, MAX_FILES_RECORDED),
    findings: report.findings,
    tool: { name: 'client-asset-inspection', observed_version: '1' },
    diagnostic: [
      `${report.classifications.length} intended-public classification(s). ${report.scopeStatement}`,
      ...report.parseErrors,
    ].join(' '),
  };
}

async function runLiveHttp(context: RecipeContext): Promise<RecipeOutcome> {
  const recordsRoot = context.recordsRoot ?? context.appRoot;
  const file = join(recordsRoot, '.hardening', 'targets.yaml');
  const { inventory, issues } = loadTargetInventory(file);
  if (inventory === undefined) return unsupported(`no approved target inventory: ${issues.join('; ')}`);
  if (issues.length > 0) return errored(`the target inventory is not usable: ${issues.join('; ')}`);

  const forEnvironment = inventory.targets.filter((target) => target.environment === context.environment);
  if (forEnvironment.length === 0) {
    return unsupported(`the inventory declares no target for the ${context.environment} environment`);
  }

  const outcome = await runHttpChecks({ schema_version: inventory.schema_version, targets: forEnvironment }, { environment: context.environment, now: context.now });
  const routes = outcome.scope.files ?? [];
  return {
    outcome: 'pass',
    coverage: outcome.coverage,
    observed: outcome.scope.observed,
    files: routes,
    ...(routes.length === 0 ? {} : { routes }),
    findings: outcome.findings,
    tool: { name: 'hardening-http', observed_version: '1' },
    ...(outcome.parserErrors.length === 0 ? {} : { diagnostic: outcome.parserErrors.join('; ') }),
  };
}

function thresholdsFor(context: RecipeContext): { thresholds?: QualityThresholdsShape; failure?: RecipeOutcome } {
  const loaded = loadQualityThresholds(context.policyRoot);
  if (loaded.thresholds === undefined) {
    return {
      failure: errored(`the reviewed quality thresholds are unusable: ${loaded.issues.join('; ')}`),
    };
  }
  return { thresholds: loaded.thresholds };
}

type QualityThresholdsShape = ReturnType<typeof loadQualityThresholds>['thresholds'];

const runStrictCorrectness = (context: RecipeContext): Promise<RecipeOutcome> => {
  const { thresholds, failure } = thresholdsFor(context);
  if (thresholds === undefined) return Promise.resolve(failure as RecipeOutcome);
  const result = analyzeStrictCorrectness(context.appRoot, thresholds.strict_correctness);
  return Promise.resolve(qualityOutcome('quality-strict-correctness', result.findings, result.filesRead,
    'suppression-marker and any-escape counts; full strict lint and the application\'s own tsc probe are recorded gaps'));
};

const runTestQuality = (context: RecipeContext): Promise<RecipeOutcome> => {
  const result = analyzeTestQuality(context.appRoot);
  return Promise.resolve(qualityOutcome('quality-test-quality', result.findings, result.filesRead,
    'static test-shape signals; coverage ratios and mutation scores need running the suite, which the isolation model forbids'));
};

const runVibeTells = (context: RecipeContext): Promise<RecipeOutcome> => {
  const { thresholds, failure } = thresholdsFor(context);
  if (thresholds === undefined) return Promise.resolve(failure as RecipeOutcome);
  const result = analyzeVibeTells(context.appRoot, { maxFilesListed: thresholds.vibe_tells.max_files_listed });
  return Promise.resolve(qualityOutcome('quality-vibe-tells', result.findings, result.scope.filesRead,
    'review-candidate signals measured on the calibration corpus; never proof of authorship'));
};

const runRepoHygiene = (context: RecipeContext): Promise<RecipeOutcome> => {
  const { thresholds, failure } = thresholdsFor(context);
  if (thresholds === undefined) return Promise.resolve(failure as RecipeOutcome);
  const result = analyzeRepoHygiene(context.appRoot, thresholds.repo_hygiene.expected_lockfiles);
  return Promise.resolve(qualityOutcome('quality-repo-hygiene', result.findings, result.checks,
    'presence checks: artifacts existing is not the same as CI being green or documentation being true'));
};

const runDependencyHealth = (context: RecipeContext): Promise<RecipeOutcome> => {
  const { thresholds, failure } = thresholdsFor(context);
  if (thresholds === undefined) return Promise.resolve(failure as RecipeOutcome);
  const result = analyzeDependencyHealth(context.appRoot, thresholds.repo_hygiene.expected_lockfiles, thresholds.dependency_health.equivalent_roles);
  return Promise.resolve(qualityOutcome('quality-dependency-health', result.findings, result.packagesExamined,
    'lockfile duplicate-role scan; registry-based deprecation and major-drift checks are recorded gaps'));
};

function qualityOutcome(toolName: string, findings: readonly Finding[], observed: number, coverageNote: string): RecipeOutcome {
  return {
    outcome: 'pass',
    coverage: 'complete',
    observed,
    files: [],
    findings,
    tool: { name: toolName, observed_version: '1' },
    diagnostic: coverageNote,
  };
}

export const RECIPES: Readonly<Record<string, RecipeHandler>> = {
  'gitleaks/repository': (context) => runGitleaks(context, true),
  'gitleaks/history': (context) => runGitleaks(context, false),
  'osv/lockfile': runOsv,
  'opengrep/rules': runOpengrep,
  'zizmor/workflows': runZizmor,
  'build/client-assets': runClientAssets,
  'web/http-requirements': runLiveHttp,
  'quality/error-handling': runQualityErrors,
  'quality/strict-correctness': runStrictCorrectness,
  'quality/test-quality': runTestQuality,
  'quality/vibe-tells': runVibeTells,
  'quality/repo-hygiene': runRepoHygiene,
  'quality/dependency-health': runDependencyHealth,
};

export const IMPLEMENTED_RECIPES: readonly string[] = Object.keys(RECIPES);
