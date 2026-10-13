import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parseGitleaksReport } from '../adapters/gitleaks.js';
import { gitConfigEnv, gitHardeningArgs } from './git-hardening.js';
import { loadTargetInventory, runHttpChecks } from '../adapters/http.js';
import { parseOpengrepReport } from '../adapters/opengrep.js';
import { parseOsvReport } from '../adapters/osv.js';
import { parseZizmorReport } from '../adapters/zizmor.js';
import { inspectBrowserAssets } from '../build/client-assets.js';
import { annotateSecretFindings, gradeIgnoredFileFinding, gradeUntrackedFinding, splitLocation } from '../evidence/secret-severity.js';
import { analyzeDependencyHealth, analyzeRepoHygiene } from '../quality/hygiene.js';
import { analyzeStrictCorrectness, analyzeTestQuality } from '../quality/correctness.js';
import { analyzeVibeTells } from '../quality/tells.js';
import { loadQualityThresholds } from '../quality/thresholds.js';
import { analyzeMigrations } from '../security/migrations.js';
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
    // A-01: harden against the audited tree's own Git configuration executing code.
    const stdout = execFileSync(git.executable, [...gitHardeningArgs(), ...args], {
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

/** The line a `file:line` location points at, trimmed, from the given file content. */
function lineAt(content: string | undefined, location: string | undefined): string | undefined {
  const parts = splitLocation(location);
  if (content === undefined || parts?.line === undefined) return undefined;
  return content.split('\n')[parts.line - 1]?.trimEnd();
}

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

  // Classification (F-02). The matched text is read from the source revision, never from the
  // redacted report: the repository scan reads the worktree, the history scan reads the finding's
  // own commit and falls back to the worktree when the secret survived to HEAD. Values are never
  // stored — only their digest is recorded — so no secret material is written anywhere by this.
  const annotated = annotateSecretFindings(parsed.findings, (finding) => {
    const parts = splitLocation(finding.location);
    if (parts === undefined) return undefined;
    if (!headOnly && finding.commit !== undefined) {
      const committed = lineAt(gitOutput(worktree, ['show', `${finding.commit}:${parts.file}`]), finding.location);
      if (committed !== undefined && committed.length > 0) return committed;
    }
    try {
      return lineAt(readFileSync(join(worktree, parts.file), 'utf8'), finding.location);
    } catch {
      return undefined;
    }
  });

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    // The scope record is the tracked-file inventory the scan was scoped to. Gitleaks reports bytes,
    // not files, so coverage stays partial: this is why the control is classified `mixed`.
    observed: files.length,
    files: files.slice(0, MAX_FILES_RECORDED),
    findings: annotated,
    tool: toolIdentity('gitleaks'),
    reportPath,
    reportDigest: digestOf(raw),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

const LOCKFILE_NAMES = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json', 'requirements.txt', 'go.mod', 'Cargo.lock', 'composer.lock'] as const;

/**
 * The directories the current-files scan never descends into. This is the audit's own exclusion
 * list (F-02 follow-up, owner's auditor 13 October 2026): dependency and build-output directories
 * hold third-party or generated content nobody can remediate. It must stay in step with the
 * machine-dir allowlist in `ci/configs/gitleaks-dir.toml`, which is what actually bounds the scan;
 * this walk only records the honest scope inventory.
 */
const DIR_SCAN_EXCLUDED_DIRS: ReadonlySet<string> = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'vendor']);
const MAX_DIR_WALK_DEPTH = 8;

/** Bounded, read-only walk of the current tree, mirroring the dir config's exclusions. */
function currentFilesWalk(root: string): string[] {
  const files: string[] = [];
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (queue.length > 0 && files.length < MAX_FILES_RECORDED) {
    const { dir, depth } = queue.shift() as { dir: string; depth: number };
    let entries: readonly string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of [...entries].sort()) {
      if (files.length >= MAX_FILES_RECORDED) break;
      if (DIR_SCAN_EXCLUDED_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      let isDirectory = false;
      try {
        isDirectory = statSync(full).isDirectory();
      } catch {
        continue;
      }
      if (isDirectory) {
        if (depth < MAX_DIR_WALK_DEPTH) queue.push({ dir: full, depth: depth + 1 });
        continue;
      }
      files.push(relative(root, full));
    }
  }
  return files;
}

/**
 * The current-files secret scan (F-02 follow-up, owner's auditor 13 October 2026): `gitleaks dir`
 * over the application root, whatever the target is. The git-mode scans read committed content
 * and history — a folder that is not a git repository got no secret scan at all, quick mode could
 * not see files committed before the newest commit, and uncommitted or untracked files were never
 * scanned. This recipe runs at every depth, with or without git, and its findings go through the
 * same classifier, de-duplication, and waiver ban as the git scans.
 */
async function runGitleaksDir(context: RecipeContext): Promise<RecipeOutcome> {
  const files = currentFilesWalk(context.appRoot);
  mkdirSync(context.rawDir, { recursive: true });
  const reportPath = join(context.rawDir, 'gitleaks-files.json');
  const args = [
    'dir',
    context.appRoot,
    '--report-format', 'json',
    '--report-path', reportPath,
    '--no-banner',
    '--redact',
    '--exit-code', '0',
    '--config', join(context.policyRoot, 'ci', 'configs', 'gitleaks-dir.toml'),
  ];

  // A-01/PR-02: gitleaks runs its own `git` inside the audited tree; inject the hardened config
  // through the environment so the child's Git cannot execute repository-configured helpers.
  const run = await runTool('gitleaks', args, { cwd: context.appRoot, timeoutMs: 600_000, env: { ...gitConfigEnv() } });
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

  const parsed = parseGitleaksReport(raw, {
    stderr: run.outcome.stderr,
    intendedScope: files.slice(0, MAX_FILES_RECORDED),
    // Dir mode was pointed at an absolute root, so gitleaks reports absolute paths; the adapter
    // relativizes them before ids and locations are minted (F-01/F-15).
    appRoot: context.appRoot,
  });
  if ('error' in parsed) return errored(`${parsed.error}; the raw report digest is ${digestOf(raw).slice(0, 12)}…`);

  // Classification (F-02), same boundary as the git scans: the matched text is read from the
  // current file, never from the redacted report, and only the digest is recorded.
  const annotated = annotateSecretFindings(parsed.findings, (finding) => {
    const parts = splitLocation(finding.location);
    if (parts === undefined) return undefined;
    try {
      return lineAt(readFileSync(join(context.appRoot, parts.file), 'utf8'), finding.location);
    } catch {
      return undefined;
    }
  });

  // Exposure grading (owner decisions, 13 October 2026): inside a git repository, the file's
  // relation to git decides the grade. Tracked files keep the classifier's grade (the content is
  // in the repository). Untracked files are graded down, but by how far the next `git add` is:
  // gitignored files are a local-file risk (medium — git add will not pick them up), while
  // untracked files that are not gitignored will be committed by the next `git add -A` and are
  // graded high. A target with no git at all is never graded down: nothing there is tracked or
  // committed, so the tree is the whole truth and the classifier's grade stands. When git cannot
  // answer, nothing is graded down — the safe direction is to keep the severity.
  const isGitWorktree = worktreeRoot(context.appRoot) !== undefined;
  const trackedListing = isGitWorktree ? gitOutput(context.appRoot, ['ls-files']) : undefined;
  const tracked = trackedListing === undefined
    ? undefined
    : new Set(trackedListing.split('\n').map((line) => line.trim()).filter((line) => line.length > 0));
  let graded = annotated;
  if (tracked !== undefined) {
    const untrackedFiles = [...new Set(annotated.flatMap((finding) => {
      const parts = splitLocation(finding.location);
      if (parts === undefined || tracked.has(parts.file)) return [];
      return [parts.file];
    }))];
    // One batched check-ignore: the paths it echoes are the ignored ones. An empty answer (exit 1
    // or an error) means none of the given paths is ignored, and those files grade high — the
    // conservative direction when git cannot say.
    const ignoredListing = untrackedFiles.length === 0 ? '' : gitOutput(context.appRoot, ['check-ignore', '--', ...untrackedFiles]) ?? '';
    const ignored = new Set(ignoredListing.split('\n').map((line) => line.trim()).filter((line) => line.length > 0));
    graded = annotated.map((finding) => {
      const parts = splitLocation(finding.location);
      if (parts === undefined || tracked.has(parts.file)) return finding;
      return ignored.has(parts.file) ? gradeIgnoredFileFinding(finding) : gradeUntrackedFinding(finding);
    });
  }

  return {
    outcome: 'pass',
    coverage: parsed.coverage,
    observed: files.length,
    files: files.slice(0, MAX_FILES_RECORDED),
    findings: graded,
    tool: toolIdentity('gitleaks'),
    reportPath,
    reportDigest: digestOf(raw),
    ...(parsed.parserErrors.length === 0 ? {} : { diagnostic: parsed.parserErrors.join('; ') }),
  };
}

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

/**
 * The Supabase migration rules (Batch F2, fix brief F-06): the six reviewed SQL rule families
 * over `supabase/migrations/*.sql`, implemented as an internal statement-shape analyser
 * (`src/security/migrations.ts`) so no SQL parser dependency enters the pack. The DATA-01
 * catalogue entry declared this recipe before it existed; it reports `unsupported` until now.
 */
const runMigrationInventory = (context: RecipeContext): Promise<RecipeOutcome> => {
  const result = analyzeMigrations(context.appRoot);
  return Promise.resolve(qualityOutcome('migration-inventory', result.findings, result.filesRead.length,
    'statement-shape rules over supabase/migrations/*.sql; no SQL parser is used, and only the reviewed shapes are claimed'));
};

const runOpengrep = async (context: RecipeContext): Promise<RecipeOutcome> => {
  // Two reviewed packs run in one check: the core pack (F-01) and the detection-depth pack
  // (Batch F2 — taint and pattern rules). Findings merge; the packs are independent scans, so a
  // pack that finds nothing does not mask the other's findings.
  const core = await runOpengrepWithPack(context, 'hardening-core.yaml', 'security');
  const depth = await runOpengrepWithPack(context, 'detection-depth.yaml', 'security');
  // A pack that is unsupported (no files to analyse at all) is fine as long as the other ran;
  // the combined result is a pass when at least one pack scanned files.
  const passes = [core, depth].filter((outcome) => outcome.outcome === 'pass');
  if (passes.length === 0) return core.outcome === 'error' ? core : depth;
  const mergedFindings = passes.flatMap((outcome) => outcome.findings ?? []);
  const observed = Math.max(...passes.map((outcome) => outcome.observed ?? 0));
  const files = [...new Set(passes.flatMap((outcome) => outcome.files ?? []))];
  const diagnostics = [core, depth]
    .map((outcome) => (outcome.outcome === 'pass' ? outcome.diagnostic : outcome.diagnostic))
    .filter((note): note is string => note !== undefined && note.length > 0);
  return {
    outcome: 'pass',
    coverage: passes.some((outcome) => outcome.coverage === 'partial') ? 'partial' : 'complete',
    observed,
    files: files.slice(0, MAX_FILES_RECORDED),
    findings: mergedFindings,
    tool: { ...toolIdentity('opengrep'), rule_pack: 'ci/configs/opengrep-rules/{hardening-core,detection-depth}.yaml' },
    ...(diagnostics.length === 0 ? {} : { diagnostic: diagnostics.join('; ') }),
  };
};

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

  const run = await runTool('zizmor', ['--format', 'json', '--no-progress', '--persona', 'auditor', workflowsDir], { cwd: root, timeoutMs: 120_000 });
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
  'gitleaks/files': runGitleaksDir,
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
  'data/migration-inventory': runMigrationInventory,
  'quality/dependency-health': runDependencyHealth,
};

export const IMPLEMENTED_RECIPES: readonly string[] = Object.keys(RECIPES);
