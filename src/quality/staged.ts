import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { runProcess } from '../execution/process.js';
import { extractVersion } from '../execution/version.js';
import type { Finding } from '../domain/types.js';
import { scanSourceFiles } from './common.js';
import { packageRoot } from '../validation/schema.js';

/**
 * The four staged quality analysers (P4.2 — F-07): jscpd (duplication, QUAL-03), Lizard
 * (complexity, QUAL-04), Knip (dead code, QUAL-05) and dependency-cruiser (module structure,
 * QUAL-06), run for real against the audited application with SecHard-owned configurations
 * (`ci/configs/quality/`) — the target's own configuration is never loaded, imported or executed.
 *
 * The tools live in the isolated package `tools/quality/`: its committed lockfile pins the
 * reviewed exact versions, and the audit uses the absolute executables from that package — no
 * npx, no target PATH, no global install, no install into the audited project. Lizard runs from
 * the private virtual environment `tools/quality/venv`. A missing tool, a crash, or an
 * unparseable report is an explicit failure, never an empty success (plan item 6).
 */

export interface StagedTool {
  readonly executable: string;
  readonly version: string;
}

const QUALITY_PACKAGE = join(packageRoot(), 'tools', 'quality');

const NPM_TOOLS: Readonly<Record<'jscpd' | 'knip' | 'dependency-cruiser' | 'tsc' | 'biome', string>> = {
  jscpd: 'jscpd',
  knip: 'knip',
  'dependency-cruiser': 'dependency-cruiser',
  tsc: 'typescript',
  biome: '@biomejs/biome',
};

const VENV_TOOLS: Readonly<Record<'lizard' | 'ruff', string>> = { lizard: 'lizard', ruff: 'ruff' };

/** Resolves a staged tool's absolute executable and its installed version. */
export async function resolveStagedTool(kind: keyof typeof NPM_TOOLS | keyof typeof VENV_TOOLS): Promise<StagedTool | { readonly unavailable: string }> {
  if (kind in VENV_TOOLS) {
    const venvKind = kind as keyof typeof VENV_TOOLS;
    const executable = join(QUALITY_PACKAGE, 'venv', 'bin', VENV_TOOLS[venvKind]);
    if (!existsSync(executable)) {
      return { unavailable: `${kind} is not provisioned (${executable} is absent); provision the reviewed quality tools before running this check — provisioning is separate from checking and never runs inside an audit` };
    }
    const run = await runProcess({ executable, args: ['--version'], cwd: packageRoot(), timeoutMs: 30_000, maxOutputBytes: 64 * 1024 });
    const version = extractVersion(`${run.stdout ?? ''}\n${run.stderr ?? ''}`);
    if (run.exitCode !== 0 || version === undefined) {
      return { unavailable: `${kind} is provisioned but its version could not be established` };
    }
    return { executable, version };
  }
  const npmKind = kind as keyof typeof NPM_TOOLS;
  const manifest = join(QUALITY_PACKAGE, 'node_modules', NPM_TOOLS[npmKind], 'package.json');
  const executable = join(QUALITY_PACKAGE, 'node_modules', '.bin', npmKind === 'dependency-cruiser' ? 'depcruise' : npmKind);
  if (!existsSync(executable) || !existsSync(manifest)) {
    return { unavailable: `${kind} is not provisioned (${executable} is absent); provision the reviewed quality tools before running this check — provisioning is separate from checking and never runs inside an audit` };
  }
  try {
    const version = (JSON.parse(readFileSync(manifest, 'utf8')) as { version?: string }).version;
    if (version === undefined) return { unavailable: `${kind} is provisioned but its recorded version could not be read` };
    return { executable, version };
  } catch {
    return { unavailable: `${kind} is provisioned but its recorded version could not be read` };
  }
}

export interface StagedAnalysis {
  readonly findings: Finding[];
  readonly observed: number;
  readonly notes: readonly string[];
}

/** A tool that cannot apply to this application (no applicable sources, no package manifest). */
export interface StagedUnsupported {
  readonly unsupported: string;
}

type StagedOutcome = StagedAnalysis | { readonly failed: string } | StagedUnsupported;

function finding(id: string, ruleId: string, severity: Finding['severity'], title: string, detail: string, location: string, controls: readonly string[]): Finding {
  return {
    id,
    tool: 'quality-staged',
    rule_id: ruleId,
    severity,
    title,
    detail,
    location,
    control_ids: controls,
    triage: 'unresolved',
  };
}

/** jscpd's own report files, written to a private temporary directory and removed after parsing. */
interface JscpdReport {
  readonly duplicates?: readonly {
    readonly firstFile?: { readonly name?: string; readonly start?: number; readonly end?: number };
    readonly secondFile?: { readonly name?: string; readonly start?: number; readonly end?: number };
    readonly lines?: number;
    readonly tokens?: number;
  }[];
  readonly statistics?: { readonly total?: { readonly sources?: number; readonly duplicatedLines?: number; readonly percentage?: number } };
}

const DUPLICATION_CONFIG = join(packageRoot(), 'ci', 'configs', 'quality', 'jscpd.json');

/**
 * QUAL-03: token-level clone detection over the application's TypeScript and JavaScript sources.
 * A clone pair is one finding naming both sites; the scanned scope and duplication percentage are
 * recorded in the result notes. The min-tokens threshold is calibrated on the corpus seed (the
 * formatPrice/legacyFormatter pair) and this repository's own self-audit.
 */
export async function analyzeDuplication(appRoot: string, tool: StagedTool): Promise<StagedOutcome> {
  const sources = scanSourceFiles(appRoot);
  if (sources.length === 0) {
    return { unsupported: 'no JavaScript/TypeScript source files to scan for duplication in this application' };
  }
  const outDir = mkdtempSync(join(tmpdir(), 'hardening-jscpd-'));
  try {
    const run = await runProcess({
      executable: tool.executable,
      args: [appRoot, '-c', DUPLICATION_CONFIG, '--reporters', 'json', '--output', outDir, '--silent'],
      cwd: appRoot,
      timeoutMs: 600_000,
      maxOutputBytes: 16 * 1024 * 1024,
    });
    if (run.exitCode !== 0) {
      return { failed: `jscpd exited ${String(run.exitCode)}: ${(run.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
    }
    const reportPath = join(outDir, 'dup-report.json');
    if (!existsSync(reportPath)) return { failed: 'jscpd produced no duplication report' };
    const report = JSON.parse(readFileSync(reportPath, 'utf8')) as JscpdReport;
    const findings: Finding[] = [];
    for (const clone of report.duplicates ?? []) {
      const first = clone.firstFile?.name ?? '(unknown)';
      const second = clone.secondFile?.name ?? '(unknown)';
      const firstLine = clone.firstFile?.start ?? 0;
      const secondLine = clone.secondFile?.start ?? 0;
      const lines = clone.lines ?? 0;
      const digest = createHash('sha256').update(`${first}:${String(firstLine)}:${second}:${String(secondLine)}:${String(clone.tokens ?? 0)}`).digest('hex').slice(0, 12);
      findings.push(finding(
        `quality-duplication:clone:${digest}`,
        'jscpd-clone',
        'low',
        `A ${String(lines)}-line code clone appears at two sites (${first}:${String(firstLine)} and ${second}:${String(secondLine)}).`,
        `The same ${String(lines)}-line block (about ${String(clone.tokens ?? 0)} tokens) exists at ${first}:${String(firstLine)}-${String(clone.firstFile?.end ?? '?')} and ${second}:${String(secondLine)}-${String(clone.secondFile?.end ?? '?')}. Extract the shared logic into one function and call it from both sites.`,
        `${first}:${String(firstLine)}`,
        ['QUAL-03'],
      ));
    }
    const sources = report.statistics?.total?.sources ?? 0;
    const percentage = report.statistics?.total?.percentage ?? 0;
    return {
      findings,
      observed: sources,
      notes: [`scanned ${String(sources)} source file(s); ${String(percentage)}% duplicated lines`],
    };
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

/** Lizard's per-function CSV row: the quoted fields may contain commas (the signature). */
const LIZARD_ROW = /^(\d+),(\d+),(\d+),(\d+),(\d+),"([^"]*)","([^"]*)","([^"]*)","(.*)",(\d+),(\d+)$/;

/** The reviewed complexity thresholds, calibrated on the corpus and this repository's own audit. */
const COMPLEXITY = { cyclomatic: 10, length: 50, parameters: 5 };

/**
 * QUAL-04: per-function complexity from Lizard — cyclomatic complexity, function length and
 * parameter count against reviewed thresholds. A file-line count alone is not complexity and is
 * never reported as such.
 */
export async function analyzeComplexity(appRoot: string, tool: StagedTool): Promise<StagedOutcome> {
  // Lizard's own directory walk maps .ts but not .tsx, so the analyser names every source file
  // explicitly (bounded by the shared scan walk) — the direct-file invocation parses both.
  const files = scanSourceFiles(appRoot);
  if (files.length === 0) {
    return { unsupported: 'no JavaScript/TypeScript source files to analyse for complexity in this application' };
  }
  const run = await runProcess({
    executable: tool.executable,
    args: ['-l', 'javascript', '-l', 'typescript', '--csv', ...files.map((file) => file.path)],
    cwd: appRoot,
    timeoutMs: 600_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });
  if (run.exitCode !== 0) {
    return { failed: `lizard exited ${String(run.exitCode)}: ${(run.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
  }
  const findings: Finding[] = [];
  let functions = 0;
  for (const line of (run.stdout ?? '').split(/\r?\n/)) {
    const row = LIZARD_ROW.exec(line.trim());
    if (row === null) continue;
    functions += 1;
    const nloc = Number(row[1]);
    const ccn = Number(row[2]);
    const params = Number(row[4]);
    const length = Number(row[5]);
    const label = row[6] ?? '';
    // With explicit file arguments lizard records absolute paths; report them app-relative.
    const rawFile = row[7] ?? '';
    const file = rawFile.startsWith('/') ? relative(appRoot, rawFile) : rawFile;
    const name = row[8] ?? '';
    // Columns 10 and 11 are the function's start and end lines; column 9 is the signature.
    const startLine = row[10] ?? '0';
    if (ccn >= COMPLEXITY.cyclomatic) {
      findings.push(finding(
        `quality-complexity:ccn:${file}:${startLine}:${name}`,
        'lizard-cyclomatic-complexity',
        'low',
        `Function ${name} has a cyclomatic complexity of ${String(ccn)}, at or above the reviewed threshold of ${String(COMPLEXITY.cyclomatic)}.`,
        `High cyclomatic complexity in ${file}:${startLine} makes the function hard to test and easy to get wrong. Split the branches into smaller named functions.`,
        `${file}:${startLine}`,
        ['QUAL-04'],
      ));
    }
    if (length > COMPLEXITY.length) {
      findings.push(finding(
        `quality-complexity:length:${file}:${startLine}:${name}`,
        'lizard-function-length',
        'low',
        `Function ${name} is ${String(length)} lines long (threshold ${String(COMPLEXITY.length)}).`,
        `Long functions in ${file}:${startLine} hide their structure. Extract coherent blocks into named helpers.`,
        `${file}:${startLine}`,
        ['QUAL-04'],
      ));
    }
    if (params > COMPLEXITY.parameters) {
      findings.push(finding(
        `quality-complexity:params:${file}:${startLine}:${name}`,
        'lizard-parameter-count',
        'low',
        `Function ${name} takes ${String(params)} parameters (threshold ${String(COMPLEXITY.parameters)}).`,
        `Too many parameters in ${file}:${startLine} usually means a missing object or options type. Group them.`,
        `${file}:${startLine}`,
        ['QUAL-04'],
      ));
    }
    void nloc;
    void label;
  }
  return { findings, observed: functions, notes: [`${String(functions)} function(s) analysed against the reviewed thresholds`] };
}

interface KnipReport {
  readonly issues?: readonly {
    readonly file?: string;
    readonly dependencies?: readonly { readonly name?: string }[];
    readonly devDependencies?: readonly { readonly name?: string }[];
    readonly exports?: readonly { readonly name?: string; readonly line?: number }[];
    readonly files?: readonly { readonly name?: string }[];
  }[];
}

const DEAD_CODE_CONFIG = join(packageRoot(), 'ci', 'configs', 'quality', 'knip.json');

/**
 * QUAL-05: reference-aware dead-code detection from Knip — unused files, unused exports and
 * unused dependencies, with the entry points declared in SecHard's own configuration. Every
 * config-loading Knip plugin is disabled in that configuration: the target's own tool
 * configuration is data here, never code (no jiti import of a target JS/TS config).
 */
export async function analyzeDeadCode(appRoot: string, tool: StagedTool): Promise<StagedOutcome> {
  if (!existsSync(join(appRoot, 'package.json'))) {
    return { unsupported: 'the application has no package.json; Knip analyses JavaScript/TypeScript projects — the Python dead-code route (Vulture) is a recorded gap' };
  }
  const run = await runProcess({
    executable: tool.executable,
    args: ['--config', DEAD_CODE_CONFIG, '--reporter', 'json', '--no-exit-code'],
    cwd: appRoot,
    timeoutMs: 600_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });
  if (run.exitCode !== 0) {
    return { failed: `knip exited ${String(run.exitCode)}: ${(run.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
  }
  const report = JSON.parse(run.stdout ?? '{}') as KnipReport;
  const findings: Finding[] = [];
  let observed = 0;
  for (const issue of report.issues ?? []) {
    observed += 1;
    const file = issue.file ?? '';
    for (const entry of issue.files ?? []) {
      if (entry.name === undefined) continue;
      findings.push(finding(
        `quality-dead-code:file:${entry.name}`,
        'knip-unused-file',
        'low',
        `A source file is never imported: ${entry.name}.`,
        `Nothing reachable imports ${entry.name}, so none of its exports can ever run. Delete it, or wire it into an entry point.`,
        entry.name,
        ['QUAL-05'],
      ));
    }
    for (const entry of issue.exports ?? []) {
      if (entry.name === undefined) continue;
      findings.push(finding(
        `quality-dead-code:export:${file}:${entry.name}`,
        'knip-unused-export',
        'low',
        `An export is never imported: ${entry.name} in ${file}.`,
        `The export ${entry.name} in ${file} has no importer in the module graph. Remove it, or export it from a declared entry point.`,
        `${file}:${String(entry.line ?? 1)}`,
        ['QUAL-05'],
      ));
    }
    for (const entry of [...(issue.dependencies ?? []), ...(issue.devDependencies ?? [])]) {
      if (entry.name === undefined) continue;
      findings.push(finding(
        `quality-dead-code:dependency:${entry.name}`,
        'knip-unused-dependency',
        'low',
        `A declared dependency is never imported: ${entry.name}.`,
        `package.json declares ${entry.name}, but no source file imports it. Remove the dependency, or import it where it is meant to be used.`,
        'package.json',
        ['QUAL-05'],
      ));
    }
  }
  return { findings, observed, notes: [`${String(observed)} file(s) with dead-code findings`] };
}

interface BiomeReport {
  readonly diagnostics?: readonly {
    readonly category?: string;
    /** Biome v2 reports the file path as a plain string, relative to the working directory. */
    readonly location?: { readonly path?: string };
  }[];
}

const FORMATTING_CONFIG = join(packageRoot(), 'ci', 'configs', 'quality', 'biome.json');

/**
 * QUAL-10: formatting consistency from Biome (JS/TS) and Ruff format (Python), both check-only
 * with SecHard's own configurations — the target's own biome/ruff configuration is never loaded
 * (`--config-path` points at SecHard's reviewed config; the target's biome.json is never
 * discovered), and neither tool writes (plan item 3). Naming-consistency signals stay in the
 * vibe-tells analyser; this recipe measures formatting only.
 */
export async function analyzeFormatting(appRoot: string, biome: StagedTool, ruff: StagedTool): Promise<StagedOutcome> {
  const files = scanSourceFiles(appRoot);
  if (files.length === 0) {
    return { unsupported: 'no source files to check for formatting in this application' };
  }
  const findings: Finding[] = [];
  const notes: string[] = [];

  const biomeRun = await runProcess({
    executable: biome.executable,
    args: ['check', '--config-path=' + FORMATTING_CONFIG, '--reporter', 'json', appRoot],
    cwd: appRoot,
    timeoutMs: 600_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });
  if (biomeRun.exitCode !== 0 && biomeRun.exitCode !== 1) {
    return { failed: `biome exited ${String(biomeRun.exitCode)}: ${(biomeRun.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
  }
  // Biome exits 1 when diagnostics were found (the expected finding case); 2+ is a crash.
  try {
    const report = JSON.parse(biomeRun.stdout ?? '{}') as BiomeReport;
    let formatDiagnostics = 0;
    for (const diagnostic of report.diagnostics ?? []) {
      const category = diagnostic.category ?? '';
      if (!category.startsWith('format')) continue; // the linter is disabled in the reviewed config
      formatDiagnostics += 1;
      const path = (diagnostic.location?.path ?? '').replace(/\\/g, '/');
      const rel = path.startsWith('/') ? relative(appRoot, path) : path;
      findings.push(finding(
        `quality-formatting:biome:${createHash('sha256').update(rel).digest('hex').slice(0, 12)}:${String(formatDiagnostics)}`,
        'biome-format',
        'low',
        `A formatting difference is detected in ${rel}.`,
        'The file does not match SecHard\u2019s reviewed formatting configuration. Run the formatter in a separate approved step; this check only measures and never writes.',
        rel,
        ['QUAL-10'],
      ));
    }
    notes.push(`biome ${biome.version}: ${String(formatDiagnostics)} formatting diagnostic(s) over ${String(files.length)} source file(s)`);
  } catch {
    return { failed: 'biome produced an unparseable JSON report' };
  }

  const pyFiles = files.filter((file) => file.path.endsWith('.py'));
  if (pyFiles.length === 0) {
    notes.push('no Python sources — the Ruff format route was not applicable');
    return { findings, observed: files.length, notes };
  }
  const ruffRun = await runProcess({
    executable: ruff.executable,
    args: ['format', '--check', '--config', join(packageRoot(), 'ci', 'configs', 'quality', 'ruff.toml'), appRoot],
    cwd: appRoot,
    timeoutMs: 600_000,
    maxOutputBytes: 8 * 1024 * 1024,
  });
  if (ruffRun.exitCode !== 0 && ruffRun.exitCode !== 1) {
    return { failed: `ruff exited ${String(ruffRun.exitCode)}: ${(ruffRun.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
  }
  // Ruff exits 1 when files would be reformatted (the expected finding case); 2+ is a crash.
  // Ruff 0.17 reports each unformatted file as a diagnostic whose location line is
  // `--> <path>:<line>:<col>` — the older "Would reformat:" summary line is gone.
  let ruffFindings = 0;
  for (const line of (ruffRun.stdout ?? '').split(/\r?\n/)) {
    const match = /^-->\s+(.+):(\d+):\d+$/.exec(line.trim());
    if (match === null) continue;
    const path = match[1] ?? '';
    const rel = path.startsWith('/') ? relative(appRoot, path) : path;
    ruffFindings += 1;
    findings.push(finding(
      `quality-formatting:ruff:${createHash('sha256').update(rel).digest('hex').slice(0, 12)}`,
      'ruff-format',
      'low',
      `A Python file does not match the reviewed format: ${rel}.`,
      'The file would be reformatted by the reviewed Ruff configuration. Run the formatter in a separate approved step; this check only measures and never writes.',
      rel,
      ['QUAL-10'],
    ));
  }
  notes.push(`ruff ${ruff.version}: ${String(ruffFindings)} Python file(s) would be reformatted (${String(pyFiles.length)} Python source(s) in scope)`);
  return { findings, observed: files.length, notes };
}

interface DepcruiseReport {
  readonly modules?: readonly unknown[];
  readonly summary?: { readonly violations?: readonly { readonly rule?: { readonly name?: string }; readonly from?: string; readonly to?: string }[] };
}

const MODULE_STRUCTURE_CONFIG = join(packageRoot(), 'ci', 'configs', 'quality', 'dependency-cruiser.json');

/**
 * QUAL-06: module-structure rules from dependency-cruiser — dependency cycles and UI →
 * database/server-only imports, with SecHard's own static rule file. The target's webpack or JS
 * configuration is never loaded; a tsconfig.json is only ever parsed as data for path resolution.
 * The rule matching runs against the raw import specifiers, so the reviewed patterns name both
 * the alias form and the relative-upward form.
 */
export async function analyzeModuleStructure(appRoot: string, tool: StagedTool): Promise<StagedOutcome> {
  const sources = scanSourceFiles(appRoot);
  if (sources.length === 0) {
    return { unsupported: 'no JavaScript/TypeScript source files to cruise in this application' };
  }
  const args = ['--config', MODULE_STRUCTURE_CONFIG, '--output-type', 'json', '**/*.{ts,tsx,js,jsx,mjs,cjs}'];
  const tsconfig = join(appRoot, 'tsconfig.json');
  if (existsSync(tsconfig)) args.push('--ts-config', tsconfig);
  const run = await runProcess({
    executable: tool.executable,
    args,
    cwd: appRoot,
    timeoutMs: 600_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });
  if (run.exitCode !== 0) {
    return { failed: `dependency-cruiser exited ${String(run.exitCode)}: ${(run.stderr ?? '').slice(-300).trim() || '(no stderr)'}` };
  }
  const report = JSON.parse(run.stdout ?? '{}') as DepcruiseReport;
  const findings: Finding[] = [];
  for (const violation of report.summary?.violations ?? []) {
    const ruleName = violation.rule?.name ?? 'unknown-rule';
    const from = violation.from ?? '';
    const to = violation.to ?? '';
    const severity = ruleName === 'no-ui-database-access' ? 'medium' : 'low';
    findings.push(finding(
      `quality-module-structure:${ruleName}:${createHash('sha256').update(`${from}->${to}`).digest('hex').slice(0, 12)}`,
      `depcruise-${ruleName}`,
      severity,
      `Module-structure rule '${ruleName}' is violated: ${from} imports ${to}.`,
      `The import from ${from} to ${to} breaks the reviewed module-structure rule '${ruleName}'. Move the shared logic to the layer both sides may import from.`,
      from,
      ['QUAL-06'],
    ));
  }
  return { findings, observed: (report.modules ?? []).length, notes: [`${String((report.modules ?? []).length)} module(s) cruised against the reviewed structure rules`] };
}
