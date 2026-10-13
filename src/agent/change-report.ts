import { packageRoot } from '../validation/schema.js';
import { diffSafetyArgs } from '../execution/git-hardening.js';
import { loadReviewManifest, reviewEntryFor, runGit, type GitRunner } from './review-manifest.js';

/**
 * The security-test change report.
 *
 * Purpose: make a weakening change visible so a human reviews it. This is a reporting tool, not a
 * judge. It cannot tell whether a deleted assertion was wrong or inconvenient, and it does not try:
 * an AST heuristic claiming to prove intent would be a false assurance. What it can do is notice the
 * mechanical facts — a test file removed, a case skipped, an assertion deleted, an exclusion added —
 * and require that each one is explained.
 *
 * A clean report is not approval. A report with findings is not proof of wrongdoing.
 */

export interface ChangeFinding {
  readonly kind:
    | 'deleted_test_file'
    | 'removed_test_case'
    | 'added_skip'
    | 'removed_assertion'
    | 'added_mock'
    | 'scan_scope_change'
    | 'security_sensitive_path_change';
  readonly path: string;
  readonly detail: string;
  readonly count?: number;
  readonly requiresReview: true;
}

export interface ChangeReport {
  readonly base: string;
  readonly head: string;
  readonly filesChanged: number;
  readonly findings: readonly ChangeFinding[];
  readonly requiresReview: boolean;
  readonly limitations: readonly string[];
}

export interface ChangeReportOptions {
  readonly cwd?: string;
  readonly base: string;
  readonly head?: string;
  readonly runGitImpl?: GitRunner;
  readonly maxDiffBytes?: number;
}

const TEST_PATH = /^tests\//;
const ASSERTION_REMOVED = /^-\s*.*\bexpect\s*\(/;
const ASSERTION_ADDED = /^\+\s*.*\bexpect\s*\(/;
const TEST_CASE_REMOVED = /^-\s*(?:it|test|describe)\s*\(/;
const TEST_CASE_ADDED = /^\+\s*(?:it|test|describe)\s*\(/;
const SKIP_ADDED = /^\+\s*.*\b(?:it|test|describe)\s*\.\s*(?:skip|todo|only)\b/;
// Matches mock-shaped introductions including helper names like `mockDatabase`: the report is a
// prompt for a human, so a false positive costs a glance while a false negative hides a mock.
const MOCK_ADDED = /^\+\s*.*(?:mock|spyOn|vi\.fn|jest\.fn)/;

export function buildChangeReport(options: ChangeReportOptions): ChangeReport {
  const cwd = options.cwd ?? packageRoot();
  const head = options.head ?? 'HEAD';
  const run = options.runGitImpl ?? runGit;
  const findings: ChangeFinding[] = [];

  const nameStatus = run(cwd, ['diff', ...diffSafetyArgs(), '--name-status', `${options.base}...${head}`]);
  if (nameStatus === undefined) {
    return {
      base: options.base,
      head,
      filesChanged: 0,
      findings: [],
      requiresReview: false,
      limitations: ['git could not be run, or one of the revisions does not exist; no change information is available'],
    };
  }

  const manifest = loadReviewManifest();
  const changed = nameStatus
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      const [status, ...rest] = line.split(/\s+/);
      return { status: status ?? '', path: rest.join(' ') };
    });

  for (const file of changed) {
    const entry = reviewEntryFor(manifest, file.path);
    if (entry !== undefined && entry.consumer !== true) {
      findings.push({
        kind: 'security_sensitive_path_change',
        path: file.path,
        detail: `matches review manifest entry '${entry.id}' (${entry.control}); a human must review this change`,
        requiresReview: true,
      });
    }
  }

  const diff = run(cwd, ['diff', ...diffSafetyArgs(), '--unified=0', `${options.base}...${head}`, '--', 'tests']) ?? '';
  const capped = diff.slice(0, options.maxDiffBytes ?? 2_000_000);
  if (capped.length < diff.length) {
    findings.push({
      kind: 'scan_scope_change',
      path: 'tests/',
      detail: `the test diff exceeded the analysis limit and was truncated at ${capped.length} characters; this report is incomplete`,
      requiresReview: true,
    });
  }

  let currentPath = '';
  let removedAssertions = 0;
  let removedCases = 0;
  let addedCases = 0;
  let addedSkips = 0;
  let addedMocks = 0;

  const flush = (): void => {
    if (currentPath === '') return;
    if (removedCases > 0) {
      findings.push({
        kind: 'removed_test_case',
        path: currentPath,
        detail: `${removedCases} test case(s) removed${addedCases === 0 ? ' with none added back' : ` (${addedCases} added)`}`,
        count: removedCases,
        requiresReview: true,
      });
    }
    if (removedAssertions > 0) {
      findings.push({
        kind: 'removed_assertion',
        path: currentPath,
        detail: `${removedAssertions} assertion line(s) removed`,
        count: removedAssertions,
        requiresReview: true,
      });
    }
    if (addedSkips > 0) {
      findings.push({
        kind: 'added_skip',
        path: currentPath,
        detail: `${addedSkips} skipped or focused test(s) added`,
        count: addedSkips,
        requiresReview: true,
      });
    }
    if (addedMocks > 0) {
      findings.push({
        kind: 'added_mock',
        path: currentPath,
        detail: `${addedMocks} mock or spy line(s) added; a mock can hide a failure`,
        count: addedMocks,
        requiresReview: true,
      });
    }
  };

  for (const line of capped.split('\n')) {
    if (line.startsWith('diff --git')) {
      flush();
      currentPath = line.replace(/^diff --git a\/\S+ b\//, '').trim();
      removedAssertions = 0;
      removedCases = 0;
      addedCases = 0;
      addedSkips = 0;
      addedMocks = 0;
      continue;
    }
    if (ASSERTION_REMOVED.test(line)) removedAssertions += 1;
    if (TEST_CASE_REMOVED.test(line)) removedCases += 1;
    if (TEST_CASE_ADDED.test(line)) addedCases += 1;
    if (SKIP_ADDED.test(line)) addedSkips += 1;
    if (MOCK_ADDED.test(line)) addedMocks += 1;
  }
  flush();

  for (const file of changed) {
    if (file.status.startsWith('D') && TEST_PATH.test(file.path)) {
      findings.push({
        kind: 'deleted_test_file',
        path: file.path,
        detail: 'a test file was deleted; deletion removes its cases with it',
        requiresReview: true,
      });
    }
  }

  // Assertions added back do not cancel removals: only one of them can be judged by reading the code.
  const assertionsAdded = (diff.match(new RegExp(ASSERTION_ADDED.source, 'gm')) ?? []).length;
  const limitations = [
    'This report notices mechanical changes. It cannot tell whether a removed assertion was wrong or inconvenient.',
    'Reformatted or moved tests appear as removals and additions and must be read, not counted.',
    assertionsAdded > 0
      ? `${assertionsAdded} assertion line(s) were added in the same range; a net count would hide a real removal.`
      : 'No assertion lines were added in this range.',
  ];

  return {
    base: options.base,
    head,
    filesChanged: changed.length,
    findings,
    requiresReview: findings.length > 0,
    limitations,
  };
}

export function formatChangeReport(report: ChangeReport): string {
  const lines = [
    `Security-test change report: ${report.base}...${report.head}`,
    `${report.filesChanged} file(s) changed. Review required: ${report.requiresReview ? 'yes' : 'no findings'}`,
    '',
  ];
  if (report.findings.length === 0) {
    lines.push('No deletions, skips, weakened assertions, or sensitive-path changes were detected.', '');
  } else {
    for (const finding of report.findings) {
      lines.push(`- [${finding.kind}] ${finding.path}: ${finding.detail}`);
    }
    lines.push('');
  }
  lines.push('Limitations:');
  for (const limitation of report.limitations) lines.push(`- ${limitation}`);
  return lines.join('\n');
}
