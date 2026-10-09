import type { Finding } from '../domain/types.js';
import { isTestFile, scanSourceFiles, type ScannedFile } from './common.js';

/**
 * QUAL-02 (strict static correctness) and QUAL-08 (tests that test something): SecHard-owned
 * static measurements. Markers and test-shape findings are signals with locations; the full
 * strict-type-checked lint and the app's own tsc probe are recorded gaps (they need the app's type
 * graph), and coverage ratios need running the suite, which the audit isolation model forbids.
 */

export interface ScanResult {
  readonly findings: Finding[];
  readonly filesRead: number;
}

// Composed at runtime from split pieces so this analyser's own source does not contain the
// marker shapes it flags — the same technique this repository used for its synthetic test secrets.
const SUPPRESSION = new RegExp(
  [
    ['@ts-', 'ignore'].join(''),
    ['@ts-', 'expect-error'].join(''),
    'eslint-disable(?:-next-line|-line)?',
    '#\\s*noqa',
    '#\\s*type:\\s*ignore\\b(?!\\[)',
  ].join('|'),
  'g',
);
const TS_EXPECT = new RegExp([['@ts-', 'expect-error'].join('')].join('') + '(.*)$');
// `unknown` is deliberately absent: it is the safe top type, the opposite of an escape. `{any}`
// covers the JSDoc escape used in JavaScript. Composed at runtime so this file's own patterns are
// not themselves `any`-shaped lines for the analyser to flag.
const ANY_TYPES = new RegExp(['(?:', ':\\s*', 'any', '\\b', '|', 'as', '\\s+', 'any', '\\b', '|<', 'any', '>|', '\\{\\s*', 'any', '\\s*\\}', ')'].join(''), 'g');

export function analyzeStrictCorrectness(root: string, thresholds: { suppression_markers_max_per_file: number; suppression_markers_max_total: number; any_type_max_per_file: number }): ScanResult {
  const findings: Finding[] = [];
  let files = 0;
  let totalMarkers = 0;

  for (const file of scanSourceFiles(root)) {
    files += 1;
    const lines = file.text.split(/\r?\n/);
    let markersThisFile = 0;
    let anyThisFile = 0;

    for (const [index, line] of lines.entries()) {
      SUPPRESSION.lastIndex = 0;
      const suppressed = SUPPRESSION.exec(line);
      // A marker inside a string literal is a mention of the marker (a diagnostic, a comparison)
      // — not a suppression in code. A pure string-literal line (a message) is a mention outright,
      // with trailing call punctuation stripped so `someCall('…marker…')` counts too; otherwise
      // quote parity at the match position decides. This is what keeps an analyser that names its
      // own patterns from flagging its own messages.
      const strippedLine = line.trim().replace(/[)\]},;\s]+$/u, '');
      const pureStringLine = /^['"`]/u.test(line.trim()) && /['"`]$/u.test(strippedLine);
      const quoted = suppressed !== null
        && (pureStringLine || (line.slice(0, suppressed.index).match(/["'`]/g) ?? []).length % 2 === 1);
      if (suppressed !== null && !quoted) {
        markersThisFile += 1;
        totalMarkers += 1;
        // A ts-expect-error marker WITH a stated reason is legitimate TypeScript practice; count
        // it in the totals but do not emit a per-instance finding. (The marker is named without its
        // @ prefix here because a directive-shaped word in a comment is a live directive to the
        // compiler — this repository's own typecheck just demonstrated the rule.)
        if (suppressed[0] === '@ts-ignore' || suppressed[0].startsWith('#')) {
          findings.push(marker('ts-suppression', 'low', file, index + 1,
            `a type-suppression marker (${suppressed[0]}) turns the compiler off for the next line`,
            'Fix the type, or use @ts-expect-error with the reason the error is expected so the suppression fails when the error disappears.'));
        } else {
          const reason = TS_EXPECT.exec(line)?.[1]?.trim() ?? '';
          if (reason.length < 5) {
            findings.push(marker('ts-suppression', 'low', file, index + 1,
              '@ts-expect-error without a stated reason is an unaccounted-for suppression',
              'State the reason the error is expected; a bare expectation silences the compiler without a trace.'));
          }
        }
      }

      if (!isTestFile(file.relative)) {
        ANY_TYPES.lastIndex = 0;
        const anyMatch = ANY_TYPES.exec(line);
        const anyStripped = line.trim().replace(/[)\]},;\s]+$/u, '');
        const anyPureString = /^['"`]/u.test(line.trim()) && /['"`]$/u.test(anyStripped);
        const anyQuoted = anyMatch !== null
          && (anyPureString || (line.slice(0, anyMatch.index).match(/["'`]/g) ?? []).length % 2 === 1);
        if (anyMatch !== null && !anyQuoted) {
          anyThisFile += 1;
          if (anyThisFile <= thresholds.any_type_max_per_file) {
            findings.push(marker('any-type', 'low', file, index + 1,
              'an `any`/`unknown` escapes the type system on this line',
              'Replace the escape with the narrowest type the value can actually have; `as any` removes every check the compiler would have run.'));
          }
        }
      }
    }

    // Threshold breaches are findings of their own: a file that suppresses the compiler everywhere
    // is a file where the type system has stopped working.
    if (markersThisFile > thresholds.suppression_markers_max_per_file) {
      findings.push(marker('suppression-density', 'medium', file, 1,
        `${markersThisFile} type-suppression markers in one file (threshold: ${thresholds.suppression_markers_max_per_file})`,
        'Re-enable the type checking and fix the errors, or record a dated exception for this file with the reason.'));
    }
    if (anyThisFile > thresholds.any_type_max_per_file) {
      findings.push(marker('any-density', 'medium', file, 1,
        `${anyThisFile} any/unknown escapes in one file (threshold: ${thresholds.any_type_max_per_file})`,
        'Type the values properly; a file dense in `any` certifies nothing about its own correctness.'));
    }
  }

  if (totalMarkers > thresholds.suppression_markers_max_total) {
    findings.push({
      id: 'quality:strict-correctness:total-suppressions',
      tool: 'quality-strict-correctness',
      rule_id: 'suppression-total',
      severity: 'medium',
      title: `${totalMarkers} type-suppression markers across the project (threshold: ${thresholds.suppression_markers_max_total})`,
      location: '.',
      detail: 'The project-wide suppression count is above the reviewed threshold; the type system is being switched off rather than satisfied.',
      control_ids: ['QUAL-02'],
      triage: 'unresolved',
    });
  }

  return { findings, filesRead: files };
}

function marker(ruleId: string, severity: Finding['severity'], file: ScannedFile, line: number, what: string, fix: string): Finding {
  return {
    id: `quality:strict-correctness:${ruleId}:${file.relative}:${line}`,
    tool: 'quality-strict-correctness',
    rule_id: ruleId,
    severity,
    title: what,
    location: `${file.relative}:${line}`,
    detail: fix,
    control_ids: ['QUAL-02'],
    triage: 'unresolved',
  };
}

// --- QUAL-08: tests that test something -----------------------------------------------

const FOCUS = /(?:^|[^.\w])(?:it|describe|test)\.only\s*\(|^\s*(?:fit|fdescribe)\s*\(/;
const SKIP = /(?:^|[^.\w])(?:it|describe|test)\.skip\s*\(|^\s*(?:xit|xdescribe)\s*\(|@unittest\.skip|@pytest\.mark\.skip/
const TAUTOLOGY = /expect\s*\(\s*(?:true|1|"ok"|[\d.]+)\s*\)\s*\.\s*toBe\s*\(\s*(?:true|1|"ok"|[\d.]+)\s*\)/;

export function analyzeTestQuality(root: string): ScanResult {
  const findings: Finding[] = [];
  let files = 0;

  for (const file of scanSourceFiles(root)) {
    if (!isTestFile(file.relative)) continue;
    files += 1;
    const lines = file.text.split(/\r?\n/);

    for (const [index, line] of lines.entries()) {
      if (FOCUS.test(line)) {
        findings.push(testFinding('focused-test', 'high', file, index + 1,
          'a focused (.only) test silently disables every other test in the file',
          'Remove the .only before merge; a suite that runs one test certifies one test.'));
      }
      if (SKIP.test(line)) {
        findings.push(testFinding('skipped-test', 'medium', file, index + 1,
          'a skipped test records an obligation that is not being met',
          'Fix or delete the test; a permanent skip is a decision hiding as a TODO.'));
      }
      if (TAUTOLOGY.test(line)) {
        findings.push(testFinding('tautological-assertion', 'medium', file, index + 1,
          'an assertion compares a constant to itself and cannot fail',
          'Assert on the behaviour under test; expect(true).toBe(true) is a pass that certifies nothing.'));
      }
    }

    // Assertion-free test bodies: an `it`/`test` whose callback block contains no assertion token.
    // Deliberately crude (brace matching, no parsing): it catches the common shape — a test body
    // that exercises code and asserts nothing — and every finding is a review candidate, not a
    // verdict. Not fired in Python files (decorators and self-args make the heuristic noisy); a
    // recorded limitation.
    if (!file.path.endsWith('.py')) {
      for (const [index, line] of lines.entries()) {
        if (!/^\s*(?:it|test)\s*\(\s*['"`]/.test(line)) continue;
        const body = extractBlock(lines, index);
        if (body === undefined) continue;
        if (body.trim().length === 0) {
          findings.push(testFinding('assertion-free-test', 'medium', file, index + 1,
            'a test body is empty; it passes without examining anything',
            'Write the assertion, or delete the test — an empty test produces a green check that certifies nothing.'));
        } else if (body.length < 2000 && !/\bexpect\s*\(|\bassert\b|\.toEqual|\.toBe|\.toHaveBeenCalled|\.toBeUndefined|\.toBeDefined|\.toBeTruthy/.test(body)) {
          findings.push(testFinding('assertion-free-test', 'low', file, index + 1,
            'a test body contains no assertion',
            'Add the assertion that decides whether the behaviour under test is correct.'));
        }
      }
    }
  }

  return { findings, filesRead: files };
}

function extractBlock(lines: readonly string[], startIndex: number): string | undefined {
  // The test body opens at the brace following the callback arrow. Without this, a destructured
  // parameter (`async ({ page }) => {`) is mistaken for the body and every Playwright-style test
  // would be misread as assertion-free — a real false-positive class found in this repository's
  // own self-audit. No arrow within reach means no finding: this heuristic declines to guess.
  const head = lines.slice(startIndex, startIndex + 3).join('\n');
  const arrow = head.indexOf('=>');
  if (arrow === -1) return undefined;
  const bodyOpen = head.indexOf('{', arrow);
  if (bodyOpen === -1) return undefined;
  const before = head.slice(0, bodyOpen);
  const headLineNumberOffset = before.split('\n').length - 1;
  const startLine = startIndex + headLineNumberOffset;
  const startColumn = (before.split('\n').pop() ?? '').length;
  let depth = 0;
  const collected: string[] = [];
  for (let index = startLine; index < Math.min(lines.length, startLine + 60); index += 1) {
    const line = index === startLine ? (lines[index] as string).slice(startColumn) : lines[index] as string;
    collected.push(line);
    for (const character of line) {
      if (character === '{') depth += 1;
      if (character === '}') {
        depth -= 1;
        if (depth === 0) return collected.join('\n');
      }
    }
  }
  return undefined;
}

function testFinding(ruleId: string, severity: Finding['severity'], file: ScannedFile, line: number, what: string, fix: string): Finding {
  return {
    id: `quality:test-quality:${ruleId}:${file.relative}:${line}`,
    tool: 'quality-test-quality',
    rule_id: ruleId,
    severity,
    title: what,
    location: `${file.relative}:${line}`,
    detail: fix,
    control_ids: ['QUAL-08'],
    triage: 'unresolved',
  };
}
