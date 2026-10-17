import { readBoundedSync } from '../evidence/bounded-io.js';
import { relative } from 'node:path';
import { walk, type WalkedFile } from '../audit/detect.js';

/**
 * Shared scanning primitives for the SecHard-owned quality analysers.
 *
 * Scope rules, stated rather than implied:
 *
 * - The same bounded walk and skip set as stack detection (node_modules, .git, build output), plus
 *   the deliberately vulnerable fixture and corpus directories, which contain synthetic findings on
 *   purpose — the same reviewed exclusion the gitleaks product config makes, for the same reason:
 *   a fixture's planted findings are not live findings, and nobody can act on them.
 * - Only source-like files are read; each analyser states what it looked at and what it skipped in
 *   its own findings' coverage, so "zero findings" always means "zero findings in what was read".
 */

export const QUALITY_SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.output', '.turbo', '.cache',
  'vendor', '__pycache__', '.venv', 'venv', 'target', 'Pods', '.dart_tool',
  'fixtures', 'corpus', '__snapshots__',
]);

export interface ScannedFile {
  readonly path: string;
  readonly relative: string;
  readonly text: string;
}

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mts', '.mjs', '.cjs', '.py']);

export function isTestFile(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  return lower.includes('.test.') || lower.includes('.spec.') || /(^|\/)(_test|test_)\w*\.py$/.test(lower) || lower.includes('/tests/') || lower.includes('/e2e/');
}

export function scanSourceFiles(root: string, limit = 1200): ScannedFile[] {
  const files: ScannedFile[] = [];
  const walked: WalkedFile[] = [];
  // walk() already skips node_modules and friends; the quality skips are filtered here so the
  // exclusion set stays visible in this module.
  for (const file of walk(root)) {
    const rel = relative(root, file.path) || file.path;
    const segments = rel.split('/');
    if (segments.some((segment) => QUALITY_SKIP_DIRS.has(segment))) continue;
    const extension = /\.[a-z0-9]+$/u.exec(file.path)?.[0] ?? '';
    if (!SOURCE_EXTENSIONS.has(extension)) continue;
    if (isTestFile(rel) && rel.includes('/fixtures/')) continue;
    walked.push(file);
  }
  for (const file of walked.slice(0, limit)) {
    try {
      const text = readFileSyncText(file.path);
      if (text !== undefined) files.push({ path: file.path, relative: relative(root, file.path) || file.path, text });
    } catch {
      // Unreadable files are skipped; the coverage note states how many files were read.
    }
  }
  return files;
}

function readFileSyncText(file: string, limitBytes = 512 * 1024): string | undefined {
  // P1.3: bounded at open time; unreadable inputs are skipped, not loaded whole.
  return readBoundedSync(file, limitBytes);
}

export interface CommentLine {
  readonly line: number;
  readonly text: string;
}

/**
 * Extracts `//` and `#` comments with their line numbers, skipping strings heuristically. This is
 * deliberately simple: the analysers judge comment *text*, and a `//` inside a string literal is
 * rare enough in practice that the corpus calibration covers it — and every rule is a signal with
 * an explanation, never a verdict.
 */
export function commentLines(text: string): CommentLine[] {
  const comments: CommentLine[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const marker of ['//', '#']) {
      let position = line.indexOf(marker);
      // `//` starts a comment anywhere (after the string-literal check). `#` starts one only at the
      // start of a line or after whitespace — mid-word `#` in JavaScript is an identifier or a
      // private field, and `#b00020` after a colon is a CSS colour, not a comment. These shapes
      // were real false positives in this repository's own self-audit.
      if (marker === '#') {
        position = -1;
        for (const match of line.matchAll(/#/g)) {
          const at = match.index ?? 0;
          if (at > 0 && !/\s/.test(line[at - 1] ?? '')) continue;
          if (/^\s*#\s*[0-9a-fA-F]{3,8}\b/.test(line.slice(at))) continue;
          position = at;
          break;
        }
        if (position === -1) continue;
      }
      if (position === -1) continue;
      const before = line.slice(0, position);
      // A quote before the comment marker suggests the marker is inside a string literal.
      const quotes = (before.match(/["'`]/g) ?? []).length;
      if (quotes % 2 === 1) continue;
      const content = line.slice(position + marker.length).trim();
      if (content.length > 0) comments.push({ line: index + 1, text: content });
      return;
    }
  });
  return comments;
}

/** Words of 4+ characters that look like identifiers, for the narration rule's shared-vocabulary test. */
export function identifiersOf(text: string): Set<string> {
  return new Set((text.match(/[A-Za-z_][A-Za-z0-9_]{3,}/g) ?? []).map((word) => word.toLowerCase()));
}
