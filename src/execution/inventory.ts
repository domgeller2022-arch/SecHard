import { existsSync, lstatSync, readdirSync, statSync, type Dirent } from 'node:fs';
import { join } from 'node:path';
import { readBoundedSync } from '../evidence/bounded-io.js';

/**
 * The independent relevant-file inventory (P3.1, A-09/A-10).
 *
 * Built BEFORE the scanner runs, from the application tree itself: files whose name matches the
 * reviewed pack's target extensions, excluding exactly the directories the recipe's reviewed
 * exclusion flags exclude. Expected scope is therefore never defined as whatever the scanner
 * happened to report: a scanner that silently skipped files — a target ignore file, a gitignore
 * rule, a parse refusal it does not surface — shows up as unexamined inventory instead of a clean,
 * complete scan.
 *
 * The walk follows the repository's standing conventions (P1.2/P1.3): symlinks are never followed
 * and are recorded as skipped with the reason, an unreadable directory is recorded as skipped, and
 * the entry cap turns the inventory into an explicit lower bound rather than a silent truncation.
 * Because inventoried files alone do not prove parsing occurred, the recipe compares the
 * scanner's own examined list against this inventory and refuses a complete claim when they
 * disagree.
 */

export interface FileInventory {
  /** Root-relative paths of relevant files, sorted. */
  readonly intended: readonly string[];
  /** True when the walk hit the entry cap: the inventory is a lower bound. */
  readonly truncated: boolean;
  /** Entries the walk could not include, with the reason. */
  readonly skipped: readonly { readonly path: string; readonly reason: string }[];
}

export interface SuppressionInventory {
  /** A target `.semgrepignore` exists: a target-controlled file-level suppression the tool honours. */
  readonly semgrepignore?: { readonly entries: number };
  /** Inline `nosemgrep` annotations in inventoried files: target-controlled finding-level suppressions. */
  readonly nosemgrep: { readonly files: number; readonly annotations: number };
  /** Inventoried files too large to inspect for inline suppressions within the read bound. */
  readonly uninspected: number;
}

const WALK_ENTRY_CAP = 50_000;
const SUPPRESSION_READ_BYTES = 262_144;

/**
 * Declaration files (*.d.ts) are not inventoried: they carry no runtime behaviour, the packs'
 * patterns are runtime sinks, and the tool does not scan them. Secret material in any file is
 * covered by the gitleaks recipes regardless of extension.
 */
const isDeclarationFile = (name: string): boolean => /\.d\.ts$/.test(name);

export function buildSourceInventory(
  appRoot: string,
  extensions: readonly string[],
  excludeDirs: ReadonlySet<string>,
): FileInventory {
  const intended: string[] = [];
  const skipped: { path: string; reason: string }[] = [];
  let visited = 0;
  let truncated = false;

  const walk = (dir: string, prefix: string): void => {
    if (truncated) return;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      skipped.push({
        path: prefix === '' ? '.' : prefix.slice(0, -1),
        reason: `could not be listed (${(error as Error & { code?: string }).code ?? 'error'})`,
      });
      return;
    }
    for (const entry of entries) {
      visited += 1;
      if (visited > WALK_ENTRY_CAP) {
        truncated = true;
        return;
      }
      // The reviewed exclusion flags apply to directories by name; the tool receives the same list.
      if (entry.isDirectory() && excludeDirs.has(entry.name)) continue;
      const rel = `${prefix}${entry.name}`;
      const full = join(appRoot, rel);
      let stats;
      try {
        stats = lstatSync(full);
      } catch {
        skipped.push({ path: rel, reason: 'could not be stat-ed' });
        continue;
      }
      if (stats.isSymbolicLink()) {
        skipped.push({ path: rel, reason: 'symlink not followed' });
        continue;
      }
      if (stats.isDirectory()) {
        walk(full, `${rel}/`);
        continue;
      }
      if (!stats.isFile()) continue;
      if (!isDeclarationFile(entry.name) && extensions.some((ext) => entry.name.endsWith(ext))) intended.push(rel);
    }
  };
  walk(appRoot, '');
  intended.sort();
  return { intended, truncated, skipped };
}

/**
 * Inventories the target-controlled suppressions that can remove obligations without review
 * (P3.1 requirement 4): a `.semgrepignore` at the application root (the tool resolves it from its
 * working directory, which is the application root), and inline `nosemgrep` annotations in the
 * inventoried files. Files too large to inspect within the read bound are counted as uninspected
 * rather than silently assumed clean.
 */
export function inventorySuppressions(appRoot: string, inventory: FileInventory): SuppressionInventory {
  const nosemgrep = { files: 0, annotations: 0 };
  let uninspected = 0;
  let semgrepignore: { readonly entries: number } | undefined;
  const ignorePath = join(appRoot, '.semgrepignore');
  if (existsSync(ignorePath)) {
    let text = '';
    try {
      text = readBoundedSync(ignorePath, SUPPRESSION_READ_BYTES) ?? '';
    } catch {
      text = '';
    }
    semgrepignore = {
      entries: text
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#')).length,
    };
  }

  for (const rel of inventory.intended) {
    const full = join(appRoot, rel);
    try {
      if (statSync(full).size > SUPPRESSION_READ_BYTES) {
        uninspected += 1;
        continue;
      }
    } catch {
      uninspected += 1;
      continue;
    }
    const text = readBoundedSync(full, SUPPRESSION_READ_BYTES);
    if (text === undefined) {
      uninspected += 1;
      continue;
    }
    const count = text.split('nosemgrep').length - 1;
    if (count > 0) {
      nosemgrep.files += 1;
      nosemgrep.annotations += count;
    }
  }
  return { nosemgrep, uninspected, ...(semgrepignore === undefined ? {} : { semgrepignore }) };
}
