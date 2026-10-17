import { lstatSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { sha256Hex } from './digest.js';

/**
 * Writes a record by writing a temporary file in the same directory and renaming it into place.
 *
 * A reader must never see a half-written plan or report: a partially written evidence file that
 * happens to parse is worse than a missing one.
 */
export function writeAtomic(file: string, contents: string): { readonly path: string; readonly digest: string } {
  // R1-02: a destination that is itself a symlink would carry the write outside the checked
  // output root; refuse rather than follow it.
  try {
    if (lstatSync(file).isSymbolicLink()) {
      throw new Error(`refusing to write through a symlink: ${file}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  mkdirSync(dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}-${Date.now().toString(36)}`;
  try {
    writeFileSync(temporary, contents, { encoding: 'utf8', mode: 0o600 });
    renameSync(temporary, file);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return { path: file, digest: sha256Hex(contents) };
}

export function writeJson(file: string, value: unknown): { readonly path: string; readonly digest: string } {
  return writeAtomic(file, `${JSON.stringify(value, null, 2)}\n`);
}

export interface RunDirectory {
  readonly root: string;
  readonly planPath: string;
  readonly resultsPath: string;
  readonly reportJsonPath: string;
  readonly reportMarkdownPath: string;
  readonly reportsDir: string;
  readonly runRecordPath: string;
}

/**
 * A run directory is per-run, so an old run's report can never satisfy a new plan. The plan identity
 * is written into `run.json` and re-checked when results are evaluated.
 */
export function createRunDirectory(parent: string, runId: string): RunDirectory {
  const root = join(parent, runId);
  for (const stale of ['plan.json', 'results.json', 'report.json', 'report.md', 'run.json']) {
    rmSync(join(root, stale), { force: true });
  }
  mkdirSync(join(root, 'reports'), { recursive: true });

  return {
    root,
    planPath: join(root, 'plan.json'),
    resultsPath: join(root, 'results.json'),
    reportJsonPath: join(root, 'report.json'),
    reportMarkdownPath: join(root, 'report.md'),
    reportsDir: join(root, 'reports'),
    runRecordPath: join(root, 'run.json'),
  };
}

export interface RunRecord {
  readonly schema: 'hardening/run-record/v1';
  readonly run_id: string;
  readonly started_at: string;
  readonly finished_at?: string;
  readonly stage: string;
  readonly environment: string;
  readonly app_root: string;
  readonly policy_root: string;
  readonly source_commit: string;
  readonly source_dirty: boolean;
  readonly tool_version: string;
  readonly node_version: string;
  readonly plan_digest?: string;
  readonly outcome?: 'satisfied' | 'blocked' | 'error';
  readonly diagnostic?: string;
}

/**
 * A deliberately narrow environment record. A full process environment can contain credentials and
 * unrelated paths, so only non-secret, decision-relevant fields are recorded.
 */
export function environmentIdentity(): { readonly tool_version: string; readonly node_version: string } {
  return { tool_version: '0.1.0-dev.0', node_version: process.version };
}
