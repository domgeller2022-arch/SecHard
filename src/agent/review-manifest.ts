import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { parse } from 'yaml';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { packageRoot } from '../validation/schema.js';
import { loadCatalogue } from '../domain/definitions.js';
import { loadToolchain } from '../execution/registry.js';

/**
 * The sensitive-file review manifest.
 *
 * The manifest states which paths are security-sensitive and what a reviewer should look for. It is
 * data: this module validates it and answers "does this path require review", and it deliberately
 * does not claim to enforce anything. Enforcement is a platform setting (required checks, review
 * rules) and is configured in Step 13.
 */

export interface ReviewManifestEntry {
  readonly id: string;
  readonly control: string;
  readonly requires: 'human_review' | 'approval_record';
  readonly consumer?: boolean;
  readonly paths: readonly string[];
  readonly reason: string;
  readonly reviewer_checks: readonly string[];
}

export interface ReviewManifest {
  readonly schema: string;
  readonly version: number;
  readonly review_status: 'draft' | 'owner_reviewed';
  readonly entries: readonly ReviewManifestEntry[];
}

export function loadReviewManifest(path = join(packageRoot(), 'agent-rules', 'review-manifest.yaml')): ReviewManifest {
  return parse(readFileSync(path, 'utf8')) as ReviewManifest;
}

export function validateReviewManifest(manifest: ReviewManifest): readonly string[] {
  const problems: string[] = [];
  const knownControls = new Set(loadCatalogue().controls.map((control) => control.id));
  const seen = new Set<string>();

  if (manifest.schema !== 'hardening/review-manifest/v1') {
    problems.push(`unexpected manifest schema '${String(manifest.schema)}'`);
  }

  for (const entry of manifest.entries) {
    if (seen.has(entry.id)) problems.push(`duplicate entry id '${entry.id}'`);
    seen.add(entry.id);

    if (!knownControls.has(entry.control)) {
      problems.push(`entry '${entry.id}' references unknown control '${entry.control}'`);
    }
    if (entry.paths.length === 0) {
      problems.push(`entry '${entry.id}' lists no paths`);
    }
    for (const pattern of entry.paths) {
      if (pattern.trim().length === 0) problems.push(`entry '${entry.id}' has an empty path pattern`);
      // A pattern that matches everything would make review meaningless.
      if (pattern === '*' || pattern === '**' || pattern === '**/*') {
        problems.push(`entry '${entry.id}' has a pattern that matches everything: '${pattern}'`);
      }
    }
    if (entry.reason.trim().length < 20) {
      problems.push(`entry '${entry.id}' needs a reason explaining why review is required`);
    }
    if (entry.reviewer_checks.length === 0) {
      problems.push(`entry '${entry.id}' must state what the reviewer should check`);
    }
  }

  return problems;
}

/** Whether a repository-relative path falls under an entry in the manifest. */
export function reviewEntryFor(manifest: ReviewManifest, relativePath: string): ReviewManifestEntry | undefined {
  return manifest.entries.find((entry) =>
    entry.paths.some((pattern) => globMatches(pattern, relativePath)),
  );
}

/**
 * A small, predictable glob matcher: `**` crosses directories, `*` does not.
 *
 * Implemented here rather than pulled in as a dependency because the semantics needed are narrow and
 * a matching bug in a security manifest would silently stop requiring review.
 */
export function globMatches(pattern: string, relativePath: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const withDoubleStar = escaped.replace(/\*\*\//g, '\u0000').replace(/\*\*/g, '\u0001');
  const withSingleStar = withDoubleStar.replace(/\*/g, '[^/]*');
  const regex = withSingleStar
    .replace(/\u0000/g, '(?:.*/)?')
    .replace(/\u0001/g, '.*');
  return new RegExp(`^${regex}$`).test(relativePath);
}

export type GitRunner = (cwd: string, args: readonly string[]) => string | undefined;

/**
 * The git to use, resolved to an absolute path from the reviewed toolchain record.
 *
 * No PATH lookup: the command that establishes which changes exist is not going to be chosen by an
 * environment variable.
 */
export function gitExecutable(): string | undefined {
  const identity = loadToolchain().executables?.git;
  const candidates = [identity?.executable, identity?.fallbackExecutable, '/usr/bin/git'].filter(
    (candidate): candidate is string => typeof candidate === 'string',
  );
  return candidates.find((candidate) => existsSync(candidate));
}

export const runGit: GitRunner = (cwd, args) => {
  const executable = gitExecutable();
  if (executable === undefined) return undefined;
  try {
    return execFileSync(executable, [...args], {
      cwd,
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { PATH: process.env['PATH'] ?? '' },
    }).trim();
  } catch {
    return undefined;
  }
};
