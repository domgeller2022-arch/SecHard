import type { ValidationIssue } from './errors.js';
import { issue } from './errors.js';

export interface TimeIntervalEntry {
  readonly id: string;
  readonly observedAt: string;
  readonly expiresAt: string;
}

export interface ReferenceSet {
  readonly known: ReadonlySet<string>;
  readonly kind: string;
  readonly file?: string;
}

/**
 * Checks that an observed/expiry pair is well formed and not already expired.
 *
 * An expiry at or before the observation is rejected outright: it cannot describe a period in which
 * the record was believed valid.
 */
export function checkIntervals(entries: readonly TimeIntervalEntry[], now: Date): readonly ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  for (const entry of entries) {
    const expires = Date.parse(entry.expiresAt);
    const observed = Date.parse(entry.observedAt);

    if (Number.isNaN(expires) || Number.isNaN(observed)) {
      issues.push(
        issue('semantic.invalid_interval', `unparsable time interval for '${entry.id}'`, undefined, entry.id),
      );
      continue;
    }
    if (expires <= observed) {
      issues.push(
        issue(
          'semantic.invalid_interval',
          `'${entry.id}' expires at or before it was observed`,
          undefined,
          entry.id,
        ),
      );
      continue;
    }
    if (expires <= now.getTime()) {
      issues.push(
        issue('semantic.invalid_interval', `'${entry.id}' expired at ${entry.expiresAt}`, undefined, entry.id),
      );
    }
  }
  return issues;
}

/**
 * Resolves a referenced ID against the known set.
 *
 * A missing reference is an error, never a silently dropped requirement.
 */
export function checkReference(id: string, reference: ReferenceSet): readonly ValidationIssue[] {
  if (reference.known.has(id)) return [];
  return [
    issue(
      'semantic.unknown_reference',
      `unknown ${reference.kind} '${id}'`,
      reference.file,
    ),
  ];
}

/** Rejects repeated IDs within one collection. */
export function checkDuplicateIds(ids: readonly string[], file?: string): readonly ValidationIssue[] {
  const seen = new Set<string>();
  const issues: ValidationIssue[] = [];
  for (const id of ids) {
    if (seen.has(id)) {
      issues.push(issue('semantic.duplicate_id', `duplicate id '${id}'`, file, id));
    }
    seen.add(id);
  }
  return issues;
}
