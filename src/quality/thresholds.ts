import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { loadDocument } from '../validation/loader.js';
import { validateAgainstSchema } from '../validation/schema.js';

/**
 * The reviewed quality thresholds (`policy/quality-thresholds.yaml`).
 *
 * Thresholds decide when a measurement becomes a finding; they are calibration values set on the
 * corpus and this repository's own self-audit, and a consumer configuration can never widen them.
 * A malformed or missing policy file is an error, never a silent default.
 */

export interface EquivalentRole {
  readonly role: string;
  readonly packages: readonly string[];
}

export interface QualityThresholds {
  readonly strict_correctness: {
    readonly suppression_markers_max_per_file: number;
    readonly suppression_markers_max_total: number;
    readonly any_type_max_per_file: number;
  };
  readonly test_quality: { readonly max_files_listed: number };
  readonly vibe_tells: { readonly max_files_listed: number };
  readonly repo_hygiene: { readonly expected_lockfiles: readonly string[] };
  readonly dependency_health: { readonly equivalent_roles: readonly EquivalentRole[] };
  readonly calibration: { readonly recall_floor: number; readonly precision_floor: number; readonly clean_twin_max_findings: number };
}

export function loadQualityThresholds(policyRoot: string): { thresholds?: QualityThresholds; issues: readonly string[] } {
  const file = join(policyRoot, 'policy', 'quality-thresholds.yaml');
  const loaded = loadDocument<Record<string, unknown>>(file);
  if (loaded.data === undefined) {
    return { issues: [`quality thresholds not found or unreadable: ${file}`] };
  }
  const result = validateAgainstSchema('quality-thresholds', loaded.data, file);
  if (!result.valid) {
    return { issues: result.issues.map((issue) => `${issue.path ?? '$'}: ${issue.message}`) };
  }
  return { thresholds: loaded.data as unknown as QualityThresholds, issues: [] };
}

/** A bounded text read, shared by every quality scanner so no file is read twice unbounded. */
export function readBounded(file: string, limitBytes = 1024 * 1024): string | undefined {
  try {
    return readFileSync(file).subarray(0, limitBytes).toString('utf8');
  } catch {
    return undefined;
  }
}

export { parseYaml };
