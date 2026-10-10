import { join } from 'node:path';
import { loadDocument } from '../validation/loader.js';
import { validateAgainstSchema } from '../validation/schema.js';
import { packageRoot } from '../validation/schema.js';

/**
 * Requirement-level standard mappings (Batch S1).
 *
 * A mapping file lives at `controls/mappings/<standard>.yaml`, is validated against the
 * `standard-mapping` schema, and answers two questions for every requirement: which controls and
 * recipes relate to it, and by what method this kit can check it (automated, manual, advisory,
 * gap with a reason, or not_applicable to the v1 profiles). The rule from the earlier chapter-level
 * work stands: every relationship is related_risk; nothing is verified_coverage until an
 * application is actually assessed against the requirement.
 */

export interface MappedRequirement {
  readonly id: string;
  readonly level?: number;
  readonly section?: string;
  readonly chapter?: string;
  readonly summary: string;
  readonly controls: readonly string[];
  readonly recipes: readonly string[];
  readonly method: 'automated' | 'manual' | 'advisory' | 'not_applicable' | 'gap';
  readonly relationship: 'related_risk' | 'verified_coverage';
  readonly note?: string;
  readonly url?: string;
}

export interface StandardMapping {
  readonly standard_id: string;
  readonly edition: string;
  readonly source_data?: string;
  readonly requirements: readonly MappedRequirement[];
}

export interface MappingLoadResult {
  readonly mapping?: StandardMapping;
  readonly issues: readonly string[];
}

export function loadStandardMapping(standardId: string): MappingLoadResult {
  const file = join(packageRoot(), 'controls', 'mappings', `${standardId}.yaml`);
  const loaded = loadDocument<Record<string, unknown>>(file);
  if (loaded.data === undefined) {
    return { issues: [`mapping not found or unreadable: ${file}`] };
  }
  const result = validateAgainstSchema('standard-mapping', loaded.data, file);
  if (!result.valid) {
    return { issues: result.issues.map((issue) => `${issue.path ?? '$'}: ${issue.message}`) };
  }
  const data = loaded.data as unknown as { standard_id: string; edition: string; source_data?: string; requirements: Record<string, unknown>[] };
  return {
    mapping: {
      standard_id: data.standard_id,
      edition: data.edition,
      ...(data.source_data === undefined ? {} : { source_data: data.source_data }),
      requirements: data.requirements.map((requirement) => ({
        id: String(requirement['id']),
        ...(requirement['level'] === undefined ? {} : { level: Number(requirement['level']) }),
        ...(requirement['section'] === undefined ? {} : { section: String(requirement['section']) }),
        ...(requirement['chapter'] === undefined ? {} : { chapter: String(requirement['chapter']) }),
        summary: String(requirement['summary']),
        controls: Array.isArray(requirement['controls']) ? (requirement['controls'] as string[]) : [],
        recipes: Array.isArray(requirement['recipes']) ? (requirement['recipes'] as string[]) : [],
        method: requirement['method'] as MappedRequirement['method'],
        relationship: requirement['relationship'] as MappedRequirement['relationship'],
        ...(requirement['note'] === undefined ? {} : { note: String(requirement['note']) }),
        ...(requirement['url'] === undefined ? {} : { url: String(requirement['url']) }),
      })),
    },
    issues: [],
  };
}

export interface CoverageSummary {
  readonly standard_id: string;
  readonly edition: string;
  readonly total: number;
  readonly byMethod: Readonly<Record<string, number>>;
}

/** The per-standard coverage summary the audit report states ("ASVS L1: x of y automated..."). */
export function coverageSummary(mapping: StandardMapping, levels?: readonly number[]): CoverageSummary {
  const requirements = levels === undefined ? mapping.requirements : mapping.requirements.filter((r) => levels.includes(r.level ?? 0));
  const byMethod: Record<string, number> = {};
  for (const requirement of requirements) {
    byMethod[requirement.method] = (byMethod[requirement.method] ?? 0) + 1;
  }
  return { standard_id: mapping.standard_id, edition: mapping.edition, total: requirements.length, byMethod };
}

/** The requirement-level coverage matrix for one standard, as markdown. */
export function renderCoverageMatrix(mapping: StandardMapping): string {
  const lines: string[] = [
    `# ${mapping.standard_id} coverage (edition ${mapping.edition})`,
    '',
    'Generated from `controls/mappings/' + mapping.standard_id + '.yaml` by `tools/generate-coverage.ts`. Do not edit',
    'by hand: the mapping file is the record.',
    '',
    `Every requirement is mapped to a method or recorded as a gap with a reason. All relationships are related_risk;`,
    `nothing is verified_coverage until an application is assessed against it.`,
    '',
    '| Requirement | L | Summary | Method | Controls | Note |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  for (const requirement of mapping.requirements) {
    const note = (requirement.note ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
    const summary = requirement.summary.replace(/\|/g, '\\|');
    lines.push(
      `| ${requirement.id} | ${requirement.level ?? '-'} | ${summary} | ${requirement.method} | ${requirement.controls.join(', ') || '-'} | ${note || '-'} |`,
    );
  }
  const summary = coverageSummary(mapping);
  lines.push(
    '',
    '## Totals',
    '',
    `- Requirements: ${summary.total}`,
    ...Object.entries(summary.byMethod).sort().map(([method, count]) => `- ${method}: ${count}`),
    '',
  );
  return lines.join('\n');
}
