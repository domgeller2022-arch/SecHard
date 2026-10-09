import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { analyzeStrictCorrectness, analyzeTestQuality } from '../../src/quality/correctness.js';
import { analyzeDependencyHealth, analyzeRepoHygiene } from '../../src/quality/hygiene.js';
import { analyzeVibeTells } from '../../src/quality/tells.js';
import { loadQualityThresholds } from '../../src/quality/thresholds.js';
import type { Finding } from '../../src/domain/types.js';

/**
 * Calibration (remediation-plan Q6). "Finds every issue" is a measured claim here, not a promise:
 * recall is the fraction of seeded issues the analysers found, precision is the fraction of
 * findings that correspond to a seed, and the clean twin must produce zero findings — that is
 * where false positives surface. The floors live in the reviewed thresholds policy, and the
 * measured numbers are reported in the batch checkpoint.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CORPUS = join(REPO, 'tests', 'corpus');

interface Seeded {
  readonly app: string;
  readonly clean_twin: string;
  readonly seeded: readonly { rule_id: string; file: string }[];
  readonly opengrep_seeded: readonly { rule_id: string; file: string }[];
}

const record = parseYaml(readFileSync(join(CORPUS, 'SEEDED-ISSUES.yaml'), 'utf8')) as Seeded;

const thresholds = loadQualityThresholds(REPO);
expect(thresholds.thresholds, 'the quality thresholds policy must load for calibration').toBeDefined();
const policy = thresholds.thresholds as NonNullable<typeof thresholds.thresholds>;

function allOwnableFindings(appRoot: string): Finding[] {
  return [
    ...analyzeVibeTells(appRoot, { maxFilesListed: policy.vibe_tells.max_files_listed }).findings,
    ...analyzeStrictCorrectness(appRoot, policy.strict_correctness).findings,
    ...analyzeTestQuality(appRoot).findings,
    ...analyzeRepoHygiene(appRoot, policy.repo_hygiene.expected_lockfiles).findings,
    ...analyzeDependencyHealth(appRoot, policy.repo_hygiene.expected_lockfiles, policy.dependency_health.equivalent_roles).findings,
  ];
}

describe('quality analyser calibration (Q6)', () => {
  const findings = allOwnableFindings(join(CORPUS, record.app));

  it('finds every seeded issue the ownable analysers own (recall)', () => {
    const foundRuleIds = new Set(findings.map((finding) => finding.rule_id));
    const missing = record.seeded.filter((seed) => !foundRuleIds.has(seed.rule_id));
    const recall = (record.seeded.length - missing.length) / record.seeded.length;
    // The measured number, printed for the record; the assertion below is the floor.
    console.info(`calibration: recall ${String(recall)} over ${String(record.seeded.length)} seeded issues${missing.length === 0 ? '' : `, missing: ${missing.map((seed) => seed.rule_id).join(', ')}`}`);
    expect(missing, `seeded issues not found: ${missing.map((seed) => `${seed.rule_id} (${seed.file})`).join(', ')}`).toEqual([]);
    expect(recall).toBeGreaterThanOrEqual(policy.calibration.recall_floor);
  });

  it('only reports findings that correspond to a seed (precision)', () => {
    const seeds = new Set(record.seeded.map((seed) => seed.rule_id));
    const matched = findings.filter((finding) => seeds.has(finding.rule_id));
    const unmatched = findings.filter((finding) => !seeds.has(finding.rule_id));
    const precision = matched.length / findings.length;
    console.info(`calibration: precision ${String(precision)} (${String(matched.length)} matched, ${String(unmatched.length)} unmatched)`);
    // Unmatched findings on the deliberately messy app are precision questions; on this corpus the
    // analyser must be tight enough that the floor holds with room to spare.
    expect(unmatched, `findings with no seed: ${unmatched.map((finding) => `${finding.rule_id} at ${finding.location}`).join(', ')}`).toEqual([]);
    expect(precision).toBeGreaterThanOrEqual(policy.calibration.precision_floor);
  });

  it('reports zero findings on the clean twin', () => {
    const clean = allOwnableFindings(join(CORPUS, record.clean_twin));
    expect(clean, `false positives on the clean twin: ${clean.map((finding) => `${finding.rule_id} at ${finding.location}`).join(', ')}`).toHaveLength(policy.calibration.clean_twin_max_findings);
  });

  it('every seeded file exists in the corpus it names', () => {
    for (const seed of [...record.seeded, ...record.opengrep_seeded]) {
      if (seed.file === '.') continue;
      expect(() => readFileSync(join(CORPUS, record.app, seed.file)), `${seed.rule_id}: ${seed.file}`).not.toThrow();
    }
  });
});

describe('each tell rule fires on its seed and stays silent on clean code', () => {
  // Per-rule isolation: a rule that fires only because another rule's file is messy is a rule that
  // will misbehave on real applications. Each seed is checked against the seeded file.
  it('fires each seeded tell in the seeded file', () => {
    const tells = analyzeVibeTells(join(CORPUS, record.app), { maxFilesListed: policy.vibe_tells.max_files_listed }).findings;
    const seededTells = record.seeded.filter((seed) => seed.rule_id.startsWith('tell.'));
    for (const seed of seededTells) {
      expect(
        tells.some((finding) => finding.rule_id === seed.rule_id && (finding.location ?? '').startsWith(seed.file)),
        `${seed.rule_id} must fire in ${seed.file}`,
      ).toBe(true);
    }
  });

  it('is silent on the clean twin, file by file', () => {
    const cleanTells = analyzeVibeTells(join(CORPUS, record.clean_twin), { maxFilesListed: policy.vibe_tells.max_files_listed }).findings;
    expect(cleanTells).toEqual([]);
    const cleanTests = analyzeTestQuality(join(CORPUS, record.clean_twin)).findings;
    expect(cleanTests).toEqual([]);
    const cleanCorrectness = analyzeStrictCorrectness(join(CORPUS, record.clean_twin), policy.strict_correctness).findings;
    expect(cleanCorrectness).toEqual([]);
  });
});
