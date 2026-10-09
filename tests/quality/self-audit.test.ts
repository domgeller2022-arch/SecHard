import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeStrictCorrectness, analyzeTestQuality } from '../../src/quality/correctness.js';
import { analyzeDependencyHealth, analyzeRepoHygiene } from '../../src/quality/hygiene.js';
import { analyzeVibeTells } from '../../src/quality/tells.js';
import { loadQualityThresholds } from '../../src/quality/thresholds.js';

/**
 * SecHard audits itself (Batch Q checkpoint: "SecHard passes its own quality audit").
 *
 * This is calibration, not vanity: the repo that owns the quality analysers is their hardest
 * precision test, because its source is full of rationale comments, pattern text, and deliberate
 * fixture material. The rule set was tuned against this repository with every change justified by
 * a real false positive, and the outcome is pinned here so any future finding is a deliberate,
 * reviewed change rather than drift.
 *
 * The one accepted finding is the absent licence: a recorded owner decision
 * (`release_scope: private-sole-maintainer`), documented in README.md and the owner decisions
 * file. The analyser reports it because an unrecorded absence is indistinguishable from an
 * oversight; here it is a recorded one, and the finding carries LOW severity for exactly that
 * reason.
 */

const REPO = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..');

describe('SecHard passes its own quality audit', () => {
  const policy = loadQualityThresholds(REPO).thresholds;
  expect(policy).toBeDefined();
  const thresholds = policy as NonNullable<typeof policy>;

  const tells = analyzeVibeTells(REPO, { maxFilesListed: thresholds.vibe_tells.max_files_listed }).findings;
  const correctness = analyzeStrictCorrectness(REPO, thresholds.strict_correctness).findings;
  const tests = analyzeTestQuality(REPO).findings;
  const hygiene = analyzeRepoHygiene(REPO, thresholds.repo_hygiene.expected_lockfiles).findings;
  const deps = analyzeDependencyHealth(REPO, thresholds.repo_hygiene.expected_lockfiles, thresholds.dependency_health.equivalent_roles).findings;
  const all = [...tells, ...correctness, ...tests, ...hygiene, ...deps];

  it('reports no high or critical quality findings on its own source', () => {
    const blocking = all.filter((finding) => finding.severity === 'high' || finding.severity === 'critical');
    expect(blocking, `blocking quality findings on SecHard itself: ${blocking.map((finding) => `${finding.rule_id} at ${finding.location}`).join(', ')}`).toEqual([]);
  });

  it('reports exactly the one recorded, accepted finding and nothing else', () => {
    expect(all.map((finding) => finding.rule_id)).toEqual(['no-licence']);
    const licence = all[0];
    expect(licence?.severity).toBe('low');
    expect(licence?.location).toBe('.');
  });

  it('finds no duplicate-role dependencies in its own lockfile', () => {
    expect(deps).toEqual([]);
  });

  it('finds no focused, skipped, tautological, or assertion-free tests in its own suite', () => {
    expect(tests).toEqual([]);
  });
});
