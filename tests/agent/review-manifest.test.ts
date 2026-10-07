import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  globMatches,
  loadReviewManifest,
  reviewEntryFor,
  validateReviewManifest,
  type ReviewManifest,
} from '../../src/agent/review-manifest.js';
import { packageRoot } from '../../src/validation/schema.js';

const manifest = loadReviewManifest();

describe('the review manifest', () => {
  it('validates cleanly', () => {
    expect(validateReviewManifest(manifest)).toEqual([]);
  });

  it('covers every sensitive area the plan names', () => {
    const required = [
      'controls',
      'mappings',
      'policy',
      'lockfiles',
      'workflows',
      'agent_settings',
      'security_tests',
      'consumer_manifest',
      'consumer_exceptions',
    ];
    const ids = new Set(manifest.entries.map((entry) => entry.id));
    for (const id of required) expect(ids.has(id), id).toBe(true);
  });

  it('every entry names a real control and says what to check', () => {
    for (const entry of manifest.entries) {
      expect(entry.control, entry.id).toMatch(/^[A-Z]{2,}-[0-9]{2}$/);
      expect(entry.reviewer_checks.length, entry.id).toBeGreaterThan(0);
      expect(entry.reason.length, entry.id).toBeGreaterThan(20);
    }
  });

  it('is a draft until the owner reviews it', () => {
    expect(manifest.review_status).toBe('draft');
  });

  it('states that it is data, not enforcement', () => {
    const raw = readFileSync(join(packageRoot(), 'agent-rules', 'review-manifest.yaml'), 'utf8');
    expect(raw).toMatch(/This manifest is data, not enforcement/);
    // Enforcement is a platform setting; the manifest must not claim otherwise.
    expect(raw).toMatch(/configured in Step 13/);
  });
});

describe('manifest validation rejects weak entries', () => {
  const base: ReviewManifest = {
    schema: 'hardening/review-manifest/v1',
    version: 1,
    review_status: 'draft',
    entries: [
      {
        id: 'x',
        control: 'GOV-02',
        requires: 'human_review',
        paths: ['src/**'],
        reason: 'A change here can alter the decision the gate reaches.',
        reviewer_checks: ['The tests still fail when the guarded behaviour is removed'],
      },
    ],
  };

  it('rejects an unknown control', () => {
    const problems = validateReviewManifest({
      ...base,
      entries: [{ ...base.entries[0]!, control: 'NOPE-99' }],
    });
    expect(problems.join(' ')).toMatch(/unknown control/);
  });

  it('rejects a pattern that matches everything', () => {
    for (const pattern of ['*', '**', '**/*']) {
      const problems = validateReviewManifest({ ...base, entries: [{ ...base.entries[0]!, paths: [pattern] }] });
      expect(problems.join(' '), pattern).toMatch(/matches everything/);
    }
  });

  it('rejects a duplicate entry id', () => {
    const problems = validateReviewManifest({ ...base, entries: [base.entries[0]!, base.entries[0]!] });
    expect(problems.join(' ')).toMatch(/duplicate entry id/);
  });

  it('rejects an entry with no reviewer checks', () => {
    const problems = validateReviewManifest({ ...base, entries: [{ ...base.entries[0]!, reviewer_checks: [] }] });
    expect(problems.join(' ')).toMatch(/what the reviewer should check/);
  });

  it('rejects a reason that explains nothing', () => {
    const problems = validateReviewManifest({ ...base, entries: [{ ...base.entries[0]!, reason: 'because' }] });
    expect(problems.join(' ')).toMatch(/needs a reason/);
  });
});

describe('glob matching', () => {
  it('matches the way the manifest needs', () => {
    expect(globMatches('tests/**', 'tests/gate/gate.test.ts')).toBe(true);
    expect(globMatches('tests/**', 'src/domain/evaluator.ts')).toBe(false);
    expect(globMatches('policy/toolchain.yaml', 'policy/toolchain.yaml')).toBe(true);
    expect(globMatches('policy/toolchain.yaml', 'policy/gate-policy.yaml')).toBe(false);
    expect(globMatches('controls/mappings/**', 'controls/mappings/standards.yaml')).toBe(true);
    expect(globMatches('.github/workflows/**', '.github/workflows/hardening-pr.yaml')).toBe(true);
    // A single star does not cross a directory boundary.
    expect(globMatches('ci/*.toml', 'ci/configs/gitleaks.toml')).toBe(false);
    expect(globMatches('ci/*.toml', 'ci/gitleaks.toml')).toBe(true);
  });

  it('finds the entry responsible for a path', () => {
    expect(reviewEntryFor(manifest, 'tests/gate/gate.test.ts')?.id).toBe('security_tests');
    expect(reviewEntryFor(manifest, 'policy/gate-policy.yaml')?.id).toBe('policy');
    expect(reviewEntryFor(manifest, '.hardening/exceptions.yaml')?.id).toBe('consumer_exceptions');
    expect(reviewEntryFor(manifest, 'README.md')).toBeUndefined();
  });

  it('marks consumer paths as consumer-owned', () => {
    for (const id of ['consumer_manifest', 'consumer_exceptions']) {
      expect(manifest.entries.find((entry) => entry.id === id)?.consumer, id).toBe(true);
    }
    // And this repository's own paths are not.
    expect(manifest.entries.find((entry) => entry.id === 'security_tests')?.consumer).toBeUndefined();
  });
});
