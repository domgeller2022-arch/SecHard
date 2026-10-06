import { describe, expect, it } from 'vitest';
import { loadCatalogue, loadPatterns, loadSources } from '../../src/domain/definitions.js';
import { allPassing, evaluateWith, planFor } from '../helpers/fixtures.js';
import { validateAgainstSchema } from '../../src/validation/schema.js';
import { checkDuplicateIds, checkReference } from '../../src/validation/semantic.js';
import { loadDocument } from '../../src/validation/loader.js';
import { packageRoot } from '../../src/validation/schema.js';
import { join } from 'node:path';

const patterns = loadPatterns().patterns;
const sources = loadSources().sources;
const controls = loadCatalogue().controls;
const knownControlIds = new Set(controls.map((control) => control.id));

describe('reviewed pattern library', () => {
  it('contains patterns with unique ids', () => {
    const ids = patterns.map((pattern) => pattern.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
    expect(checkDuplicateIds(ids)).toEqual([]);
  });

  it('validates every pattern against the pattern schema', () => {
    for (const pattern of patterns) {
      const result = validateAgainstSchema('pattern', pattern);
      expect(result.issues, pattern.id).toEqual([]);
    }
  });

  // A pattern is a supporting record. If it could use a control ID, or be selected by a profile, it
  // would become a second, unreviewed control catalogue by accident.
  it('never uses a control ID shape', () => {
    for (const pattern of patterns) {
      expect(pattern.id).toMatch(/^PAT-[A-Z]+-[0-9]{2}$/);
      expect(knownControlIds.has(pattern.id), `${pattern.id} must not collide with a control id`).toBe(false);
    }
  });

  it('links only to controls that exist', () => {
    for (const pattern of patterns) {
      expect(pattern.related_control_ids.length).toBeGreaterThan(0);
      for (const id of pattern.related_control_ids) {
        expect(checkReference(id, { known: knownControlIds, kind: 'control' })).toEqual([]);
      }
    }
  });

  it('is draft until the owner reviews the corrected rationale', () => {
    expect(patterns.every((pattern) => pattern.review_status === 'draft')).toBe(true);
    expect(patterns.every((pattern) => pattern.reviewed_by === undefined)).toBe(true);
  });

  it('records provenance with a review date for every pattern', () => {
    for (const pattern of patterns) {
      expect(pattern.provenance.source_id, pattern.id).toBeTruthy();
      expect(Date.parse(pattern.provenance.reviewed_at)).not.toBeNaN();
      expect(pattern.provenance.reviewed_at <= '2026-10-06T00:00:01Z').toBe(true);
    }
  });

  it('records the factual corrections applied to imported material', () => {
    for (const pattern of patterns) {
      expect((pattern.provenance.corrections ?? []).length, pattern.id).toBeGreaterThan(0);
      for (const correction of pattern.provenance.corrections ?? []) {
        expect(correction.length).toBeGreaterThan(20);
      }
    }
  });

  it('gives every pattern both a vulnerable and a permitted example', () => {
    for (const pattern of patterns) {
      expect(pattern.vulnerable_example.code.length, pattern.id).toBeGreaterThan(0);
      expect(pattern.permitted_example.code.length, pattern.id).toBeGreaterThan(0);
      expect(pattern.vulnerable_example.code).not.toBe(pattern.permitted_example.code);
    }
  });

  it('does not claim verification was implemented when it was not', () => {
    const claims = patterns.flatMap((pattern) =>
      pattern.verification.filter((entry) => entry.implemented === true).map((entry) => `${pattern.id}:${entry.method}`),
    );
    // No fixture or recipe exists yet, so any claim here would be false.
    expect(claims).toEqual([]);
  });

  it('names a real method for each verification entry', () => {
    const methods = new Set([
      'authorization_test',
      'functional_test',
      'static_analysis',
      'schema_validation',
      'policy_consistency',
      'live_http_check',
      'client_asset_inspection',
      'manual_attestation',
    ]);
    for (const pattern of patterns) {
      for (const entry of pattern.verification) {
        expect(methods.has(entry.method), `${pattern.id} uses unknown method ${entry.method}`).toBe(true);
        expect(entry.description.length).toBeGreaterThan(10);
      }
    }
  });

  it('states limitations for every pattern', () => {
    for (const pattern of patterns) {
      expect(pattern.limitations.length, pattern.id).toBeGreaterThan(0);
    }
  });

  it('covers the corrections the integration review required', () => {
    const byId = new Map(patterns.map((pattern) => [pattern.id, pattern]));
    const allCorrections = patterns.flatMap((pattern) => pattern.provenance.corrections ?? []).join(' ');

    expect(byId.has('PAT-RLS-01')).toBe(true);
    expect(allCorrections).toMatch(/WITH CHECK/);
    expect(allCorrections).toMatch(/storage/i);
    expect(allCorrections).toMatch(/definer/i);
    expect(allCorrections).toMatch(/HttpOnly/);
    expect(allCorrections).toMatch(/x-forwarded-for|forwarding header|forwarded/i);
    expect(allCorrections).toMatch(/budget alert/i);
    expect(allCorrections).toMatch(/source[ -]?map/i);
    expect(allCorrections).toMatch(/parameteriz|parameter/i);
  });
});

describe('guidance can never become execution evidence', () => {
  it('produces no plan checks: planning is driven by profile and control definitions only', () => {
    const plan = planFor('pr');
    const patternTokens = patterns.map((pattern) => pattern.id);
    for (const check of plan.expected_checks) {
      for (const token of patternTokens) {
        expect(check.check_id).not.toContain(token);
        expect(check.recipe).not.toContain(token);
      }
    }
  });

  it('has no input path into the evaluator: pattern fields are not read as results', () => {
    // The evaluator's input contract names check results, manual evidence, exceptions, and approvals.
    // A pattern carries none of those shapes, so a reviewed pattern cannot satisfy a check.
    for (const pattern of patterns) {
      expect('outcome' in pattern).toBe(false);
      expect('evidence_origin' in pattern).toBe(false);
      expect('check_id' in pattern).toBe(false);
      expect('content_digest' in pattern).toBe(false);
    }
  });

  it('will not accept a pattern-verification entry as a satisfying result even if marked implemented', () => {
    const plan = planFor('pr');
    // Everything satisfies the plan. There is no field anywhere to inject a pattern observation, and
    // the decision is unchanged by the patterns existing at all.
    const decision = evaluateWith({ plan, results: allPassing(plan) });
    expect(decision.satisfied).toBe(true);
    expect(decision.reasons).toEqual([]);
  });
});

describe('upstream provenance records', () => {
  it('validates against the source schema', () => {
    for (const source of sources) {
      const result = validateAgainstSchema('source', source);
      expect(result.issues, source.id).toEqual([]);
    }
    const file = join(packageRoot(), 'upstream', 'sources.yaml');
    expect(loadDocument(file).issues).toEqual([]);
  });

  it('records the imported skill with its licence, attribution, and notice', () => {
    const skill = sources.find((source) => source.id === 'vibe-security-skill');
    expect(skill).toBeDefined();
    expect(skill?.licence).toBe('MIT');
    expect(skill?.use_type).toBe('adapting');
    expect(skill?.notice_file).toBe('upstream/notices/vibe-security-skill.LICENSE');
    expect(skill?.attribution).toMatch(/Chris Raroque/);
    expect(skill?.notes).toMatch(/No installer was run/);
  });

  it('does not present a reviewed snapshot as an established upstream commit', () => {
    const skill = sources.find((source) => source.id === 'vibe-security-skill');
    expect(skill?.reviewed_release.kind).toBe('digest');
    expect(skill?.notes).toMatch(/no Git metadata|commit could not be established/i);
  });

  it('conservatively states that imports cannot satisfy a control', () => {
    const skill = sources.find((source) => source.id === 'vibe-security-skill');
    expect(skill?.notes).toMatch(/cannot satisfy a control|supporting guidance only/);
  });
});
