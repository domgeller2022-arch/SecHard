import { describe, expect, it } from 'vitest';
import { loadMappings, loadSources } from '../../src/domain/definitions.js';
import { validateAgainstSchema } from '../../src/validation/schema.js';

const mappings = loadMappings();
const sources = loadSources().sources;
const sourceById = new Map(sources.map((source) => [source.id, source]));

describe('every standard cited by a control mapping is recorded', () => {
  it('names a pinned edition with a source URL', () => {
    for (const framework of Object.keys(mappings.editions)) {
      const edition = mappings.editions[framework];
      expect(edition, framework).toBeDefined();
      expect(edition?.edition.length, framework).toBeGreaterThan(0);
      expect(edition?.source, framework).toMatch(/^https:\/\//);
      // The framework must be traceable to a full source record, not only to a URL in this file.
      expect(edition?.source_id, framework).toBeDefined();
      expect(sourceById.get(edition?.source_id ?? ''), framework).toBeDefined();
    }
  });

  it('records a licence and a review date for each of those sources', () => {
    for (const framework of Object.keys(mappings.editions)) {
      const source = sourceById.get(mappings.editions[framework]?.source_id ?? '');
      expect(source?.licence, framework).toBeTruthy();
      expect(Date.parse(source?.last_reviewed ?? ''), framework).not.toBeNaN();
    }
  });
});

describe('nothing claims conformance', () => {
  it('uses related_risk only, never verified_coverage', () => {
    for (const [control, entries] of Object.entries(mappings.controls)) {
      for (const mapping of entries) {
        expect(mapping.relationship, `${control} -> ${mapping.framework}`).toBe('related_risk');
        expect(mapping.verified_by, control).toBeUndefined();
      }
    }
  });

  it('keeps the file marked unreviewed so a reader is not misled', () => {
    expect(mappings.reviewed).toBe(false);
    expect(mappings.review_note ?? '').toMatch(/not been reviewed|related_risk/);
  });
});

describe('the blueprint\'s standards are all accounted for', () => {
  // Each standard named in blueprint section 3 is either used by a mapping or recorded as
  // deliberately not referenced, with a reason. Absence is not allowed to imply coverage.
  const requiredSources = [
    'owasp-asvs',
    'owasp-top-10',
    'owasp-api-security',
    'owasp-cheat-sheets',
    'owasp-wstg',
    'nist-ssdf',
    'openssf-osps',
    'mvsp',
    'rfc-9700',
    'asd-secure-by-design',
    'slsa',
    'owasp-aisvs',
    'owasp-llm-top-10',
    'owasp-agentic-top-10',
    'owasp-mcp-top-10',
    'owasp-masvs',
    'electron-security',
  ];

  it('has a source record for each one', () => {
    for (const id of requiredSources) {
      expect(sourceById.get(id), id).toBeDefined();
    }
  });

  it('marks the out-of-scope ones with a reason and no control mapping', () => {
    const referenced = new Set(Object.values(mappings.editions).map((edition) => edition.source_id));
    for (const entry of mappings.not_referenced ?? []) {
      expect(sourceById.get(entry.source_id), entry.source_id).toBeDefined();
      expect(entry.reason.length, entry.source_id).toBeGreaterThan(20);
      expect(referenced.has(entry.source_id), `${entry.source_id} is both referenced and unreferenced`).toBe(false);
    }
    // The runtime-AI, mobile, and desktop standards are exactly the ones expected to be excluded.
    const excluded = new Set((mappings.not_referenced ?? []).map((entry) => entry.source_id));
    for (const id of ['owasp-aisvs', 'owasp-llm-top-10', 'owasp-agentic-top-10', 'owasp-mcp-top-10', 'owasp-masvs', 'electron-security']) {
      expect(excluded.has(id), id).toBe(true);
    }
  });

  it('records the non-commercial licence constraint on the MCP standard', () => {
    const mcp = sourceById.get('owasp-mcp-top-10');
    expect(mcp?.licence).toMatch(/NC|non-commercial/i);
    expect((mcp?.notes ?? '') + (mcp?.update_policy ?? '')).toMatch(/commercial/i);
  });
});

describe('every source record validates', () => {
  it('passes the source schema, including the standards and tool candidates', () => {
    expect(sources.length).toBeGreaterThan(20);
    for (const source of sources) {
      const result = validateAgainstSchema('source', source);
      expect(result.issues, source.id).toEqual([]);
    }
  });

  it('states a support status that matches what the repository actually does', () => {
    const invoked = sources.filter((source) => source.use_type === 'invoking').map((source) => source.id);
    // Only tools the toolchain actually runs may claim `invoking` plus `verified`.
    expect(invoked.sort()).toEqual(['colima', 'gitleaks', 'opengrep', 'osv-scanner', 'zizmor']);
    for (const id of invoked) {
      expect(sourceById.get(id)?.support_status, id).toBe('verified');
    }
  });

  it('treats every standard as a link, never as reused text', () => {
    for (const [framework, edition] of Object.entries(mappings.editions)) {
      expect(sourceById.get(edition.source_id ?? '')?.use_type, framework).toBe('linking');
    }
  });
});
