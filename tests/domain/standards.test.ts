import { describe, expect, it } from 'vitest';
import { loadCatalogue, loadMappings, loadSources } from '../../src/domain/definitions.js';
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

  it('cites a WSTG test id, or records why none exists, on every test recipe (Batch S)', () => {
    // The remediation plan's WSTG row: every test recipe (authorization_test or functional_test)
    // must cite the WSTG test IDs it implements and the cheat sheet it follows. Where WSTG has no
    // equivalent (supply-chain hooks, the repository's own test suite, resource exhaustion - WSTG
    // deliberately excludes DoS testing), the reason is recorded on the entry rather than a fake
    // id being invented.
    const catalogue = loadCatalogue();
    const wstgIds = new Set<string>();
    let checked = 0;
    for (const control of catalogue.controls) {
      for (const method of control.verification) {
        if (method.method !== 'authorization_test' && method.method !== 'functional_test') continue;
        checked += 1;
        const raw = method as unknown as { wstg?: unknown; wstg_note?: unknown; recipe?: string };
        const ids = Array.isArray(raw.wstg) ? (raw.wstg as string[]) : [];
        for (const id of ids) {
          expect(id, `${control.id} ${raw.recipe}: malformed WSTG id`).toMatch(/^WSTG-[A-Z]{4}-[0-9]{2}$/);
          // Multiple recipes may cite the same WSTG test: ownership, role/tenant, and provider
          // policy checks each implement a facet of WSTG-ATHZ-02, and that is legitimate.
          wstgIds.add(id);
        }
        const note = typeof raw.wstg_note === 'string' ? raw.wstg_note : '';
        expect(ids.length > 0 || note.length >= 20, `${control.id} ${raw.recipe}: a test recipe must cite WSTG ids or record why none exists`).toBe(true);
        expect(ids.length === 0 || note.length === 0, `${control.id} ${raw.recipe}: cite ids or a reason, not both`).toBe(true);
      }
    }
    // Deliberate floor: the plan's examples (ATHZ-02 for IDOR) and the session/input chapters must
    // be represented.
    expect(wstgIds.has('WSTG-ATHZ-02')).toBe(true);
    expect(wstgIds.has('WSTG-ATHZ-04')).toBe(true);
    expect(wstgIds.has('WSTG-SESS-01')).toBe(true);
    expect(wstgIds.has('WSTG-INPV-01')).toBe(true);
    expect(checked).toBeGreaterThan(8);
  });

  it('records reused standard material with a digest, a licence, and a review-before-distribution note', () => {
    // Until Batch S, every standard was link-only: no standard text was reused anywhere. Batch S
    // vendored the official ASVS requirement CSV so the requirement-level mapping is checkable
    // offline and reviewable against the real text. The rule is therefore stricter, not looser:
    // a standard recorded as `adapting` must carry a content digest, a named licence, and the
    // review-before-distribution note; everything else stays link-only.
    const adaptingStandards: string[] = [];
    for (const [framework, edition] of Object.entries(mappings.editions)) {
      const source = sourceById.get(edition.source_id ?? '');
      if (source?.use_type === 'linking') continue;
      adaptingStandards.push(framework);
      expect(source?.use_type, framework).toBe('adapting');
      expect(source?.licence, framework).toBeTruthy();
      expect(source?.reviewed_release.kind, framework).toBe('digest');
      expect(source?.reviewed_release.value, framework).toMatch(/^[0-9a-f]{64}$/);
      expect(source?.notes ?? '', framework).toMatch(/CC BY-SA|licence review/i);
    }
    // The deliberate list: exactly the standards whose data is vendored. Anything else appearing
    // here is an undeclared reuse of standard text and must fail this test.
    expect(adaptingStandards.sort()).toEqual(['OWASP-ASVS']);
  });
});
