import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadStandardMapping } from '../../src/domain/standards-coverage.js';
import { loadCatalogue } from '../../src/domain/definitions.js';
import { RECIPES } from '../../dist/execution/recipes.js';

/**
 * Batch S acceptance. The remediation plan's own "done when" criteria, executed:
 * - "A test fails if any ASVS ID is unmapped or any chapter name is invalid" - both are checked
 *   against the vendored official CSV, not against the mapping's own claim about itself.
 * - "All 10 present; a test rejects names not in the 2025 list" for the Top 10.
 * - Every mapped control and recipe id exists; every gap and not_applicable carries a reason.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Minimal quoted-field CSV parsing; the vendored ASVS data embeds commas in descriptions. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"') {
        if (text[index + 1] === '"') { field += '"'; index += 1; } else { quoted = false; }
      } else {
        field += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ',') {
      row.push(field); field = '';
    } else if (character === '\n' || character === '\r') {
      if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); row = []; field = ''; }
      if (character === '\r' && text[index + 1] === '\n') index += 1;
    } else {
      field += character;
    }
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows.slice(1); // header row
}
const MAPPING_IDS = ['asvs', 'owasp-top-10', 'owasp-api-top-10', 'nist-ssdf', 'osps', 'mvsp', 'asd-sbd', 'mcp-top-10'];

const MAPPINGS = new Map(MAPPING_IDS.map((id) => {
  const loaded = loadStandardMapping(id);
  expect(loaded.mapping, `${id}: ${loaded.issues.join('; ')}`).toBeDefined();
  return [id, loaded.mapping as NonNullable<typeof loaded.mapping>];
}));

const catalogue = loadCatalogue();
const knownControls = new Set(catalogue.controls.map((control) => control.id));

describe('every mapping file is a valid standard mapping', () => {
  it('maps at least the planned requirement counts', () => {
    expect(MAPPINGS.get('asvs')?.requirements.length).toBe(345);
    expect(MAPPINGS.get('owasp-top-10')?.requirements.length).toBe(10);
    expect(MAPPINGS.get('owasp-api-top-10')?.requirements.length).toBe(10);
    expect(MAPPINGS.get('nist-ssdf')?.requirements.length).toBe(47);
    expect(MAPPINGS.get('osps')?.requirements.length).toBeGreaterThanOrEqual(64);
    expect(MAPPINGS.get('mvsp')?.requirements.length).toBe(25);
    expect(MAPPINGS.get('asd-sbd')?.requirements.length).toBe(6);
    expect(MAPPINGS.get('mcp-top-10')?.requirements.length).toBe(10);
  });

  it('names only controls that exist in the catalogue, and recipes that are declared somewhere', () => {
    const declaredRecipes = new Set<string>(Object.keys(RECIPES));
    for (const control of catalogue.controls) {
      for (const method of control.verification) {
        if (method.recipe !== undefined) declaredRecipes.add(method.recipe);
      }
    }
    for (const [id, mapping] of MAPPINGS) {
      for (const requirement of mapping.requirements) {
        for (const control of requirement.controls) {
          expect(knownControls.has(control), `${id} ${requirement.id}: unknown control ${control}`).toBe(true);
        }
        for (const recipe of requirement.recipes) {
          expect(declaredRecipes.has(recipe), `${id} ${requirement.id}: recipe ${recipe} is not declared by any control or registry`).toBe(true);
        }
      }
    }
  });

  it('records a reason on every gap and every not_applicable, and never claims verified coverage', () => {
    for (const [id, mapping] of MAPPINGS) {
      for (const requirement of mapping.requirements) {
        expect(requirement.relationship, `${id} ${requirement.id}`).toBe('related_risk');
        if (requirement.method === 'gap' || requirement.method === 'not_applicable') {
          expect((requirement.note ?? '').length, `${id} ${requirement.id}: ${requirement.method} without a reason`).toBeGreaterThan(15);
        }
        // A gap may still name related controls: related_risk means they relate to the
        // requirement without any recipe verifying it. automated and manual, by contrast, must
        // name at least one control - a method with nothing behind it would be a fabrication.
        if (requirement.method === 'automated' || requirement.method === 'manual') {
          expect(requirement.controls.length > 0, `${id} ${requirement.id}: ${requirement.method} with no control behind it`).toBe(true);
        }
      }
    }
  });

  it('keeps every summary a written paraphrase, not a copy of the standard text', () => {
    // The ASVS licence check: no summary may reproduce the official requirement text verbatim.
    // The vendored CSV is the source of truth for what "verbatim" means here.
    const officialTexts = new Set(
      parseCsv(readFileSync(join(REPO, 'controls', 'mappings', 'data', 'asvs-5.0.0-en.csv'), 'utf8'))
        .map((columns) => String(columns[5] ?? '').trim().toLowerCase())
        .filter((text) => text.length > 0),
    );
    for (const requirement of MAPPINGS.get('asvs')?.requirements ?? []) {
      const summary = requirement.summary.trim().toLowerCase();
      // The official texts all start "verify that ..."; our paraphrases never do.
      expect(summary.startsWith('verify that'), `${requirement.id}: the summary reproduces the standard's phrasing`).toBe(false);
      expect(officialTexts.has(summary), `${requirement.id}: the summary is the standard's text verbatim`).toBe(false);
    }
  });
});

describe('ASVS 5.0.0: no unmapped id, no invalid chapter', () => {
  const csv = readFileSync(join(REPO, 'controls', 'mappings', 'data', 'asvs-5.0.0-en.csv'), 'utf8');
  const official = parseCsv(csv).map((columns) => ({
    chapterId: columns[0] as string,
    sectionId: columns[2] as string,
    reqId: columns[4] as string,
    level: columns[6] as string,
  }));

  it('maps every requirement id in the official CSV, exactly once', () => {
    const mapped = new Set(MAPPINGS.get('asvs')?.requirements.map((requirement) => requirement.id));
    const unmapped = official.filter((row) => !mapped.has(row.reqId)).map((row) => row.reqId);
    expect(unmapped, `unmapped ASVS ids: ${unmapped.slice(0, 5).join(', ')}…`).toEqual([]);
    expect(mapped.size).toBe(official.length);
  });

  it('uses valid chapter ids and correct levels for every entry', () => {
    const officialById = new Map(official.map((row) => [row.reqId, row]));
    const validChapters = new Set(official.map((row) => row.chapterId));
    for (const requirement of MAPPINGS.get('asvs')?.requirements ?? []) {
      const row = officialById.get(requirement.id);
      expect(row, `${requirement.id}: not in the official CSV`).toBeDefined();
      if (row === undefined) continue;
      expect(validChapters.has(row.chapterId), `${requirement.id}: invalid chapter ${row.chapterId}`).toBe(true);
      expect(requirement.section, `${requirement.id}`).toBe(row.sectionId);
      expect(requirement.chapter, `${requirement.id}`).toBe(row.chapterId);
      expect(requirement.level, `${requirement.id}`).toBe(Number.parseInt(row.level, 10));
    }
  });

  it('gives every Level 1 requirement a method - none is silently skipped', () => {
    const l1 = (MAPPINGS.get('asvs')?.requirements ?? []).filter((requirement) => requirement.level === 1);
    expect(l1).toHaveLength(70);
    for (const requirement of l1) {
      expect(['automated', 'manual', 'gap', 'not_applicable']).toContain(requirement.method);
      if (requirement.method === 'gap' || requirement.method === 'not_applicable') {
        expect((requirement.note ?? '').length).toBeGreaterThan(15);
      }
    }
  });
});

describe('OWASP Top 10 2025: all ten categories, exact 2025 names', () => {
  // The 2025 category names fetched from the published edition on 2026-10-10 (recorded in
  // upstream sources). A mapping that names anything else fails here.
  const NAMES_2025 = [
    'Broken Access Control',
    'Security Misconfiguration',
    'Software Supply Chain Failures',
    'Cryptographic Failures',
    'Injection',
    'Insecure Design',
    'Authentication Failures',
    'Software or Data Integrity Failures',
    'Security Logging and Alerting Failures',
    'Mishandling of Exceptional Conditions',
  ];

  it('maps exactly the ten published categories, by name', () => {
    const requirements = MAPPINGS.get('owasp-top-10')?.requirements ?? [];
    expect(requirements.map((requirement) => requirement.id)).toEqual(['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']);
    for (const requirement of requirements) {
      const name = requirement.summary.replace(' (2025 list, fetched from the published edition)', '');
      expect(NAMES_2025.includes(name), `${requirement.id}: '${name}' is not in the 2025 list`).toBe(true);
    }
    expect(new Set(requirements.map((requirement) => requirement.summary.replace(' (2025 list, fetched from the published edition)', ''))).size).toBe(10);
  });

  it('API Top 10 2023: maps API1 through API10', () => {
    const ids = (MAPPINGS.get('owasp-api-top-10')?.requirements ?? []).map((requirement) => requirement.id);
    expect(ids).toEqual(['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10']);
    const ssrf = MAPPINGS.get('owasp-api-top-10')?.requirements.find((requirement) => requirement.id === 'API7');
    expect(ssrf?.method).toBe('automated');
    expect(ssrf?.recipes).toContain('opengrep/rules');
  });
});

describe('SSDF and OSPS: tasks and requirements, with the consolidations visible', () => {
  it('maps the 42 active SSDF tasks and records the 5 consolidated ones as such', () => {
    const ssdf = MAPPINGS.get('nist-ssdf')?.requirements ?? [];
    const moved = ssdf.filter((requirement) => requirement.method === 'not_applicable');
    expect(moved.map((requirement) => requirement.id).sort()).toEqual(['PW.3.1', 'PW.3.2', 'PW.4.3', 'PW.4.5', 'PW.5.2']);
    for (const requirement of moved) {
      expect(requirement.note ?? '').toMatch(/[Cc]onsolidated|[Mm]oved/);
    }
    expect(ssdf.length - moved.length).toBe(42);
  });

  it('maps the OSPS requirements it fetched, with the retired id kept visible', () => {
    const osps = MAPPINGS.get('osps')?.requirements ?? [];
    expect(osps.length).toBeGreaterThanOrEqual(65);
    const retired = osps.find((requirement) => requirement.id === 'OSPS-BR-01.02');
    expect(retired?.method).toBe('not_applicable');
    expect(retired?.note ?? '').toContain('retired');
  });
});

describe('MCP Top 10 is link-only, with no adapted text', () => {
  it('records ids, category names, and links, and states the licence constraint', () => {
    const mcp = MAPPINGS.get('mcp-top-10')?.requirements ?? [];
    for (const requirement of mcp) {
      expect(requirement.url, `${requirement.id}: the link is the definition`).toBeTruthy();
      expect(requirement.summary.length).toBeLessThan(60);
      expect(requirement.note ?? '').toContain('forbids adapted text');
    }
    expect(mcp.map((requirement) => requirement.id)).toEqual(
      Array.from({ length: 10 }, (_, index) => `MCP${String(index + 1).padStart(2, '0')}`),
    );
  });
});
