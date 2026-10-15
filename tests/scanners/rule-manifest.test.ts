import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { CASES } from './rule-twin-cases.js';

/**
 * The rule manifest (P3.2, A-15/A-16) must stay in lockstep with the packs it describes: every
 * rule in the three packs has exactly one entry, every entry is complete, and every twin anchor
 * names a real case in the rule-twins CLI regression. Without this sync the matrix rots and any
 * "all rules verified" claim becomes unearned.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const RULES_DIR = join(REPO, 'ci', 'configs', 'opengrep-rules');
const PACKS = ['hardening-core.yaml', 'detection-depth.yaml', 'quality-errors.yaml'] as const;

interface ManifestEntry {
  readonly id: string;
  readonly pack: string;
  readonly languages: readonly string[];
  readonly grade: string;
  readonly confidence: string;
  readonly limitations: string;
  readonly twins?: { readonly fires?: readonly string[]; readonly silent?: readonly string[] };
}

const packRuleIds = new Map<string, Set<string>>(
  PACKS.map((pack) => {
    const parsed = parseYaml(readFileSync(join(RULES_DIR, pack), 'utf8')) as { rules: { id: string }[] };
    return [pack, new Set(parsed.rules.map((rule) => rule.id))];
  }),
);

const manifest = parseYaml(readFileSync(join(RULES_DIR, 'manifest.yaml'), 'utf8')) as { rules: ManifestEntry[] };

const allPackIds = new Set([...packRuleIds.values()].flatMap((ids) => [...ids]));
const manifestById = new Map(manifest.rules.map((entry) => [entry.id, entry]));
const caseNames = new Set(CASES.map((tw) => tw.name));

describe('the rule manifest stays in lockstep with the packs, the twins, and itself', () => {
  it('every rule in the three packs has exactly one manifest entry', () => {
    const missing = [...allPackIds].filter((id) => !manifestById.has(id));
    const stale = [...manifestById.keys()].filter((id) => !allPackIds.has(id));
    expect({ missing, stale }, 'manifest/pack divergence').toEqual({ missing: [], stale: [] });
  });

  it('every entry is complete and anchored to its own pack', () => {
    for (const entry of manifest.rules) {
      expect(entry.pack, entry.id).toBeOneOf([...PACKS]);
      expect(packRuleIds.get(entry.pack)?.has(entry.id), `${entry.id} belongs to ${entry.pack}`).toBe(true);
      expect(entry.languages.length, `${entry.id} languages`).toBeGreaterThan(0);
      expect(entry.grade, `${entry.id} grade`).toBeTypeOf('string');
      expect(entry.confidence, `${entry.id} confidence`).toBeTypeOf('string');
      expect(entry.limitations.length, `${entry.id} limitations`).toBeGreaterThan(10);
    }
  });

  it('every twin anchor names a real case, and every case is anchored in the manifest', () => {
    const anchored = new Set<string>();
    for (const entry of manifest.rules) {
      for (const name of [...(entry.twins?.fires ?? []), ...(entry.twins?.silent ?? [])]) {
        anchored.add(name);
        expect(caseNames.has(name), `${entry.id} anchors ${name}, which no twin case defines`).toBe(true);
      }
    }
    for (const twin of CASES) {
      const entry = manifestById.get(twin.rule);
      expect(entry, `twin case ${twin.name} references unmanifested rule ${twin.rule}`).toBeDefined();
      const names = [...(entry?.twins?.fires ?? []), ...(entry?.twins?.silent ?? [])];
      expect(names.includes(twin.name), `case ${twin.name} is not anchored by ${String(twin.rule)}`).toBe(true);
    }
    expect(anchored.size).toBe(CASES.length);
  });

  it('every rule marked by a twin case records its safe twin where one exists', () => {
    const firesWithoutSilent = CASES.filter((tw) => tw.expect === 'fires').filter((tw) => {
      const entry = manifestById.get(tw.rule);
      return entry !== undefined && (entry.twins?.silent ?? []).length === 0;
    });
    // Every fires-anchor in this matrix currently has its safe twin; a new fires case without a
    // silent twin must either add the twin or extend this list with the reason.
    expect(firesWithoutSilent.map((tw) => tw.rule), 'fires without a silent twin').toEqual([]);
  });
});
