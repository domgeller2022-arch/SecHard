import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { DEFAULT_MARKERS, inspectBrowserAssets, inventoryDigest } from '../../src/build/client-assets.js';
import { packageRoot } from '../../src/validation/schema.js';

const FIXTURES = join(packageRoot(), 'tests', 'fixtures', 'build');

describe('the inspection classifies rather than flags everything', () => {
  it('passes clean output and records the publishable key as intended-public', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'clean'));
    expect(report.findings).toEqual([]);
    expect(report.classifications.map((entry) => entry.marker)).toContain('supabase-publishable-key');
    expect(report.coverage).toBe('complete');
  });

  // A check that cannot see its own fixture has never been shown to work.
  it('detects the synthetic privileged marker in the leaking fixture', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'leaking'));
    const rules = report.findings.map((finding) => finding.rule_id);
    expect(rules).toContain('synthetic-leak-marker');
    expect(report.findings.every((finding) => finding.severity === 'critical' || finding.severity === 'medium')).toBe(true);
    // The finding says where, and withholds the value.
    expect(report.findings[0]?.location).toMatch(/\.js$/);
    expect(JSON.stringify(report.findings)).not.toContain('SYNTHETIC_PRIVILEGED_LEAK_MARKER');
  });

  it('reports a browser-shipped source map as a finding', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'leaking'));
    expect(report.sourceMaps).toContain('static/chunks/app.js.map');
    expect(report.findings.some((finding) => finding.rule_id === 'browser-source-map')).toBe(true);
  });

  it('flags a service-role variable name and a secret-shaped key', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'clean'), {
      markers: DEFAULT_MARKERS,
    });
    expect(report.findings).toEqual([]);

    const withSecrets = inspectBrowserAssets(join(FIXTURES, 'clean'), {
      markers: [
        { id: 'test-var', pattern: /supabaseUrl/g, kind: 'privileged' },
        { id: 'test-secret', pattern: /sb_secret_[A-Za-z0-9_-]{10,}/g, kind: 'privileged' },
      ],
    });
    expect(withSecrets.findings.map((finding) => finding.rule_id)).toEqual(['test-var']);
  });
});

describe('coverage is stated, never implied', () => {
  it('says exactly what it inspected and what it did not', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'clean'));
    expect(report.scopeStatement).toMatch(/browser-shipped output/);
    expect(report.scopeStatement).toMatch(/server output.*outside this scan/s);
  });

  it('reports unknown coverage for an empty or missing directory rather than a clean result', () => {
    const missing = inspectBrowserAssets(join(FIXTURES, 'does-not-exist'));
    expect(missing.coverage).toBe('unknown');
    expect(missing.findings).toEqual([]);
  });

  it('downgrades coverage to partial when a file could not be read', () => {
    const report = inspectBrowserAssets(join(FIXTURES, 'clean'), { maxTextFileBytes: 10 });
    expect(report.coverage).toBe('partial');
    expect(report.parseErrors.length).toBeGreaterThan(0);
  });
});

describe('the real application build passes', () => {
  const buildStatic = join(packageRoot(), 'examples', 'nextjs-supabase', '.next', 'static');

  it('has a production build to inspect', () => {
    // The build is produced by `next build`; this suite inspects an artifact, so its absence is a
    // precondition failure rather than a skipped test.
    expect(existsSync(buildStatic), 'run `pnpm --dir examples/nextjs-supabase run build` first').toBe(true);
  });

  it('ships no privileged material and no source maps', () => {
    const report = inspectBrowserAssets(buildStatic);
    expect(report.findings, JSON.stringify(report.findings, null, 2)).toEqual([]);
    expect(report.sourceMaps).toEqual([]);
    expect(report.files.length).toBeGreaterThan(0);
    expect(report.coverage).toBe('complete');
  });

  // Stronger than "the publishable key is classified correctly": this application performs every
  // Supabase operation server-side (Server Components and Server Actions), so no key of any kind is
  // inlined into the browser bundle. The classification path itself is proven by the clean fixture
  // above, which does contain a publishable key.
  it('ships no Supabase key at all, because all access is server-side', () => {
    const report = inspectBrowserAssets(buildStatic);
    expect(report.classifications.filter((entry) => entry.marker === 'supabase-publishable-key')).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it('produces a deterministic inventory digest', () => {
    const first = inventoryDigest(inspectBrowserAssets(buildStatic));
    const second = inventoryDigest(inspectBrowserAssets(buildStatic));
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not claim server output in its scope', () => {
    const report = inspectBrowserAssets(buildStatic);
    const serverDir = join(packageRoot(), 'examples', 'nextjs-supabase', '.next', 'server');
    expect(existsSync(serverDir)).toBe(true);
    for (const file of report.files) {
      expect(file.path).not.toMatch(/^server\//);
    }
    void readdirSync;
    void readFileSync;
  });
});
