import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { inspectBrowserAssets, inventoryDigest } from '../../src/build/client-assets.js';
import { packageRoot } from '../../src/validation/schema.js';

/**
 * The real application build, inspected rather than the synthetic fixtures.
 *
 * This suite needs `pnpm --dir examples/nextjs-supabase run build` first, so it lives outside the
 * default `test` script: the unit suite must have no external preconditions, and a missing artifact
 * here is a loud failure rather than a skipped test.
 */

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
