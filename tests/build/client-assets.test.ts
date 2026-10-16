import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { DEFAULT_MARKERS, browserOutputCandidates, inspectBrowserAssets, inventoryDigest, selectBrowserOutput } from '../../src/build/client-assets.js';
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

/**
 * H5 regression from the 2026-10-08 audit: the original marker set missed the commonest real leaks.
 * The probe values are synthetic and functional for no provider; they exist to prove detection.
 */
describe('the extended marker set catches the commonest real leaks', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'hardening-client-assets-'));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  const jwt = (payload: Record<string, unknown>): string => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.${'x'.repeat(20)}`;

  it('flags an OpenAI, Anthropic, Stripe, and legacy service-role JWT value', () => {
    const dir = join(scratch, 'leaks');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'bundle.js'),
      [
        `const openai = "${['sk', 'proj', 'A'.repeat(40)].join('-')}";`,
        `const anthropic = "${['sk', 'ant', 'B'.repeat(40)].join('-')}";`,
        `const stripe = "sk_live_${'C'.repeat(24)}";`,
        `const legacy = "${jwt({ role: 'service_role', iss: 'supabase' })}";`,
      ].join('\n'),
    );

    const report = inspectBrowserAssets(dir);
    const rules = report.findings.map((finding) => finding.rule_id);
    expect(rules).toContain('openai-key');
    expect(rules).toContain('anthropic-key');
    expect(rules).toContain('stripe-live-key');
    expect(rules).toContain('jwt-privileged-role');
    expect(report.coverage).toBe('complete');
  });

  it('classifies an anon-role JWT as intended-public instead of flagging it', () => {
    const dir = join(scratch, 'anon');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'bundle.js'), `const key = "${jwt({ role: 'anon', iss: 'supabase' })}";`);

    const report = inspectBrowserAssets(dir);
    expect(report.findings).toEqual([]);
    expect(report.classifications.map((entry) => entry.marker)).toContain('jwt-role-publishable');
  });
});

/**
 * P3.4 (A-21): a shipped source map is secret-inspected with the same blocking class as a bundle
 * — its raw text includes any embedded sourcesContent — and a malformed or oversized map is an
 * explicit incompleteness, never a silent pass.
 */
describe('the inspection covers shipped source maps (A-21)', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'hardening-client-assets-maps-'));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  it('a privileged secret only inside a shipped map fires with the same blocking class as a bundle', () => {
    const dir = join(scratch, 'map-secret');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'app.js.map'),
      JSON.stringify({ version: 3, sources: ['../src/config.ts'], sourcesContent: ['const serviceKey = "sb_secret_MAPONLYLEAKVALUE1";'] }),
    );

    const report = inspectBrowserAssets(dir);
    const mapFindings = report.findings.filter((finding) => finding.location?.endsWith('.map') === true);
    expect(mapFindings.map((finding) => finding.rule_id)).toContain('supabase-secret-key');
    expect(mapFindings.find((finding) => finding.rule_id === 'supabase-secret-key')?.severity).toBe('critical');
    // The publication warning stays a separate, weaker finding.
    expect(report.findings.some((finding) => finding.rule_id === 'browser-source-map')).toBe(true);
    expect(report.coverage).toBe('complete');
    expect(JSON.stringify(report)).not.toContain('sb_secret_MAPONLYLEAKVALUE1');
  });

  it('map findings carry a match digest and never the matched value', () => {
    const dir = join(scratch, 'map-digest');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'app.js.map'),
      JSON.stringify({ version: 3, sourcesContent: ['const key = "sb_secret_DIGESTEDLEAKVALUE";'] }),
    );

    const report = inspectBrowserAssets(dir);
    const secretFinding = report.findings.find((finding) => finding.rule_id === 'supabase-secret-key');
    expect(secretFinding?.secret_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(report)).not.toContain('sb_secret_DIGESTEDLEAKVALUE');
  });

  it('a publishable key inside a map is classified, not flagged', () => {
    const dir = join(scratch, 'map-publishable');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'app.js.map'),
      JSON.stringify({ version: 3, sourcesContent: ['const key = "sb_publishable_MAPVALUE12345";'] }),
    );

    const report = inspectBrowserAssets(dir);
    expect(report.findings.every((finding) => finding.rule_id === 'browser-source-map')).toBe(true);
    expect(report.classifications.map((entry) => entry.marker)).toContain('supabase-publishable-key');
  });

  it('a malformed map is an explicit incompleteness, and its raw text is still scanned', () => {
    const dir = join(scratch, 'map-broken');
    mkdirSync(dir, { recursive: true });
    // Deliberately invalid JSON whose raw text still carries a privileged value.
    writeFileSync(join(dir, 'broken.js.map'), '{"version":3,"sourcesContent":["const k = "sb_secret_BROKENMAPLEAK1";"]}');

    const report = inspectBrowserAssets(dir);
    expect(report.parseErrors.join(' ')).toContain('not valid JSON');
    expect(report.findings.map((finding) => finding.rule_id)).toContain('supabase-secret-key');
    expect(report.coverage).toBe('partial');
  });

  it('an oversized map is recorded, not read, and the coverage is explicitly partial', () => {
    const dir = join(scratch, 'map-oversized');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'big.js.map'), `{"version":3,${'"padding":'.padEnd(120, 'x')}}`);

    const report = inspectBrowserAssets(dir, { maxTextFileBytes: 32 });
    expect(report.sourceMaps).toContain('big.js.map');
    expect(report.parseErrors.join(' ')).toContain('was not read as text');
    expect(report.findings.some((finding) => finding.rule_id === 'browser-source-map')).toBe(true);
    expect(report.coverage).toBe('partial');
  });
});

describe('the inventory digest distinguishes same-size edits', () => {
  it('rewriting a file with the same byte length changes the digest', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hardening-client-assets-digest-'));
    writeFileSync(join(dir, 'bundle.js'), 'const a = "aaaa";');
    const before = inventoryDigest(inspectBrowserAssets(dir));
    writeFileSync(join(dir, 'bundle.js'), 'const a = "bbbb";');
    const after = inventoryDigest(inspectBrowserAssets(dir));
    expect(before).not.toBe(after);
    rmSync(dir, { recursive: true, force: true });
  });
});

/**
 * P3.4 (A-32): browser output follows the detected stack's reviewed build shape. A Node CLI's
 * compiled `dist` is server output and is never scanned as browser-shipped merely because the
 * directory exists.
 */
describe('browser-output selection follows the detected stack (A-32)', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'hardening-browser-output-'));
  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  it('a Node CLI stack has no browser-output candidates at all', () => {
    expect(browserOutputCandidates('node-api')).toEqual([]);
    const dir = join(scratch, 'cli');
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(join(dir, 'dist', 'cli.js'), 'console.log(1);');
    const selection = selectBrowserOutput(dir, 'node-api');
    expect('unsupported' in selection && selection.unsupported.includes('node-api')).toBe(true);
  });

  it('a dist without a browser entry point is not browser-shipped even for a vite-flagged stack', () => {
    const dir = join(scratch, 'cli-vite');
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(join(dir, 'dist', 'cli.js'), 'console.log(1);');
    const selection = selectBrowserOutput(dir, 'react-spa');
    expect('unsupported' in selection && selection.unsupported.includes('no browser entry point')).toBe(true);
  });

  it('a dist with an index.html is selected for a browser stack', () => {
    const dir = join(scratch, 'spa');
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(join(dir, 'dist', 'index.html'), '<html></html>');
    writeFileSync(join(dir, 'dist', 'app.js'), 'export {};');
    const selection = selectBrowserOutput(dir, 'react-spa');
    expect('root' in selection && selection.root.endsWith('dist')).toBe(true);
  });

  it('the nextjs static dir is trusted by framework without an entry point', () => {
    const dir = join(scratch, 'next');
    mkdirSync(join(dir, '.next', 'static'), { recursive: true });
    writeFileSync(join(dir, '.next', 'static', 'chunk.js'), 'export {};');
    const selection = selectBrowserOutput(dir, 'nextjs');
    expect('root' in selection && selection.root.includes('.next/static')).toBe(true);
  });
});
