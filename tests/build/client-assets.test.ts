import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { DEFAULT_MARKERS, inspectBrowserAssets } from '../../src/build/client-assets.js';
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
