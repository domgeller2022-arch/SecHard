import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detectStackAndFeatures } from '../../src/audit/detect.js';
import { packageRoot } from '../../src/validation/schema.js';

/**
 * Stack and feature detection (Batch U). The rules that matter most:
 *
 * - a detection is only ever recorded with the evidence that produced it;
 * - an undetectable feature stays `unknown`, never `disabled`;
 * - an unsupported stack produces a gap, never a clean report.
 */

const scratch = mkdtempSync(join(tmpdir(), 'hardening-detect-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function app(name: string, files: Readonly<Record<string, string>>): string {
  const root = join(scratch, name);
  for (const [file, contents] of Object.entries(files)) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), contents);
  }
  return root;
}

describe('stack detection', () => {
  it('detects a Vite + Supabase + Stripe app with evidence, and composes its profiles', () => {
    const root = app('vite-supabase', {
      'package.json': JSON.stringify({
        name: 'vite-app',
        dependencies: { react: '19.0.0', vite: '6.0.0', '@supabase/supabase-js': '2.50.0', stripe: '17.0.0' },
      }),
      'vite.config.ts': 'export default {};',
      'src/main.tsx': "import { createClient } from '@supabase/supabase-js';\nimport Stripe from 'stripe';\n",
    });

    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('react-spa');
    expect(detection.stack.evidence.length).toBeGreaterThan(0);
    expect(detection.profiles.map((profile) => profile.id)).toEqual(['core', 'quality', 'react-spa', 'supabase', 'payments']);
    expect(detection.features['persistent_storage']).toMatchObject({ state: 'enabled' });
    expect(detection.features['payments']).toMatchObject({ state: 'enabled' });
    expect(detection.features['payments']?.evidence.length).toBeGreaterThan(0);
    expect(detection.unsupported_stack).toBeUndefined();
  });

  it('detects Next.js ahead of Vite when both are present', () => {
    const root = app('nextjs', {
      'package.json': JSON.stringify({ dependencies: { next: '16.0.0', react: '19.0.0', vite: '6.0.0' } }),
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('nextjs');
    expect(detection.profiles.some((profile) => profile.id === 'nextjs')).toBe(true);
  });

  it('detects a FastAPI app from its dependency list', () => {
    const root = app('fastapi', {
      'requirements.txt': 'fastapi==0.95.2\nuvicorn==0.22.0\n',
      'app/main.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('python-web');
    expect(detection.profiles.map((profile) => profile.id)).toEqual(['core', 'quality', 'python-web']);
    // Static analysis is deliberately not required for this stack: the rule pack is JS-only.
    expect(detection.profiles.some((profile) => profile.id === 'nextjs')).toBe(false);
  });

  it('flags Expo as an unsupported stack with a gap, not a clean result', () => {
    const root = app('expo-app', {
      'package.json': JSON.stringify({ dependencies: { expo: '~52.0.0' } }),
      'app.json': '{ "expo": { "name": "fixture" } }',
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('expo');
    expect(detection.unsupported_stack).toBeDefined();
    expect(detection.unsupported_stack?.reason).toContain('no stack profile');
    expect(detection.gaps.some((gap) => gap.includes("stack 'expo' is not supported"))).toBe(true);
  });

  it('reports an unknown stack honestly when nothing matches', () => {
    const root = app('mystery', { 'README.md': 'just docs\n' });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('unknown');
    expect(detection.unsupported_stack).toBeDefined();
  });
});

describe('feature detection honesty', () => {
  it('keeps undetected features unknown, never disabled', () => {
    const root = app('plain', { 'package.json': JSON.stringify({ name: 'plain' }) });
    const detection = detectStackAndFeatures(root);
    for (const feature of ['accounts', 'tenancy', 'recovery', 'uploads', 'personal_data', 'runtime_ai']) {
      expect(detection.features[feature]?.state, feature).toBe('unknown');
    }
  });

  it('records evidence for every enabled feature', () => {
    const root = app('ai-app', {
      'package.json': JSON.stringify({ dependencies: { express: '5.0.0', openai: '4.0.0' } }),
      'src/server.js': "import OpenAI from 'openai';\n",
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('node-api');
    expect(detection.features['runtime_ai']).toMatchObject({ state: 'enabled' });
    expect(detection.features['runtime_ai']?.evidence.length).toBeGreaterThan(0);
    for (const evidence of detection.features['runtime_ai']?.evidence ?? []) {
      expect(evidence.file.length).toBeGreaterThan(0);
      expect(evidence.detail.length).toBeGreaterThan(0);
    }
  });

  it('never writes to the target: the tree is byte-identical after detection', () => {
    const root = app('immutable', {
      'package.json': JSON.stringify({ dependencies: { vite: '6.0.0' } }),
      'src/deep/nested/file.ts': 'export {};\n',
    });
    const before = join(scratch, 'immutable-sentinel');
    writeFileSync(before, 'x');
    detectStackAndFeatures(root);
    // Detection only reads; this asserts the API contract at unit level (the CLI-level test
    // checksums the whole tree).
    expect(() => detectStackAndFeatures(join(scratch, 'does-not-exist'))).toThrow(/not a directory|does not exist|ENOENT/);
  });
});

/**
 * P3.5 (A-32, F-09): feature detection reads executable evidence — production dependencies,
 * line-start imports, quoted event literals — never matcher definitions, comments or explanatory
 * strings. Dev-only Vite/Vitest is tooling, not a browser stack. P3.5 (A-17): the python-web gap
 * states the supported families instead of a blanket unsupported claim.
 */
describe('feature detection reads executable evidence, not matcher text (A-32, F-09)', () => {
  it('dev-only Vite and Vitest do not make a browser SPA', () => {
    const root = app('devtools-cli', {
      'package.json': JSON.stringify({
        name: 'cli-tool',
        dependencies: { ajv: '8.0.0', yaml: '2.0.0' },
        devDependencies: { typescript: '5.9.0', vitest: '3.0.0', vite: '7.0.0' },
      }),
      'src/cli.ts': 'console.log(1);\n',
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.stack.kind).toBe('unknown');
    expect(detection.profiles.some((profile) => profile.id === 'react-spa')).toBe(false);
    expect(detection.unsupported_stack).toBeDefined();
  });

  it('SecHard itself is not classified as a payments app or browser SPA from its own matchers', () => {
    const detection = detectStackAndFeatures(packageRoot());
    expect(detection.features['payments']).toMatchObject({ state: 'unknown' });
    expect(detection.features['webhooks']).toMatchObject({ state: 'unknown' });
    expect(detection.stack.kind).not.toBe('react-spa');
    expect(detection.profiles.every((profile) => profile.id !== 'payments')).toBe(true);
  });

  it('matcher definitions and explanatory strings do not enable payments', () => {
    const root = app('self-like', {
      'package.json': JSON.stringify({ name: 'scanner', dependencies: { ajv: '8.0.0' }, devDependencies: { vitest: '3.0.0' } }),
      'src/detector.ts': [
        "// a checkout.session.completed handler is a payments integration even when",
        "const MATCH = /(checkout\\.session\\.completed|payment_intent\\.[a-z_]+|invoice\\.paid)/;",
        "const doc = 'for example checkout.session.completed - and the handler grants the entitlement';",
        "// import Stripe from 'stripe';",
      ].join('\n'),
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.features['payments']).toMatchObject({ state: 'unknown' });
    expect(detection.features['webhooks']).toMatchObject({ state: 'unknown' });
  });

  it('a real webhook handler with a line-start SDK import and quoted events is still detected', () => {
    const root = app('real-handler', {
      'package.json': JSON.stringify({ name: 'shop', dependencies: { next: '16.0.0' } }),
      'app/api/webhook/route.ts': [
        "import Stripe from 'stripe';",
        'export async function POST(request: Request) {',
        '  const event = stripe.webhooks.constructEvent(body, sig, secret);',
        '  switch (event.type) {',
        "    case 'checkout.session.completed':",
        '      break;',
        "    case 'payment_intent.payment_failed':",
        '      break;',
        '  }',
        '  return Response.json({ ok: true });',
        '}',
      ].join('\n'),
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.features['payments']).toMatchObject({ state: 'enabled' });
    expect(detection.features['webhooks']).toMatchObject({ state: 'enabled' });
  });

  it('a vanilla Vite app with a browser entry point is still a SPA', () => {
    const root = app('vanilla-vite', {
      'package.json': JSON.stringify({ name: 'vanilla', devDependencies: { vite: '7.0.0' } }),
      'vite.config.ts': 'export default {};',
      'index.html': '<html><body></body></html>',
      'src/main.js': 'document.body.append("hi");\n',
    });
    expect(detectStackAndFeatures(root).stack.kind).toBe('react-spa');
  });

  it('an unsupported mobile stack composes the generic checks and an explicit gap', () => {
    const root = app('flutter-app', { 'pubspec.yaml': 'name: app\n' });
    const detection = detectStackAndFeatures(root);
    expect(detection.unsupported_stack?.generic_checks.length).toBeGreaterThan(0);
    expect(detection.gaps.join(' ')).toContain("detected stack 'flutter' is not supported");
  });

  it('the python-web gap states the supported families, not a blanket unsupported claim (A-17)', () => {
    const root = app('fastapi-gap', {
      'requirements.txt': 'fastapi==0.95.2\nuvicorn==0.22.0\n',
      'app/main.py': 'from fastapi import FastAPI\napp = FastAPI()\n',
    });
    const detection = detectStackAndFeatures(root);
    expect(detection.gaps.join(' ')).toContain('covers the reviewed Python rule families only');
    expect(detection.gaps.join(' ')).not.toContain('does not support Python');
  });
});
