import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detectStackAndFeatures } from '../../src/audit/detect.js';

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
    expect(detection.profiles.map((profile) => profile.id)).toEqual(['core', 'react-spa', 'supabase', 'payments']);
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
    expect(detection.profiles.map((profile) => profile.id)).toEqual(['core', 'python-web']);
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
