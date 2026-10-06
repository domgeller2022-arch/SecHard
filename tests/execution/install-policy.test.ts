import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { loadDependencyPolicy } from '../../src/execution/policy.js';
import { packageRoot } from '../../src/validation/schema.js';

/**
 * The install-script policy for this repository itself.
 *
 * The enforcing mechanism is pnpm's `allowBuilds` with default deny, which **fails the install** on
 * an unapproved hook rather than skipping it quietly. That behaviour was verified against pnpm
 * 12.9.1 and recorded in `policy/toolchain.yaml`.
 *
 * `.npmrc`'s `ignore-scripts=true` is deliberately NOT relied on: pnpm 12 ignores it. It is kept
 * only so a stray `npm install` behaves safely, and this test asserts that it is not the control.
 *
 * A future dependency that adds a real install-time hook must be reviewed and either allowed or
 * explicitly denied in `pnpm-workspace.yaml`. Until someone does that, `pnpm install` fails — which
 * is the intended outcome, not an inconvenience.
 */

const INSTALL_TIME_HOOKS = ['preinstall', 'install', 'postinstall'] as const;

interface PackageManifest {
  readonly scripts?: Record<string, string>;
}

function readManifest(file: string): PackageManifest | undefined {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as PackageManifest;
  } catch {
    return undefined;
  }
}

describe('dependency install scripts are denied unless reviewed', () => {
  it('declares an empty reviewed allowlist in pnpm-workspace.yaml', () => {
    const workspace = parse(readFileSync(join(packageRoot(), 'pnpm-workspace.yaml'), 'utf8')) as {
      allowBuilds?: Record<string, boolean>;
    };
    expect(workspace.allowBuilds).toBeDefined();
    expect(Object.keys(workspace.allowBuilds ?? {})).toEqual([]);
  });

  it('enforces the seven-day release-age delay in pnpm-workspace.yaml', () => {
    const workspace = parse(readFileSync(join(packageRoot(), 'pnpm-workspace.yaml'), 'utf8')) as {
      minimumReleaseAge?: number;
    };
    // pnpm 12 reads pnpm settings from this file, not .npmrc. The units are minutes.
    expect(workspace.minimumReleaseAge).toBe(10080);
  });

  it('agrees with the dependency policy', () => {
    const policy = loadDependencyPolicy(join(packageRoot(), 'policy', 'dependency-policy.yaml')).policy;
    expect(policy?.install_scripts.default).toBe('disabled');
    expect(policy?.install_scripts.allowed_hooks).toEqual([]);
    expect(policy?.minimum_release_age_minutes).toBe(10080);
  });

  it('does not rely on .npmrc for the pnpm install-script control', () => {
    const npmrc = readFileSync(join(packageRoot(), '.npmrc'), 'utf8');
    // The key is present for npm's benefit and the file says so; pnpm ignores it.
    expect(npmrc).toMatch(/^ignore-scripts=true$/m);
    // The file must state that it is not the enforcing mechanism, so a reader is not misled.
    expect(npmrc).toMatch(/pnpm 12\.9\.1 does NOT/);
    expect(npmrc).toMatch(/NOT the\s+#?\s*mechanism|NOT the mechanism/);
  });

  it('has no direct dependency that needs an install-time hook', () => {
    const manifest = readManifest(join(packageRoot(), 'package.json')) as unknown as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const direct = [...Object.keys(manifest.dependencies ?? {}), ...Object.keys(manifest.devDependencies ?? {})];

    const hooks: string[] = [];
    for (const name of direct) {
      const dependency = readManifest(join(packageRoot(), 'node_modules', name, 'package.json'));
      const scripts = dependency?.scripts ?? {};
      for (const hook of INSTALL_TIME_HOOKS) {
        if (scripts[hook] !== undefined) hooks.push(`${name}:${hook}`);
      }
    }

    // `prepublish`/`prepare` are deliberately excluded: they do not run for a registry dependency at
    // install time. Only preinstall/install/postinstall execute during installation.
    expect(hooks, `review the hook and record a decision in pnpm-workspace.yaml allowBuilds: ${hooks.join(', ')}`).toEqual([]);
  });
});
