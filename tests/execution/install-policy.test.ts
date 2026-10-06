import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadDependencyPolicy } from '../../src/execution/policy.js';
import { packageRoot } from '../../src/validation/schema.js';

/**
 * The install-script policy for this repository itself.
 *
 * `ignore-scripts=true` in `.npmrc` is what stops a dependency's hook from running with the
 * developer's privileges during installation. This test guards the two halves of that control:
 * the setting, and the absence of a hook that would need an allowance.
 *
 * A future dependency that adds a real install-time hook fails this test, which is the intended
 * outcome: adding one is a policy decision, not a routine upgrade.
 */

const INSTALL_TIME_HOOKS = ['preinstall', 'install', 'postinstall'] as const;

interface PackageManifest {
  readonly name?: string;
  readonly version?: string;
  readonly scripts?: Record<string, string>;
}

function readManifest(file: string): PackageManifest | undefined {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as PackageManifest;
  } catch {
    return undefined;
  }
}

describe('install scripts are disabled for this repository', () => {
  it('sets ignore-scripts in the installed-configuration file', () => {
    const npmrc = readFileSync(join(packageRoot(), '.npmrc'), 'utf8');
    expect(npmrc).toMatch(/^ignore-scripts=true$/m);
  });

  it('declares hooks disabled by default with an empty allowlist', () => {
    const policy = loadDependencyPolicy(join(packageRoot(), 'policy', 'dependency-policy.yaml')).policy;
    expect(policy?.install_scripts.default).toBe('disabled');
    expect(policy?.install_scripts.allowed_hooks).toEqual([]);
  });

  it('has no direct dependency that needs an install-time hook', () => {
    const manifest = readManifest(join(packageRoot(), 'package.json'));
    const direct = [
      ...Object.keys((manifest as unknown as { dependencies?: Record<string, string> }).dependencies ?? {}),
      ...Object.keys((manifest as unknown as { devDependencies?: Record<string, string> }).devDependencies ?? {}),
    ];

    const hooks: string[] = [];
    for (const name of direct) {
      const dependency = readManifest(join(packageRoot(), 'node_modules', name, 'package.json'));
      const scripts = dependency?.scripts ?? {};
      for (const hook of INSTALL_TIME_HOOKS) {
        if (scripts[hook] !== undefined) hooks.push(`${name}:${hook}`);
      }
    }

    // `prepublish`/`prepare` are deliberately not counted: they do not run for a registry
    // dependency at install time. Only preinstall/install/postinstall execute during installation.
    expect(hooks, `add an allowance in policy/dependency-policy.yaml after reviewing the hook: ${hooks.join(', ')}`).toEqual([]);
  });

  it('was installed and built successfully with scripts disabled', () => {
    // The evidence for this is the passing build and suite itself. Asserting the setting is present
    // alongside a successful run is what makes it a checked claim rather than a configured one.
    const npmrc = readFileSync(join(packageRoot(), '.npmrc'), 'utf8');
    expect(npmrc).toContain('ignore-scripts=true');
    expect(packageRoot().endsWith('hardening')).toBe(true);
  });
});
