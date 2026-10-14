import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterAll, describe, expect, it } from 'vitest';
import { resolveSourceIdentity } from '../../src/commands/io.js';
import { buildChangeReport } from '../../src/agent/change-report.js';
import { gitConfigEnv, gitHardeningArgs, diffSafetyArgs } from '../../src/execution/git-hardening.js';

// A-01 counterexample (Batch R1): a repository's own .git/config can execute code during
// read-only inspection. The fixture config points core.fsmonitor and diff.external at a marker
// script; if any Git path in SecHard runs unhardened, the marker file appears.

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function markerRepo(name: string): { root: string; marker: string } {
  const root = mkdtempSync(join(tmpdir(), `sechard-git-hardening-${name}-`));
  roots.push(root);
  const marker = join(root, 'helper-ran.txt');
  const helper = join(root, 'helper.sh');
  writeFileSync(helper, `#!/bin/sh\necho ran >> "${marker}"\n`);
  chmodSync(helper, 0o755);
  const git = (...args: string[]): void => {
    execFileSync('git', args, { cwd: root, env: { PATH: process.env['PATH'] ?? '' } });
  };
  git('init', '-q');
  git('config', 'user.email', 'fixture@example.invalid');
  git('config', 'user.name', 'fixture');
  mkdirSync(join(root, 'tests'), { recursive: true });
  writeFileSync(join(root, 'tests', 'sample.test.ts'), 'test("a", () => { expect(actual).toBe(expected); });\n');
  git('add', '-A');
  git('commit', '-qm', 'base');
  writeFileSync(join(root, 'tests', 'sample.test.ts'), 'test("a", () => { expect(actual).toBe(updated); });\n');
  git('add', '-A');
  git('commit', '-qm', 'change an assertion');
  // The hostile configuration, appended like a cloned repository's would be. diff.external is
  // the live executable channel on this Git (2.55 rejects core.fsmonitor=<path> at parse time —
  // the runner still disables fsmonitor for older parsers); an unhardened diff runs the helper.
  // The hostile configuration is written with `git config` (valid on every Git version,
  // including the pathname fsmonitor vector on Git 2.55 — the earlier claim that 2.55 rejected it
  // was wrong): a fsmonitor hook and a diff.external helper, both pointing at the marker script.
  git('config', 'core.fsmonitor', helper);
  git('config', 'diff.external', helper);
  return { root, marker };
}

describe('A-01: repository Git configuration cannot execute helpers during inspection', () => {
  it('source identity runs hardened and still detects the tree', () => {
    const { root, marker } = markerRepo('identity');
    const identity = resolveSourceIdentity(root);
    expect(existsSync(marker), 'a Git helper executed during source identity').toBe(false);
    // The hardened call still produces a real identity for a clean git repo.
    expect(identity).toBeDefined();
  });

  it('the change report runs hardened and keeps the ordinary patch content', () => {
    const { root, marker } = markerRepo('report');
    // Fixture validity: an UNHARDENED patch-producing diff runs the helper (the counterexample is
    // real on this Git). --name-status alone never invokes it, so use the patch form.
    // The helper writes the marker and outputs no patch, so git exits nonzero; the marker is the point.
    try {
      execFileSync('git', ['diff', 'HEAD~1...HEAD'], { cwd: root, stdio: 'ignore' });
    } catch {
      // expected: the external helper is not a real diff driver
    }
    expect(existsSync(marker), 'fixture invalid: the diff helper did not run unhardened').toBe(true);
    rmSync(marker);
    const report = buildChangeReport({ base: 'HEAD~1', head: 'HEAD', cwd: root });
    expect(existsSync(marker), 'the diff helper executed during the change report').toBe(false);
    // PR-01: helper hardening must not hide real changes — the removed-assertion finding proves
    // patch analysis survived, not merely that a filename appeared.
    expect(report.filesChanged).toBeGreaterThan(0);
    expect(JSON.stringify(report)).toContain('sample.test.ts');
    expect(JSON.stringify(report).toLowerCase()).toContain('remov');
  });

  it('the hardening channel for scanner-owned Git children is set from the environment', () => {
    const env = gitConfigEnv();
    expect(env['GIT_CONFIG_COUNT']).toBe('2');
    expect(env['GIT_CONFIG_KEY_0']).toBe('core.fsmonitor');
    expect(env['GIT_CONFIG_VALUE_0']).toBe('false');
    expect(env['GIT_CONFIG_KEY_1']).toBe('core.hooksPath');
    expect(gitHardeningArgs()).toEqual(['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/nonexistent-sechard-hardened-hooks']);
    expect(diffSafetyArgs()).toEqual(['--no-ext-diff', '--no-textconv']);
  });
});
