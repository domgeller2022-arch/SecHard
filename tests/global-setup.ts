import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Prepares the artifacts the suite actually exercises, before any test runs.
 *
 * Two things must be current or the results are meaningless:
 *
 * 1. The consumer fixtures, because the fixture's `policy_lock.commit` must equal the policy root's
 *    actual commit, and that commit moves every time this repository is committed.
 * 2. The compiled CLI in `dist/`, because the CLI and integration tests run the real binary as a
 *    separate process. Without this, a stale `dist/` makes the suite report on code that is not the
 *    code in the working tree — the exact class of misleading result this repository exists to stop.
 */
export default function setup(): void {
  const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

  execFileSync(process.execPath, [join(repo, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.build.json'], {
    cwd: repo,
    stdio: 'ignore',
    timeout: 180_000,
  });

  execFileSync(process.execPath, [join(repo, 'tools', 'build-fixtures.ts')], {
    cwd: repo,
    stdio: 'ignore',
    timeout: 60_000,
  });
}
