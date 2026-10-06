import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Rebuilds the consumer fixtures before any test runs.
 *
 * The fixture's `policy_lock.commit` must equal the policy root's actual commit, and that commit
 * moves every time this repository is committed. Regenerating here keeps the fixture honest instead
 * of letting a stale pin make the CLI tests fail for the wrong reason.
 */
export default function setup(): void {
  const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
  execFileSync(process.execPath, [join(repo, 'tools', 'build-fixtures.ts')], {
    cwd: repo,
    stdio: 'ignore',
    timeout: 60_000,
  });
}
