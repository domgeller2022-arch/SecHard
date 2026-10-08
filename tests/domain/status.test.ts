import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';

/**
 * R6.2: the status document is generated from the progress record so it cannot drift. If the record
 * changed and the document did not, this fails instead of the two quietly disagreeing.
 */
describe('the generated status document cannot drift', () => {
  it('docs/status.md matches a fresh generation from docs/implementation-progress.md', () => {
    const stdout = execFileSync(process.execPath, [join(packageRoot(), 'tools', 'generate-status.mjs'), '--check'], {
      cwd: packageRoot(),
      encoding: 'utf8',
    });
    expect(stdout).toContain('current');
  });
});
