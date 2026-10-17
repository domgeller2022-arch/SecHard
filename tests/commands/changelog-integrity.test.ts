import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';

// P0.1: the changelog hash is recorded and protected. The audited bytes (858bb9cf…) were
// superseded on 15 October by the owner's explicit instruction to record the programme state
// here (decision p0_d_02 in docs/completion-ledger.yaml). Changing this constant again requires
// the same explicit owner instruction in the same change.
const IMMUTABLE_CHANGELOG_SHA256 = '18a37123aeba715d607318c0c458aaf6b914599ea91da929a815026fff9b602e';

describe('P0.1: the changelog bytes are frozen for the programme', () => {
  it('CHANGELOG.md is byte-identical to the immutable programme hash', () => {
    const bytes = readFileSync(join(packageRoot(), 'CHANGELOG.md'));
    const actual = createHash('sha256').update(bytes).digest('hex');
    expect(actual).toBe(IMMUTABLE_CHANGELOG_SHA256);
  });
});
