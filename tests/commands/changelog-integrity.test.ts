import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';

// P0.1: the changelog is an audited artifact — every intentional edit must update this recorded
// hash (and the ledger) in the same change. Any other edit fails CI here.
const EXPECTED_CHANGELOG_SHA256 = 'dc1d9020d2c56030d16a5dea850096550d2b83e5c4f96cfb0bab5a90681fa9fd';

describe('P0.1: the changelog bytes match the recorded integrity hash', () => {
  it('CHANGELOG.md is byte-identical to the ledger-recorded hash', () => {
    const bytes = readFileSync(join(packageRoot(), 'CHANGELOG.md'));
    const actual = createHash('sha256').update(bytes).digest('hex');
    expect(actual).toBe(EXPECTED_CHANGELOG_SHA256);
  });
});
