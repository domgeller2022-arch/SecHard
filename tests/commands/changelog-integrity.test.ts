import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';

// P0.1 (auditor correction, 14 Oct): the changelog is FROZEN for this programme. The hash below
// is the immutable programme hash recorded in the full audit; no changelog edit is authorised —
// plan authority and progress live in docs/completion-ledger.yaml and living documents. Changing
// this constant is a change to the programme's integrity guard and requires owner review.
const IMMUTABLE_CHANGELOG_SHA256 = '858bb9cf8183a40c732d5c9003aca9c2a786b58211ef6b873ff5605ef85bd0bc';

describe('P0.1: the changelog bytes are frozen for the programme', () => {
  it('CHANGELOG.md is byte-identical to the immutable programme hash', () => {
    const bytes = readFileSync(join(packageRoot(), 'CHANGELOG.md'));
    const actual = createHash('sha256').update(bytes).digest('hex');
    expect(actual).toBe(IMMUTABLE_CHANGELOG_SHA256);
  });
});
