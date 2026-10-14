import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { readBoundedSync } from '../../src/evidence/bounded-io.js';

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

describe('P1.3: bounded reads stop at the byte limit, at open time', () => {
  it('returns exactly maxBytes for an oversized file and the whole file under the limit', () => {
    const root = mkdtempSync(join(tmpdir(), 'sechard-bounded-'));
    roots.push(root);
    const big = join(root, 'big.ts');
    writeFileSync(big, 'x'.repeat(1024 * 1024));
    const bounded = readBoundedSync(big, 4096);
    expect(bounded).toHaveLength(4096);
    expect(bounded).toBe('x'.repeat(4096));
    const small = join(root, 'small.ts');
    writeFileSync(small, 'content\n');
    expect(readBoundedSync(small, 4096)).toBe('content\n');
  });

  it('returns undefined for unreadable files and symlinks instead of throwing or following', () => {
    const root = mkdtempSync(join(tmpdir(), 'sechard-bounded-err-'));
    roots.push(root);
    const unreadable = join(root, 'locked.ts');
    writeFileSync(unreadable, 'secret-ish\n');
    chmodSync(unreadable, 0o000);
    expect(readBoundedSync(unreadable, 4096)).toBeUndefined();
    const linked = join(root, 'link.ts');
    symlinkSync('/etc/hosts', linked);
    expect(readBoundedSync(linked, 4096)).toBeUndefined();
    chmodSync(unreadable, 0o644);
  });
});
