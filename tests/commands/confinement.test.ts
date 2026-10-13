import { existsSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { auditCommand } from '../../src/commands/audit.js';
import { packageRoot } from '../../src/validation/schema.js';
import { walk } from '../../src/audit/detect.js';
import { redactSecrets } from '../../src/evidence/redaction.js';

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function app(): string {
  const root = mkdtempSync(join(tmpdir(), 'sechard-confine-app-'));
  roots.push(root);
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  return root;
}

describe('A-02: audit output stays outside the audited tree, resolved through real paths', () => {
  it('rejects an output symlink pointing into the audited target', async () => {
    const target = app();
    const outside = mkdtempSync(join(tmpdir(), 'sechard-confine-out-'));
    roots.push(outside);
    const out = join(outside, 'out-link');
    symlinkSync(join(target, 'stolen'), out);
    const run = await auditCommand({ target, out, depth: 'quick', now: new Date(), policyRoot: join(packageRoot(), 'policy') });
    // Either refusal is a correct confinement outcome: the symlink resolves into the target, or a
    // symlinked output that resolves nowhere cannot be proven confined and is refused.
    const stderr = run.stderr.join('\n');
    expect(run.exitCode).toBe(2);
    expect(stderr.includes('must live outside the audited project') || stderr.includes('could not be resolved')).toBe(true);
    expect(existsSync(join(target, 'stolen'))).toBe(false);
  });

  it('rejects an output directory inside the target', async () => {
    const target = app();
    const run = await auditCommand({ target, out: join(target, 'innocent-name'), depth: 'quick', now: new Date(), policyRoot: join(packageRoot(), 'policy') });
    expect(run.exitCode).toBe(2);
    expect(run.stderr.join('\n')).toContain('must live outside the audited project');
  });

  it('accepts a normal outside output directory (the run proceeds past the guard)', async () => {
    const target = app();
    const outside = mkdtempSync(join(tmpdir(), 'sechard-confine-ok-'));
    roots.push(outside);
    const run = await auditCommand({ target, out: join(outside, 'out'), depth: 'quick', now: new Date(), policyRoot: join(packageRoot(), 'policy') });
    expect(run.stderr.join('\n')).not.toContain('must live outside the audited project');
  });
});

describe('A-02: the detection walk never follows symlinks', () => {
  it('skips a symlink out of the tree and reports it', () => {
    const root = mkdtempSync(join(tmpdir(), 'sechard-confine-walk-'));
    roots.push(root);
    const secretDir = mkdtempSync(join(tmpdir(), 'sechard-confine-secret-'));
    roots.push(secretDir);
    writeFileSync(join(secretDir, 'outside.txt'), 'outside\n');
    writeFileSync(join(root, 'inside.txt'), 'inside\n');
    symlinkSync(join(secretDir, 'outside.txt'), join(root, 'link-out.txt'));
    const skipped: string[] = [];
    const files = walk(root, (path) => skipped.push(path));
    expect(files.some((file) => file.path.endsWith('inside.txt'))).toBe(true);
    expect(files.some((file) => file.path.includes('link-out'))).toBe(false);
    expect(skipped).toHaveLength(1);
  });
});

describe('A-03: provider values are scrubbed at the persistence boundary', () => {
  it('redacts stripe, openai, database URLs, and google keys — including without a variable name', () => {
    const stripe = `sk_live_${'A1b2C3d4E5f6G7h8'}`;
    const openai = `sk-proj-${'A1b2C3d4E5f6G7h8I9j0K1l2'}`;
    const dbUrl = 'postgres://app:hunter2@db.example.invalid:5432/app';
    const google = `AIza${'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r'}`;
    const line = `const value = "${stripe}"; fetch("${dbUrl}"); "${openai}" "${google}"`;
    const scrubbed = redactSecrets(line);
    expect(scrubbed).not.toContain(stripe);
    expect(scrubbed).not.toContain(openai);
    expect(scrubbed).not.toContain(dbUrl);
    expect(scrubbed).not.toContain(google);
    expect(scrubbed).toContain('[REDACTED]');
  });
});
