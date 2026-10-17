import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { auditCommand } from '../../src/commands/audit.js';
import { packageRoot } from '../../src/validation/schema.js';
import { walk } from '../../src/audit/detect.js';
import { redactSecrets } from '../../src/evidence/redaction.js';

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});


/** Whole-tree digest (B-06): names+sizes of every file under root — proves nothing was written. */
function treeDigest(root: string): string {
  const entries: string[] = [];
  const walkDir = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stats = lstatSync(full);
      if (stats.isDirectory()) walkDir(full);
      else entries.push(`${relative(root, full)}:${String(stats.size)}`);
    }
  };
  walkDir(root);
  entries.sort();
  return entries.join('|');
}

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
    const run = await auditCommand({ target, out, depth: 'quick', now: new Date(), policyRoot: packageRoot() });
    // Either refusal is a correct confinement outcome: the symlink resolves into the target, or a
    // symlinked output that resolves nowhere cannot be proven confined and is refused.
    const stderr = run.stderr.join('\n');
    expect(run.exitCode).toBe(2);
    expect(stderr.includes('must live outside the audited project') || stderr.includes('could not be resolved')).toBe(true);
    expect(existsSync(join(target, 'stolen'))).toBe(false);
  });

  it('rejects an output directory inside the target', async () => {
    const target = app();
    const run = await auditCommand({ target, out: join(target, 'innocent-name'), depth: 'quick', now: new Date(), policyRoot: packageRoot() });
    expect(run.exitCode).toBe(2);
    expect(run.stderr.join('\n')).toContain('must live outside the audited project');
  });

  it('accepts a normal outside output directory (the run proceeds past the guard)', async () => {
    const target = app();
    const outside = mkdtempSync(join(tmpdir(), 'sechard-confine-ok-'));
    roots.push(outside);
    const run = await auditCommand({ target, out: join(outside, 'out'), depth: 'quick', now: new Date(), policyRoot: packageRoot() });
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

describe('P1.2 (auditor R1-02): nested unreadable output directories cannot hide aliases into the target', () => {
  it('refuses before any write when a nested records directory is unreadable and hides a symlink', async () => {
    const target = app();
    const outside = mkdtempSync(join(tmpdir(), 'sechard-confine-nested-'));
    roots.push(outside);
    const out = join(outside, 'out');
    mkdirSync(join(out, 'records', '.hardening'), { recursive: true });
    // records itself: no read permission (write/search only) — enumeration of its .hardening
    // symlink must not be skipped as a mere missing entry.
    symlinkSync(join(target, 'owned'), join(out, 'records', '.hardening', 'stolen'));
    // B-06: actually remove read permission so the enumeration genuinely fails — the refusal
    // must come from the unreadable path, not from the symlink being visible.
    chmodSync(join(out, 'records'), 0o300);
    const digestBefore = treeDigest(target);
    const run = await auditCommand({ target, out, depth: 'quick', now: new Date(), policyRoot: packageRoot() });
    const stderr = run.stderr.join('\n');
    expect(stderr, 'expected the unreadable-output refusal').toContain('cannot be inspected');
    expect(run.exitCode).toBe(2);
    // B-06: the whole target tree is byte-identical — nothing was written into it.
    expect(treeDigest(target)).toBe(digestBefore);
    // Restore read permission so the suite's cleanup can remove the fixture.
    chmodSync(join(out, 'records'), 0o755);
  });

  it('fails loudly when the final report write fails, and leaves no raw scanner bytes (R1-05)', async () => {
    const target = app();
    const outside = mkdtempSync(join(tmpdir(), 'sechard-confine-rawfail-'));
    roots.push(outside);
    const out = join(outside, 'out');
    mkdirSync(join(out, 'report.md'), { recursive: true });
    const digestBefore = treeDigest(target);
    const run = await auditCommand({ target, out, depth: 'quick', now: new Date(), policyRoot: packageRoot() });
    // B-06: with a valid policy root the run reaches the report write and fails THERE (EISDIR),
    // not on an earlier policy-load error.
    expect(run.exitCode, run.stderr.join('\n')).not.toBe(0);
    expect(run.stderr.join('\n')).toContain('report.md');
    expect(treeDigest(target)).toBe(digestBefore);
    // The private staging area is removed on the failure path: no sechard-raw-* directory remains.
    const leftovers = readdirSync(tmpdir()).filter((entry) => entry.startsWith('sechard-raw-'));
    expect(leftovers, `raw staging left behind: ${leftovers.join(', ')}`).toEqual([]);
  });
});
