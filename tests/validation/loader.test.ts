import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { loadDocument } from '../../src/validation/loader.js';
import { confineToRoot, isInside } from '../../src/validation/paths.js';

const scratch = mkdtempSync(join(tmpdir(), 'hardening-loader-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

let counter = 0;
function fixture(contents: string, name?: string): string {
  const file = join(scratch, name ?? `f${counter++}.yaml`);
  writeFileSync(file, contents, 'utf8');
  return file;
}

const MINIMAL = 'schema_version: app/v1\nid: demo\n';

function codeOf(result: unknown): string {
  return typeof result === 'object' && result !== null && 'code' in result
    ? String((result as { code: unknown }).code)
    : 'accepted';
}

describe('bounded document loading', () => {
  it('accepts a valid record and reports its raw digest', () => {
    const result = loadDocument(fixture(MINIMAL));
    expect(result.issues).toEqual([]);
    expect(result.data).toMatchObject({ id: 'demo' });
    expect(result.rawDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects duplicate keys instead of silently taking the last one', () => {
    const result = loadDocument(fixture('id: a\nid: b\n'));
    expect(result.issues[0]?.code).toBe('input.duplicate_key');
    expect(result.issues[0]?.message).toMatch(/id/i);
  });

  it('rejects duplicate keys inside JSON input too', () => {
    const result = loadDocument(fixture('{"schema_version":"app/v1","id":"a","id":"b"}', 'dup.json'));
    expect(result.issues[0]?.code).toBe('input.duplicate_key');
  });

  it('rejects a second document when one is expected', () => {
    const result = loadDocument(fixture(`${MINIMAL}---\nid: other\n`));
    expect(result.issues[0]?.code).toBe('input.multiple_documents');
  });

  it('rejects custom tags', () => {
    const result = loadDocument(fixture('id: !custom demo\n'));
    expect(result.issues.map((i) => i.code)).toContain('input.custom_tag');
  });

  it('rejects YAML anchors and aliases', () => {
    const anchored = loadDocument(fixture('base: &base\n  id: demo\nother: *base\n'));
    expect(anchored.issues.map((i) => i.code)).toContain('input.alias_or_anchor');

    const anchorOnly = loadDocument(fixture('base: &base\n  id: demo\n'));
    expect(anchorOnly.issues.map((i) => i.code)).toContain('input.alias_or_anchor');
  });

  it('rejects an empty file', () => {
    expect(loadDocument(fixture('')).issues[0]?.code).toBe('input.empty_document');
    expect(loadDocument(fixture('# only a comment\n')).issues[0]?.code).toBe('input.empty_document');
  });

  it('rejects a non-object document root when one is required', () => {
    expect(loadDocument(fixture('- a\n- b\n')).issues[0]?.code).toBe('input.not_an_object');
  });

  it('reports a missing file instead of throwing', () => {
    expect(loadDocument(join(scratch, 'absent.yaml')).issues[0]?.code).toBe('input.not_found');
  });

  it('refuses to read a file above the size limit', () => {
    const big = `id: ${'x'.repeat(2000)}\n`;
    const result = loadDocument(fixture(big, 'big.yaml'), { limits: { maxFileBytes: 100 } });
    expect(result.issues[0]?.code).toBe('input.file_too_large');
  });

  it('refuses nesting past the depth limit', () => {
    const levels = 8;
    const lines: string[] = [];
    for (let level = 0; level < levels; level += 1) {
      lines.push(`${'  '.repeat(level)}nest:`);
    }
    lines.push(`${'  '.repeat(levels)}leaf: 1`);

    const result = loadDocument(fixture(`${lines.join('\n')}\n`, 'deep.yaml'), {
      limits: { maxDepth: 3 },
    });
    expect(result.issues[0]?.code).toBe('input.depth_exceeded');
  });

  it('accepts nesting within the depth limit', () => {
    const nested = 'nest:\n  leaf: 1\n';
    expect(loadDocument(fixture(nested, 'shallow.yaml'), { limits: { maxDepth: 4 } }).issues).toEqual([]);
  });

  it('refuses a string past the length limit', () => {
    const result = loadDocument(fixture(`id: ${'y'.repeat(300)}\n`), {
      limits: { maxStringLength: 50 },
    });
    expect(result.issues[0]?.code).toBe('input.string_too_long');
  });

  it('refuses an array past the length limit', () => {
    const result = loadDocument(fixture(`- a\n${'- b\n'.repeat(40)}`), {
      limits: { maxArrayLength: 5 },
    });
    expect(result.issues[0]?.code).toBe('input.collection_too_large');
  });

  it('keeps the exact 40-hex commit shape rather than trimming it', () => {
    const commit = 'a'.repeat(40);
    const result = loadDocument(fixture(`commit: "${commit}"\ncommit2: "${commit}b"\n`));
    expect(result.issues).toEqual([]);
  });
});

describe('path confinement', () => {
  const root = join(scratch, 'root');
  const outside = join(scratch, 'outside');
  mkdirSync(root, { recursive: true });
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(root, 'inside.txt'), 'ok', 'utf8');
  writeFileSync(join(outside, 'secret.txt'), 'secret', 'utf8');

  it('accepts a path inside the root', () => {
    const result = confineToRoot(root, 'inside.txt');
    expect(result).toMatchObject({ relativePath: 'inside.txt' });
  });

  it('rejects traversal out of the root', () => {
    const result = confineToRoot(root, '../outside/secret.txt');
    expect(codeOf(result)).toBe('path.outside_root');
  });

  it('rejects an absolute path outside the root', () => {
    const result = confineToRoot(root, join(outside, 'secret.txt'));
    expect(codeOf(result)).toBe('path.outside_root');
  });

  it('rejects a symlink that escapes the root', () => {
    const link = join(root, 'escape.txt');
    symlinkSync(join(outside, 'secret.txt'), link);
    const result = confineToRoot(root, 'escape.txt');
    expect(codeOf(result)).toBe('path.symlink_escape');
  });

  it('does not read the escaping target', () => {
    const link = join(root, 'escape-dir');
    symlinkSync(outside, link);
    const result = confineToRoot(root, 'escape-dir/secret.txt');
    expect(codeOf(result)).toBe('path.symlink_escape');
  });

  it('reports a missing required path', () => {
    const result = confineToRoot(root, 'absent.txt', { mustExist: true });
    expect(codeOf(result)).toBe('path.outside_root');
  });

  it('isInside rejects a sibling with a shared prefix', () => {
    expect(isInside(root, join(root, 'x'))).toBe(true);
    expect(isInside(root, `${root}-sibling`)).toBe(false);
  });
});
