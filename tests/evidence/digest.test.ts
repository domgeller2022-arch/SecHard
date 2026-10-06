import { describe, expect, it } from 'vitest';
import { canonicalDigest, canonicalize, sha256Hex } from '../../src/evidence/digest.js';

describe('RFC 8785 JSON Canonicalization Scheme', () => {
  // Vector from RFC 8785 section 3.2.2/3.2.3, retrieved from
  // https://www.rfc-editor.org/rfc/rfc8785.txt on 2026-10-06.
  const rfcSample = {
    numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
    string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
    literals: [null, true, false],
  };

  it('reproduces the RFC example output exactly', () => {
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';

    expect(canonicalize(rfcSample)).toBe(expected);
  });

  it('produces the known SHA-256 for the RFC example output', () => {
    expect(canonicalDigest(rfcSample)).toBe(
      '2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb',
    );
  });

  // Vectors from RFC 8785 Appendix B (IEEE 754 representation, JSON representation).
  const numberVectors: readonly [number, string][] = [
    [0, '0'],
    [-0, '0'],
    [Number.MIN_VALUE, '5e-324'],
    [-Number.MIN_VALUE, '-5e-324'],
    [Number.MAX_VALUE, '1.7976931348623157e+308'],
    [-Number.MAX_VALUE, '-1.7976931348623157e+308'],
    [9007199254740992, '9007199254740992'],
    [-9007199254740992, '-9007199254740992'],
    [1e23, '1e+23'],
    [1e21, '1e+21'],
    [0.000001, '0.000001'],
    [333333333.3333333, '333333333.3333333'],
    [9.999999999999997e22, '9.999999999999997e+22'],
  ];

  it.each(numberVectors)('serializes %s as %s', (input, expected) => {
    expect(canonicalize({ v: input })).toBe(`{"v":${expected}}`);
  });

  it('sorts object properties by UTF-16 code units, recursively', () => {
    const unsorted = { b: 1, a: { z: 1, y: [{ q: 1, p: 2 }] }, A: 1, 'ä': 1, a$: 1 };
    expect(canonicalize(unsorted)).toBe('{"A":1,"a":{"y":[{"p":2,"q":1}],"z":1},"a$":1,"b":1,"ä":1}');
  });

  it('does not reorder arrays', () => {
    expect(canonicalize(['b', 'a', 'c'])).toBe('["b","a","c"]');
  });

  it('is insensitive to the order keys were inserted', () => {
    const first: Record<string, unknown> = {};
    first.z = 1;
    first.a = 2;
    const second: Record<string, unknown> = {};
    second.a = 2;
    second.z = 1;

    expect(canonicalize(first)).toBe(canonicalize(second));
    expect(canonicalDigest(first)).toBe(canonicalDigest(second));
  });

  it('rejects values outside the I-JSON subset rather than coercing them', () => {
    expect(() => canonicalize({ v: Number.NaN })).toThrow(/I-JSON number/);
    expect(() => canonicalize({ v: Number.POSITIVE_INFINITY })).toThrow(/I-JSON number/);
    expect(() => canonicalize({ v: 10n })).toThrow(/bigint/);
    expect(() => canonicalize({ v: '\ud800' })).toThrow(/lone surrogate/);
    expect(() => canonicalize({ v: () => 1 })).toThrow(/unsupported type/);
  });

  it('refuses to silently drop an undefined field', () => {
    expect(() => canonicalize({ a: 1, b: undefined })).toThrow(/undefined/);
  });
});

describe('sha256Hex', () => {
  it('matches the published SHA-256 test vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(
      sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('hashes bytes and equivalent text identically', () => {
    expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(sha256Hex('abc'));
  });
});
