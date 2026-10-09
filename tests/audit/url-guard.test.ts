import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { approveUrl } from '../../src/audit/url-guard.js';

/**
 * The `--url` guard (gap analysis D6). The rule: audit mode's live checks may only ever contact an
 * operator-supplied public origin. Everything private — loopback, link-local (cloud metadata),
 * RFC1918, unique-local IPv6 — is refused unless `--allow-local` explicitly opts in to local
 * development.
 */

describe('approveUrl refuses private and non-origin targets', () => {
  const refuse = async (url: string): Promise<readonly string[]> => {
    const result = await approveUrl(url, { allowLocal: false });
    expect(result.approved).toBeUndefined();
    expect(result.refusals.length).toBeGreaterThan(0);
    return result.refusals;
  };

  it('refuses cloud metadata and link-local addresses by name', async () => {
    const refusals = await refuse('http://169.254.169.254/');
    expect(refusals.join(' ')).toContain('link-local');
  });

  it('refuses loopback IPs and the localhost name', async () => {
    expect((await refuse('http://127.0.0.1/')).join(' ')).toContain('loopback');
    expect((await refuse('http://localhost:3000/')).join(' ')).toContain('localhost');
  });

  it('refuses RFC1918 space in all three ranges and mapped IPv6', async () => {
    expect((await refuse('http://10.1.2.3/')).join(' ')).toContain('private');
    expect((await refuse('http://172.16.9.9/')).join(' ')).toContain('private');
    expect((await refuse('http://192.168.1.1/')).join(' ')).toContain('private');
    expect((await refuse('http://[::ffff:10.0.0.1]/')).join(' ')).toContain('private');
  });

  it('refuses IPv6 loopback, link-local, and unique-local literals', async () => {
    expect((await refuse('http://[::1]/')).join(' ')).toContain('loopback');
    expect((await refuse('http://[fe80::1]/')).join(' ')).toContain('link-local');
    expect((await refuse('http://[fc00::1]/')).join(' ')).toContain('unique-local');
  });

  it('refuses URLs with embedded credentials, wrong schemes, and deep paths', async () => {
    expect((await refuse('https://user:pass@example.com/')).join(' ')).toContain('credentials');
    expect((await refuse('ftp://example.com/')).join(' ')).toContain('not supported');
    expect((await refuse('https://example.com/deep/path')).join(' ')).toContain('origin');
  });

  it('refuses a hostname that cannot be resolved, and records why', async () => {
    // A name that cannot resolve at all is refused, not silently skipped. (A name resolving into
    // private space hits the same branch; hermetic tests cannot force a real resolver to return a
    // private address, so the unresolvable case stands in for the resolved-refusal path.)
    const unresolvable = await approveUrl(`https://${randomUUID()}.invalid/`, { allowLocal: false });
    expect(unresolvable.approved).toBeUndefined();
    expect(unresolvable.refusals.join(' ')).toContain('resolved');
  });
});

describe('approveUrl approves explicit and local targets', () => {
  it('approves a public IP literal and records the pinned address', async () => {
    const result = await approveUrl('https://192.0.2.10/', { allowLocal: false });
    expect(result.refusals).toEqual([]);
    expect(result.approved).toMatchObject({ scheme: 'https', host: '192.0.2.10', environment: 'production' });
    expect(result.approved?.resolvedAddresses).toEqual(['192.0.2.10']);
  });

  it('approves localhost only with the explicit --allow-local opt-in, pinned to the local environment', async () => {
    const result = await approveUrl('http://localhost:54321/', { allowLocal: true });
    expect(result.refusals).toEqual([]);
    expect(result.approved?.environment).toBe('local');
    expect(result.approved?.port).toBe(54321);
    expect(result.approved?.resolvedAddresses.length).toBeGreaterThan(0);
  });

  it('approves a private literal only with --allow-local', async () => {
    const refused = await approveUrl('http://10.0.0.5:8080/', { allowLocal: false });
    expect(refused.approved).toBeUndefined();
    const allowed = await approveUrl('http://10.0.0.5:8080/', { allowLocal: true });
    expect(allowed.approved?.host).toBe('10.0.0.5');
  });
});
