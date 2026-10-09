import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/**
 * The `--url` guard for audit mode (gap analysis D6).
 *
 * The approved-target model exists precisely so that nothing contacts a host because a finding or
 * a page mentioned it. Audit mode generates the inventory from a single operator-supplied `--url`,
 * so the one thing this guard must guarantee is that a *private* network address can never become
 * a live-check target by accident: no loopback, no link-local (which includes cloud metadata
 * services such as 169.254.169.254), no RFC1918 space, no unique-local IPv6.
 *
 * `--allow-local` is the explicit local-development opt-in the gap analysis requires; a plain-HTTP
 * URL is only ever accepted with it, and such targets are pinned to the `local` environment.
 */

export interface ApprovedUrl {
  readonly scheme: 'http' | 'https';
  readonly host: string;
  readonly port?: number;
  readonly environment: 'local' | 'production';
  readonly resolvedAddresses: readonly string[];
}

export interface UrlGuardResult {
  readonly approved?: ApprovedUrl;
  readonly refusals: readonly string[];
}

const ipv4Refused = (octets: readonly number[]): string | undefined => {
  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;
  if (a === 0) return 'this network is unusable ("this" network, 0.0.0.0/8)';
  if (a === 10) return 'private IPv4 range (10.0.0.0/8)';
  if (a === 127) return 'loopback (127.0.0.0/8)';
  if (a === 169 && b === 254) return 'link-local range (169.254.0.0/16), which includes cloud metadata services';
  if (a === 172 && b >= 16 && b <= 31) return 'private IPv4 range (172.16.0.0/12)';
  if (a === 192 && b === 168) return 'private IPv4 range (192.168.0.0/16)';
  if (a === 100 && b >= 64 && b <= 127) return 'shared address space (100.64.0.0/10, CGNAT)';
  if (a >= 224) return 'multicast or reserved IPv4 space';
  return undefined;
};

function refusedReason(address: string): string | undefined {
  const family = isIP(address);
  if (family === 4) {
    const octets = address.split('.').map((part) => Number.parseInt(part, 10));
    if (octets.length !== 4 || octets.some((part) => Number.isNaN(part))) return 'malformed IPv4 address';
    return ipv4Refused(octets);
  }
  if (family === 6) {
    const normalized = address.toLowerCase();
    // An IPv4-mapped IPv6 address is judged as its IPv4 half. The URL parser compresses the
    // mapped form (`::ffff:a00:1`), so both the dotted and the two-hex-group spellings expand.
    const mapped = /^::ffff:(?:(?<dotted>\d+\.\d+\.\d+\.\d+)|(?<hex>[0-9a-f]{1,4}):(?<hex2>[0-9a-f]{1,4}))$/.exec(normalized);
    if (mapped?.groups?.['dotted'] !== undefined) return refusedReason(mapped.groups['dotted']);
    if (mapped?.groups?.['hex'] !== undefined && mapped.groups['hex2'] !== undefined) {
      const high = Number.parseInt(mapped.groups['hex'], 16);
      const low = Number.parseInt(mapped.groups['hex2'], 16);
      return refusedReason(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
    }
    if (normalized === '::' || normalized === '::1') return 'the unspecified or loopback IPv6 address';
    if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return 'unique-local IPv6 range (fc00::/7)';
    if (/^fe[89ab][0-9a-f]:/.test(normalized)) return 'link-local IPv6 range (fe80::/10)';
    if (/^ff[0-9a-f]{2}:/.test(normalized)) return 'multicast IPv6 range';
    return undefined;
  }
  return undefined;
}

export async function approveUrl(rawUrl: string, options: { allowLocal: boolean }): Promise<UrlGuardResult> {
  const refusals: string[] = [];

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { refusals: [`'${rawUrl}' is not an absolute URL`] };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    refusals.push(`scheme '${parsed.protocol.replace(':', '')}' is not supported; live checks accept http and https only`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    refusals.push('URLs with embedded credentials are refused');
  }
  if (parsed.pathname !== '/' && parsed.pathname !== '') {
    // An audit's live target is an origin. A deep path is refused rather than silently dropped,
    // because a half-remembered URL would otherwise become the wrong target.
    refusals.push(`live checks target an origin; pass the origin without a path (got '${parsed.pathname}')`);
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (host.length === 0) {
    refusals.push('the URL has no host');
  }

  const literalReason = host.length > 0 ? refusedReason(host) : undefined;
  if (literalReason !== undefined && !options.allowLocal) {
    refusals.push(`the host is a ${literalReason}`);
  }
  if (host === 'localhost' && !options.allowLocal) {
    refusals.push("the host 'localhost' is a loopback name; pass --allow-local explicitly to audit a local development target");
  }

  // Resolve and check every address: the name a URL uses can point anywhere, and the resolved
  // addresses are what will actually be contacted. The resolved list is recorded so the report can
  // state exactly what was contacted and why.
  const resolved: string[] = [];
  if (host.length > 0 && isIP(host) === 0) {
    try {
      const records = await lookup(host, { all: true });
      resolved.push(...records.map((record) => record.address));
    } catch (error) {
      refusals.push(`the host could not be resolved: ${(error as Error).message}`);
    }
    for (const address of resolved) {
      const reason = refusedReason(address);
      if (reason !== undefined && !options.allowLocal) {
        refusals.push(`'${host}' resolves to ${address}, which is a ${reason}`);
      }
    }
  } else if (host.length > 0) {
    resolved.push(host);
  }

  if (refusals.length > 0) return { refusals };

  const scheme = parsed.protocol === 'https:' ? 'https' : 'http';
  const portText = parsed.port === '' ? undefined : Number.parseInt(parsed.port, 10);

  return {
    approved: {
      scheme,
      host,
      ...(portText === undefined || Number.isNaN(portText) ? {} : { port: portText }),
      // Plain HTTP can only ever be a local development target; HTTPS is treated as production,
      // which is also what the inventory's own validation rules require.
      environment: scheme === 'https' ? 'production' : 'local',
      resolvedAddresses: resolved.length > 0 ? resolved : [host],
    },
    refusals: [],
  };
}
