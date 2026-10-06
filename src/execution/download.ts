import { createHash } from 'node:crypto';
import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { isRegistryApproved, type DependencyPolicy } from './policy.js';

/**
 * Verified download for tools that are fetched rather than provided by the platform.
 *
 * A download is only ever accepted when its content matches an expected SHA-256 that was recorded
 * in reviewed policy or toolchain data. Without an expected digest the download is refused: an
 * unverified fetch is exactly the supply-chain path the pinning rules exist to close.
 *
 * Redirects are not followed by default. A redirect is a second URL that the reviewed policy did
 * not approve, and following it silently would move the download outside the approved origin.
 */

export interface DownloadSpec {
  readonly url: string;
  readonly expectedSha256: string;
  readonly destination: string;
  readonly policy: DependencyPolicy;
  readonly maxBytes?: number;
  readonly allowedHosts?: readonly string[];
  readonly followRedirects?: boolean;
  /** Injected for tests so the fetch can be exercised without the network. */
  readonly fetchImpl?: typeof fetch;
}

export type DownloadOutcome =
  | { readonly ok: true; readonly path: string; readonly bytes: number; readonly sha256: string }
  | { readonly ok: false; readonly reason: DownloadFailure; readonly message: string };

export type DownloadFailure =
  | 'unapproved_registry'
  | 'insecure_origin'
  | 'unapproved_host'
  | 'missing_expected_digest'
  | 'http_error'
  | 'too_large'
  | 'digest_mismatch'
  | 'redirect_refused'
  | 'write_error';

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;

export async function downloadVerified(spec: DownloadSpec): Promise<DownloadOutcome> {
  if (!/^[0-9a-f]{64}$/.test(spec.expectedSha256)) {
    return { ok: false, reason: 'missing_expected_digest', message: `expectedSha256 '${spec.expectedSha256}' is not a SHA-256 digest` };
  }

  const url = new URL(spec.url);
  // A download over plain HTTP can be replaced in transit, so the digest would be the only thing
  // standing between an attacker and the tool. Loopback is exempt: it is not a network path, and
  // tests and local mirrors need it.
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1';
  if (url.protocol !== 'https:' && !loopback) {
    return { ok: false, reason: 'insecure_origin', message: `${url.protocol}//${url.host} is not HTTPS` };
  }
  if (!isRegistryApproved(spec.policy, `${url.protocol}//${url.host}/`)) {
    return { ok: false, reason: 'unapproved_registry', message: `origin ${url.host} is not a reviewed registry` };
  }
  if (spec.allowedHosts !== undefined && !spec.allowedHosts.includes(url.host)) {
    return { ok: false, reason: 'unapproved_host', message: `host ${url.host} is not in the approved host list` };
  }

  const maxBytes = spec.maxBytes ?? DEFAULT_MAX_BYTES;
  const doFetch = spec.fetchImpl ?? fetch;

  let response: Response;
  try {
    response = await doFetch(spec.url, { redirect: spec.followRedirects === true ? 'follow' : 'manual' });
  } catch (error) {
    return { ok: false, reason: 'http_error', message: `request failed: ${(error as Error).message}` };
  }

  if (spec.followRedirects !== true && response.status >= 300 && response.status < 400) {
    const location = response.headers.get('location') ?? 'unknown';
    return { ok: false, reason: 'redirect_refused', message: `refused to follow redirect to ${location}` };
  }
  if (!response.ok) {
    return { ok: false, reason: 'http_error', message: `HTTP ${response.status} from ${url.host}` };
  }

  const declared = Number(response.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) {
    return { ok: false, reason: 'too_large', message: `content-length ${declared} exceeds the ${maxBytes}-byte limit` };
  }

  const body = Buffer.from(await response.arrayBuffer());
  if (body.length > maxBytes) {
    return { ok: false, reason: 'too_large', message: `received ${body.length} bytes, above the ${maxBytes}-byte limit` };
  }

  const sha256 = createHash('sha256').update(body).digest('hex');
  if (sha256 !== spec.expectedSha256) {
    return { ok: false, reason: 'digest_mismatch', message: `expected ${spec.expectedSha256.slice(0, 12)}…, received ${sha256.slice(0, 12)}…` };
  }

  try {
    mkdirSync(dirname(spec.destination), { recursive: true });
    const temporary = `${spec.destination}.part-${process.pid}`;
    writeFileSync(temporary, body, { mode: 0o600 });
    renameSync(temporary, spec.destination);
  } catch (error) {
    rmSync(`${spec.destination}.part-${process.pid}`, { force: true });
    return { ok: false, reason: 'write_error', message: `could not write ${spec.destination}: ${(error as Error).message}` };
  }

  return { ok: true, path: spec.destination, bytes: body.length, sha256 };
}
