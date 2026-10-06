import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { downloadVerified } from '../../src/execution/download.js';
import type { DependencyPolicy } from '../../src/execution/policy.js';

const scratch = mkdtempSync(join(tmpdir(), 'hardening-download-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const PAYLOAD = Buffer.from('synthetic tool payload, not a real binary\n');
const PAYLOAD_SHA = createHash('sha256').update(PAYLOAD).digest('hex');

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer((request, response) => {
    if (request.url === '/good') {
      response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(PAYLOAD.length) });
      response.end(PAYLOAD);
      return;
    }
    if (request.url === '/redirect') {
      response.writeHead(302, { location: `${origin}/good` });
      response.end();
      return;
    }
    if (request.url === '/lies-about-length') {
      response.writeHead(200, { 'content-length': '10' });
      response.end(PAYLOAD);
      return;
    }
    response.writeHead(404);
    response.end('not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no server address');
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const policyWith = (origin: string): DependencyPolicy => ({
  schema: 'hardening/dependency-policy/v1',
  policy_version: 1,
  review_status: 'draft',
  minimum_release_age_minutes: 10080,
  registries: {
    allow_additional_registries: false,
    allowed: [{ id: 'local-test', url: `${origin}/`, reviewed_at: '2026-10-01T00:00:00Z' }],
  },
  install_scripts: { default: 'disabled', allowed_hooks: [] },
  install_exceptions: [],
  urgent_fix_route: { permitted: true, requires_exact_version: true, requires_expiry: true, requires_approval: true, max_exception_days: 30 },
  provisioning: { separate_from_checking: true, require_digest_for_execution: true, require_reviewed_registry: true, require_recorded_identity: true },
  application_execution: { requires_operator_approved_environment: true, isolation_is_operator_responsibility: true },
});

describe('verified download', () => {
  it('writes the file only when the digest matches', async () => {
    const destination = join(scratch, 'tool', 'good.bin');
    const result = await downloadVerified({
      url: `${origin}/good`,
      expectedSha256: PAYLOAD_SHA,
      destination,
      policy: policyWith(origin),
    });

    expect(result.ok).toBe(true);
    expect(existsSync(destination)).toBe(true);
    expect(readFileSync(destination).equals(PAYLOAD)).toBe(true);
  });

  it('rejects content whose digest does not match and leaves nothing behind', async () => {
    const destination = join(scratch, 'tool', 'mismatch.bin');
    const result = await downloadVerified({
      url: `${origin}/good`,
      expectedSha256: 'f'.repeat(64),
      destination,
      policy: policyWith(origin),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('digest_mismatch');
    expect(existsSync(destination)).toBe(false);
  });

  // A digest is the whole control; without one the download is refused rather than trusted.
  it('refuses a download with no usable expected digest', async () => {
    const result = await downloadVerified({
      url: `${origin}/good`,
      expectedSha256: 'not-a-digest',
      destination: join(scratch, 'tool', 'nodigest.bin'),
      policy: policyWith(origin),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('missing_expected_digest');
  });

  it('refuses to follow a redirect by default', async () => {
    const result = await downloadVerified({
      url: `${origin}/redirect`,
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'redirect.bin'),
      policy: policyWith(origin),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('redirect_refused');
    expect(existsSync(join(scratch, 'tool', 'redirect.bin'))).toBe(false);
  });

  it('refuses an origin that is not a reviewed registry', async () => {
    const result = await downloadVerified({
      url: `${origin}/good`,
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'other.bin'),
      policy: { ...policyWith(origin), registries: { allow_additional_registries: false, allowed: [] } },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('unapproved_registry');
  });

  it('refuses a host outside the approved host list', async () => {
    const result = await downloadVerified({
      url: `${origin}/good`,
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'host.bin'),
      policy: policyWith(origin),
      allowedHosts: ['downloads.example.invalid'],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('unapproved_host');
  });

  it('enforces the size limit even when the server understates content-length', async () => {
    const result = await downloadVerified({
      url: `${origin}/lies-about-length`,
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'big.bin'),
      policy: policyWith(origin),
      maxBytes: 4,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('too_large');
    expect(existsSync(join(scratch, 'tool', 'big.bin'))).toBe(false);
  });

  it('reports an HTTP error rather than treating it as content', async () => {
    const result = await downloadVerified({
      url: `${origin}/missing`,
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'missing.bin'),
      policy: policyWith(origin),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('http_error');
  });

  it('refuses plain HTTP for a non-loopback origin', async () => {
    const result = await downloadVerified({
      url: 'http://downloads.example.invalid/tool.bin',
      expectedSha256: PAYLOAD_SHA,
      destination: join(scratch, 'tool', 'insecure.bin'),
      policy: policyWith('http://downloads.example.invalid'),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('insecure_origin');
  });
});

void writeFileSync;
