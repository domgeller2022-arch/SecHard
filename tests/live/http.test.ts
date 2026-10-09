import { createServer, type Server } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadTargetInventory, runHttpChecks, type LiveTarget, type TargetInventory } from '../../src/adapters/http.js';

/**
 * The live HTTP recipe, exercised against a local server that can be made to break in each of the
 * ways the recipe exists to catch. Real HTTP, real headers, real redirects.
 */

const scratch = mkdtempSync(join(tmpdir(), 'hardening-http-'));
let server: Server;
let port = 0;

beforeAll(async () => {
  server = createServer((request, response) => {
    switch (request.url ?? '/') {
      case '/ok':
        response.writeHead(200, {
          'content-type': 'text/plain',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
        });
        response.end('fine');
        return;
      case '/missing-header':
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('no headers here');
        return;
      case '/wrong-header':
        response.writeHead(200, { 'content-type': 'text/plain', 'x-content-type-options': 'sniff' });
        response.end('wrong value');
        return;
      case '/leak':
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('Error: boom\n    at Object.<anonymous> (/srv/node_modules/next/server.js:1)');
        return;
      case '/private-public':
        response.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'public, s-maxage=60' });
        response.end('private, supposedly');
        return;
      case '/redirect-bad':
        response.writeHead(302, { location: 'https://evil.example.invalid/' });
        response.end();
        return;
      case '/redirect-ok':
        response.writeHead(302, { location: 'http://localhost/ok' });
        response.end();
        return;
      case '/boom':
        response.writeHead(500, { 'content-type': 'text/plain' });
        response.end('server error');
        return;
      default:
        response.writeHead(404);
        response.end('not found');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no address');
  port = address.port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(scratch, { recursive: true, force: true });
});

function target(overrides: Partial<LiveTarget> = {}): LiveTarget {
  return {
    id: 'test',
    scheme: 'http',
    host: '127.0.0.1',
    port,
    environment: 'local',
    routes: ['/ok'],
    approved_redirect_hosts: [],
    requirements: [
      {
        route_prefix: '/',
        required_headers: [
          { name: 'x-content-type-options', value_contains: 'nosniff' },
          { name: 'x-frame-options' },
        ],
        must_not_appear: ['at Object.<anonymous>', 'node_modules'],
      },
    ],
    ...overrides,
  };
}

const inventory = (targets: LiveTarget[]): TargetInventory => ({ schema_version: 'live-targets/v1', targets });

describe('requirements are asserted per route', () => {
  it('passes a route that satisfies every requirement', async () => {
    const outcome = await runHttpChecks(inventory([target()]), { environment: 'local' });
    expect(outcome.findings).toEqual([]);
    expect(outcome.coverage).toBe('complete');
    expect(outcome.scope.observed).toBe(1);
  });

  it('reports a missing required header', async () => {
    const outcome = await runHttpChecks(inventory([target({ routes: ['/missing-header'] })]), { environment: 'local' });
    expect(outcome.findings.map((finding) => finding.rule_id)).toContain('missing-security-header');
  });

  it('reports a header whose value does not match the requirement', async () => {
    const outcome = await runHttpChecks(inventory([target({ routes: ['/wrong-header'] })]), { environment: 'local' });
    expect(outcome.findings.map((finding) => finding.rule_id)).toContain('header-value-mismatch');
  });

  it('reports sensitive content such as a stack trace, without echoing the match', async () => {
    const outcome = await runHttpChecks(inventory([target({ routes: ['/leak'] })]), { environment: 'local' });
    const finding = outcome.findings.find((entry) => entry.rule_id === 'sensitive-content-in-response');
    expect(finding).toBeDefined();
    expect(finding?.redacted).toBe(true);
    expect(JSON.stringify(finding)).not.toContain('at Object.<anonymous> (/srv');
  });

  it('reports a private route that is publicly cacheable', async () => {
    const outcome = await runHttpChecks(
      inventory([target({ routes: ['/private-public'], requirements: [{ route_prefix: '/private', private: true }] })]),
      { environment: 'local' },
    );
    expect(outcome.findings.map((finding) => finding.rule_id)).toContain('private-route-publicly-cacheable');
  });
});

describe('redirects and reachability', () => {
  it('reports a redirect to a host that is not approved', async () => {
    const outcome = await runHttpChecks(inventory([target({ routes: ['/redirect-bad'] })]), { environment: 'local' });
    expect(outcome.findings.map((finding) => finding.rule_id)).toContain('unapproved-redirect');
  });

  it('accepts a redirect to an approved host', async () => {
    const outcome = await runHttpChecks(
      inventory([target({ routes: ['/redirect-ok'], approved_redirect_hosts: ['localhost'] })]),
      { environment: 'local' },
    );
    expect(outcome.findings).toEqual([]);
  });

  it('treats a declared route returning 500 as a high finding', async () => {
    const outcome = await runHttpChecks(inventory([target({ routes: ['/boom'] })]), { environment: 'local' });
    expect(outcome.findings.find((entry) => entry.rule_id === 'route-unreachable')?.severity).toBe('high');
  });

  it('reports an unreachable target and marks coverage partial rather than clean', async () => {
    const outcome = await runHttpChecks(inventory([target({ port: 9, routes: ['/ok'] })]), { environment: 'local' });
    expect(outcome.findings[0]?.rule_id).toBe('route-unreachable');
    expect(outcome.coverage).toBe('partial');
    expect(outcome.scope.observed).toBe(0);
  });

  it('classifies a TLS failure even when fetch nests the real error in cause', async () => {
    // Node's fetch reports certificate failures as "fetch failed" with the socket error on
    // `.cause`. Reading only the outer message classified a broken TLS target as a generic
    // unreachable route — found by the audit live-target acceptance, fixed with a regression test.
    const nested = new Error('unable to verify the first certificate');
    const wrapped = Object.assign(new Error('fetch failed'), { cause: nested });
    const outcome = await runHttpChecks(
      inventory([target({ scheme: 'https', environment: 'production', tls: { required: true }, routes: ['/'] })]),
      {
        environment: 'production',
        fetchImpl: (() => {
          throw wrapped;
        }) as typeof fetch,
      },
    );
    expect(outcome.findings[0]?.rule_id).toBe('tls-invalid');
    expect(outcome.findings[0]?.severity).toBe('critical');
  });

  it('claims unknown coverage when no route was declared for the environment', async () => {
    const outcome = await runHttpChecks(inventory([target({ environment: 'production' })]), { environment: 'local' });
    expect(outcome.coverage).toBe('unknown');
    expect(outcome.scope.expected).toBe(0);
  });

  it('never contacts a target outside the requested environment', async () => {
    const outcome = await runHttpChecks(
      inventory([target({ id: 'prod', environment: 'production', routes: ['/leak'] })]),
      { environment: 'local' },
    );
    expect(outcome.findings).toEqual([]);
    expect(outcome.scope.observed).toBe(0);
  });
});

describe('only validated inventories are used', () => {
  let counter = 0;
  function writeInventory(contents: unknown): string {
    counter += 1;
    const file = join(scratch, `targets-${counter}.json`);
    writeFileSync(file, JSON.stringify(contents), 'utf8');
    return file;
  }

  const valid = {
    schema_version: 'live-targets/v1',
    targets: [
      {
        id: 'local-app',
        scheme: 'http',
        host: '127.0.0.1',
        port: 3100,
        environment: 'local',
        routes: ['/'],
        approved_redirect_hosts: [],
        requirements: [{ route_prefix: '/' }],
      },
    ],
  };

  it('accepts a valid inventory', () => {
    const result = loadTargetInventory(writeInventory(valid));
    expect(result.issues).toEqual([]);
    expect(result.inventory?.targets).toHaveLength(1);
  });

  it('rejects a wildcard host', () => {
    const result = loadTargetInventory(
      writeInventory({ ...valid, targets: [{ ...valid.targets[0], host: '*.example.invalid' }] }),
    );
    expect(result.issues.join(' ')).toMatch(/wildcard/);
  });

  it('rejects plain HTTP outside the local environment', () => {
    const result = loadTargetInventory(
      writeInventory({ ...valid, targets: [{ ...valid.targets[0], environment: 'production' }] }),
    );
    expect(result.issues.join(' ')).toMatch(/plain HTTP/);
  });

  it('rejects an HTTPS target that does not state TLS is required', () => {
    const result = loadTargetInventory(
      writeInventory({
        ...valid,
        targets: [{ ...valid.targets[0], scheme: 'https', environment: 'production', tls: { required: false } }],
      }),
    );
    expect(result.issues.join(' ')).toMatch(/must state that TLS is required/);
  });

  it('rejects an inventory that does not match the schema', () => {
    const result = loadTargetInventory(writeInventory({ schema_version: 'live-targets/v1', targets: [{}] }));
    expect(result.issues.length).toBeGreaterThan(0);
    expect(result.inventory).toBeUndefined();
  });

  it('reports a missing inventory file rather than defaulting to no targets', () => {
    expect(loadTargetInventory(join(scratch, 'absent.yaml')).issues[0]).toMatch(/not found/);
  });
});
