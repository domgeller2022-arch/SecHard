import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import type { Finding } from '../domain/types.js';
import { validateAgainstSchema } from '../validation/schema.js';
import type { AdapterOutcome } from './types.js';

/**
 * The live HTTP recipe.
 *
 * It asserts the requirements an application declares for its routes — headers, private-response
 * caching, and content that must not appear — rather than assigning a letter grade. Grading a site
 * hides which requirement failed; a named requirement that fails is actionable.
 *
 * Boundaries this recipe respects:
 *
 * - **Only approved targets.** Targets come from a validated inventory. A host suggested by a
 *   finding, a scanner, or a fetched page is not a target, and nothing here will contact one.
 * - **Bounded requests.** Time and response size are capped, and the body is read through a limit
 *   rather than after the fact.
 * - **Redirects are checked, not followed blindly.** A redirect to a host outside the approved list
 *   is a finding.
 * - **No authentication.** This recipe performs anonymous requests only. An authenticated
 *   requirement cannot be met by it, and it does not claim to.
 */

export interface HeaderRequirement {
  readonly name: string;
  readonly value_contains?: string;
}

export interface RouteRequirement {
  readonly route_prefix: string;
  readonly private?: boolean;
  readonly required_headers?: readonly HeaderRequirement[];
  readonly must_not_appear?: readonly string[];
}

export interface LiveTarget {
  readonly id: string;
  readonly scheme: 'http' | 'https';
  readonly host: string;
  readonly port?: number;
  readonly environment: 'local' | 'preview' | 'staging' | 'production';
  readonly routes: readonly string[];
  readonly approved_redirect_hosts: readonly string[];
  readonly response_limits?: { readonly max_bytes?: number; readonly timeout_ms?: number };
  readonly tls?: { readonly required: boolean; readonly min_days_valid?: number };
  readonly requirements: readonly RouteRequirement[];
}

export interface TargetInventory {
  readonly schema_version: string;
  readonly targets: readonly LiveTarget[];
}

const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

export function loadTargetInventory(file: string): { inventory?: TargetInventory; issues: string[] } {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return { issues: [`target inventory not found: ${file}`] };
  }

  let parsed: unknown;
  try {
    parsed = parse(raw);
  } catch (error) {
    return { issues: [`target inventory is not valid YAML: ${(error as Error).message}`] };
  }

  const result = validateAgainstSchema('live-targets', parsed, file);
  if (!result.valid) {
    return { issues: result.issues.map((issue) => `${issue.path ?? '$'}: ${issue.message}`) };
  }

  const inventory = parsed as TargetInventory;
  const issues: string[] = [];
  for (const target of inventory.targets) {
    // A wildcard is not an inventory, and a scheme without TLS requirements on a non-local
    // environment is a claim this repository will not let pass silently.
    if (target.host.includes('*')) issues.push(`${target.id}: wildcard hosts are not accepted`);
    if (target.scheme === 'http' && target.environment !== 'local') {
      issues.push(`${target.id}: plain HTTP is only acceptable for the local environment`);
    }
    if (target.scheme === 'https' && target.tls?.required !== true) {
      issues.push(`${target.id}: an HTTPS target must state that TLS is required`);
    }
    const duplicate = inventory.targets.filter((other) => other.id === target.id).length > 1;
    if (duplicate) issues.push(`${target.id}: duplicate target id`);
  }

  return { inventory, issues };
}

export interface HttpRunOptions {
  readonly environment: LiveTarget['environment'];
  readonly fetchImpl?: typeof fetch;
  readonly now?: Date;
}

function url(target: LiveTarget, route: string): string {
  const port = target.port === undefined ? '' : `:${target.port}`;
  return `${target.scheme}://${target.host}${port}${route}`;
}

/**
 * The full text of a fetch failure. Node's fetch wraps the socket error as `cause`, so the TLS
 * classification lives on `error.cause.message` ("unable to verify the first certificate") while
 * `error.message` is only "fetch failed". Reading only the outer message misclassifies a TLS
 * failure as a generic unreachable route — found by the audit live-target test, not by reading.
 */
function fetchErrorText(error: unknown): string {
  const outer = error as { message?: string; cause?: unknown };
  const cause = outer.cause as { message?: string; cause?: unknown } | undefined;
  const nested = cause?.cause as { message?: string } | undefined;
  return [outer.message, cause?.message, nested?.message].filter((part) => typeof part === 'string' && part.length > 0).join(': ');
}

/**
 * Reads a response body without allowing it to exceed the limit.
 */
async function boundedBody(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    const remaining = maxBytes - total;
    if (remaining <= 0) {
      await reader.cancel();
      break;
    }
    const slice = value.byteLength > remaining ? value.subarray(0, remaining) : value;
    chunks.push(slice);
    total += slice.byteLength;
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8');
}

export async function runHttpChecks(
  inventory: TargetInventory,
  options: HttpRunOptions,
): Promise<AdapterOutcome> {
  const doFetch = options.fetchImpl ?? fetch;
  const findings: Finding[] = [];
  const parserErrors: string[] = [];
  const files: string[] = [];
  let expected = 0;
  let observed = 0;

  for (const target of inventory.targets.filter((entry) => entry.environment === options.environment)) {
    const maxBytes = target.response_limits?.max_bytes ?? DEFAULT_MAX_BYTES;
    const timeoutMs = target.response_limits?.timeout_ms ?? DEFAULT_TIMEOUT_MS;

    for (const route of target.routes) {
      expected += 1;
      const address = url(target, route);
      let response: Response;
      try {
        response = await doFetch(address, {
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: { 'user-agent': 'hardening-live-check' },
        });
      } catch (error) {
        const message = fetchErrorText(error);
        const tlsFailure = /certificate|self[- ]signed|unable to verify|ERR_TLS/i.test(message);
        findings.push({
          id: `http:${target.id}:${route}:unreachable`,
          tool: 'live-http-check',
          rule_id: tlsFailure ? 'tls-invalid' : 'route-unreachable',
          title: tlsFailure ? 'the TLS connection could not be verified' : 'the approved target could not be reached',
          severity: tlsFailure ? 'critical' : 'high',
          location: address,
          detail: tlsFailure
            ? 'certificate validation failed; a transport requirement cannot be satisfied by an unverified connection'
            : `request failed: ${message}`,
          control_ids: ['WEB-02', 'DEPLOY-01'],
          triage: 'unresolved',
        });
        continue;
      }

      observed += 1;
      files.push(route);

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location') ?? '';
        let redirectHost = '';
        try {
          redirectHost = new URL(location, address).hostname;
        } catch {
          redirectHost = '';
        }
        if (!target.approved_redirect_hosts.includes(redirectHost)) {
          findings.push({
            id: `http:${target.id}:${route}:redirect`,
            tool: 'live-http-check',
            rule_id: 'unapproved-redirect',
            title: 'a route redirects to a host that is not approved',
            severity: 'medium',
            location: address,
            detail: `redirect target '${redirectHost || location || 'unknown'}' is not in the approved redirect hosts`,
            control_ids: ['WEB-02', 'DEPLOY-01'],
            triage: 'unresolved',
          });
        }
        continue;
      }

      if (response.status >= 400) {
        findings.push({
          id: `http:${target.id}:${route}:status`,
          tool: 'live-http-check',
          rule_id: 'route-unreachable',
          title: `a declared route returned ${response.status}`,
          severity: response.status >= 500 ? 'high' : 'medium',
          location: address,
          detail: 'a declared route should be reachable; adjust the inventory or fix the route',
          control_ids: ['WEB-02'],
          triage: 'unresolved',
        });
        // Still inspect headers and body: a 4xx can leak as much as a 200.
      }

      const requirements = target.requirements.filter((requirement) => route.startsWith(requirement.route_prefix));
      const body = await boundedBody(response, maxBytes);

      for (const requirement of requirements) {
        for (const header of requirement.required_headers ?? []) {
          const value = response.headers.get(header.name);
          if (value === null) {
            findings.push({
              id: `http:${target.id}:${route}:header:${header.name}`,
              tool: 'live-http-check',
              rule_id: 'missing-security-header',
              title: `required header '${header.name}' is absent`,
              severity: 'medium',
              location: address,
              control_ids: ['WEB-02'],
              triage: 'unresolved',
            });
            continue;
          }
          if (header.value_contains !== undefined && !value.includes(header.value_contains)) {
            findings.push({
              id: `http:${target.id}:${route}:header-value:${header.name}`,
              tool: 'live-http-check',
              rule_id: 'header-value-mismatch',
              title: `header '${header.name}' does not contain the required value`,
              severity: 'medium',
              location: address,
              detail: `expected to contain '${header.value_contains}'`,
              control_ids: ['WEB-02'],
              triage: 'unresolved',
            });
          }
        }

        if (requirement.private === true) {
          const cacheControl = (response.headers.get('cache-control') ?? '').toLowerCase();
          if (cacheControl.includes('public') || /s-maxage=[1-9]/.test(cacheControl)) {
            findings.push({
              id: `http:${target.id}:${route}:cache`,
              tool: 'live-http-check',
              rule_id: 'private-route-publicly-cacheable',
              title: 'a private route is publicly cacheable',
              severity: 'high',
              location: address,
              detail: `cache-control: ${cacheControl}`,
              control_ids: ['WEB-02', 'AUTHZ-01'],
              triage: 'unresolved',
            });
          }
        }

        for (const forbidden of requirement.must_not_appear ?? []) {
          if (body.includes(forbidden)) {
            findings.push({
              id: `http:${target.id}:${route}:body:${forbidden}`,
              tool: 'live-http-check',
              rule_id: 'sensitive-content-in-response',
              title: 'response contains content that must not appear',
              severity: 'high',
              location: address,
              detail: 'the response matched a configured forbidden pattern; the matched value is withheld',
              redacted: true,
              resource: forbidden,
              control_ids: ['WEB-01', 'SEC-02', 'OPS-01'],
              triage: 'unresolved',
            });
          }
        }
      }
    }
  }

  const notes = [
    'anonymous requests only; an authenticated requirement cannot be satisfied by this recipe',
    'TLS: a successful HTTPS fetch means Node validated the certificate chain and expiry against its trust store. Protocol versions, ciphers, and configuration depth are not assessed here and require current testssl.sh output or manual evidence.',
  ];
  if (options.environment === 'production') {
    notes.push('a production target that requires TLS must also provide current TLS evidence; this recipe does not substitute for it');
  }

  return {
    tool: 'live-http-check',
    findings,
    scope: { expected, observed, files, notes: notes.join('; ') },
    coverage: expected === 0 ? 'unknown' : observed === expected ? 'complete' : 'partial',
    parserErrors,
  };
}
