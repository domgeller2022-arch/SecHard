import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { StackKind } from '../audit/detect.js';
import { sha256Hex } from '../evidence/digest.js';
import type { Finding } from '../domain/types.js';

/**
 * Inspects browser-shipped build output for privileged credential material.
 *
 * The distinction this module exists to make: a **publishable** key appearing in a client bundle is
 * correct and must not be reported as a leak, while a **privileged** key is a containment incident.
 * A scanner that flags both is a scanner whose findings get ignored.
 *
 * What it does not do: it reads text files. It does not execute the bundle, follow imports, or
 * attribute a value to whoever put it there. It also only covers the directory it is given — a
 * browser-only scan says nothing about server output, so the coverage it reports is exactly the
 * coverage it has.
 */

export interface Marker {
  readonly id: string;
  readonly pattern: RegExp;
  /** `privileged` is a finding; `publishable` is expected and classified rather than reported. */
  readonly kind: 'privileged' | 'publishable';
}

/**
 * Reviewed marker set.
 *
 * The fixture marker is deliberately included: it is the synthetic value the leak fixture plants, and
 * a check that cannot detect its own fixture has never been shown to work.
 *
 * The provider markers were extended in Batch W after the 2026-10-08 audit showed the original set
 * missed the commonest real leaks (a legacy Supabase service-role JWT, OpenAI, Stripe, and Anthropic
 * keys). A JWT cannot be judged by its shape alone, so JWT-shaped strings are decoded separately by
 * `classifyJwt` and judged by their `role` claim.
 */
export const DEFAULT_MARKERS: readonly Marker[] = [
  { id: 'supabase-secret-key', pattern: /\bsb_secret_[A-Za-z0-9_-]{10,}/g, kind: 'privileged' },
  { id: 'supabase-service-role-var', pattern: /\bSUPABASE_SERVICE_ROLE_KEY\b/g, kind: 'privileged' },
  { id: 'service-role-literal', pattern: /\bservice_role\b/g, kind: 'privileged' },
  { id: 'private-key-block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, kind: 'privileged' },
  { id: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, kind: 'privileged' },
  { id: 'openai-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, kind: 'privileged' },
  { id: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, kind: 'privileged' },
  { id: 'stripe-live-key', pattern: /\b[rs]k_live_[0-9A-Za-z]{10,}\b/g, kind: 'privileged' },
  { id: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, kind: 'privileged' },
  { id: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, kind: 'privileged' },
  { id: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, kind: 'privileged' },
  { id: 'twilio-api-key', pattern: /\bSK[0-9a-fA-F]{32}\b/g, kind: 'privileged' },
  { id: 'sendgrid-key', pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, kind: 'privileged' },
  { id: 'resend-key', pattern: /\bre_[A-Za-z0-9_]{20,}\b/g, kind: 'privileged' },
  { id: 'firebase-service-account', pattern: /"type"\s*:\s*"service_account"/g, kind: 'privileged' },
  { id: 'synthetic-leak-marker', pattern: /\bSYNTHETIC_PRIVILEGED_LEAK_MARKER\b/g, kind: 'privileged' },
  { id: 'supabase-publishable-key', pattern: /\bsb_publishable_[A-Za-z0-9_-]{10,}/g, kind: 'publishable' },
];

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

/**
 * A JWT-shaped value is judged by its `role` claim, not its shape: a Supabase anon/publishable JWT
 * belongs in a browser and must not be reported, while a legacy service-role JWT is a containment
 * incident. An unreadable payload is reported as privileged, because failing closed is the only safe
 * direction for credential material.
 */
export function classifyJwt(value: string): 'privileged' | 'publishable' {
  const payload = value.split('.')[1];
  if (payload === undefined) return 'privileged';
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { role?: unknown };
    if (decoded.role === 'anon' || decoded.role === 'publishable') return 'publishable';
    return 'privileged';
  } catch {
    return 'privileged';
  }
}

export interface AssetInventoryEntry {
  readonly path: string;
  readonly bytes: number;
  /** SHA-256 of the file bytes, present when the file was read within the review bounds. */
  readonly digest?: string;
}

export interface ClassificationRecord {
  readonly marker: string;
  readonly path: string;
  readonly kind: 'privileged' | 'publishable';
}

export interface ClientAssetReport {
  /** The directory actually inspected, stated so the coverage cannot be overread. */
  readonly inspectedRoot: string;
  readonly files: readonly AssetInventoryEntry[];
  readonly totalBytes: number;
  readonly findings: readonly Finding[];
  readonly classifications: readonly ClassificationRecord[];
  /** Files that ship to a browser and expose original source. */
  readonly sourceMaps: readonly string[];
  readonly coverage: 'complete' | 'partial' | 'unknown';
  readonly scopeStatement: string;
  readonly parseErrors: readonly string[];
}

export interface InspectOptions {
  readonly markers?: readonly Marker[];
  readonly maxFileBytes?: number;
  /** Files larger than this are recorded but not read as text. */
  readonly maxTextFileBytes?: number;
}

const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_TEXT_FILE_BYTES = 8 * 1024 * 1024;

export function inspectBrowserAssets(root: string, options: InspectOptions = {
}): ClientAssetReport {
  // R1-02: the scan root itself is checked before enumeration — a symlinked build-output root
  // would read outside the application and must become an explicit gap, not a complete scan.
  try {
    if (lstatSync(root).isSymbolicLink()) {
      return { inspectedRoot: root, files: [], totalBytes: 0, findings: [], classifications: [], sourceMaps: [], coverage: 'partial', scopeStatement: 'the browser-output root was not inspected',
        parseErrors: [`the browser-output root ${root} is a symlink and was not followed (R1-02)`] };
    }
  } catch (error) {
    // A missing root keeps the original empty/missing contract (unknown coverage); an
    // unreadable-but-present root is the explicit-gap case.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      return { inspectedRoot: root, files: [], totalBytes: 0, findings: [], classifications: [], sourceMaps: [], coverage: 'partial', scopeStatement: 'the browser-output root was not inspected',
        parseErrors: [`the browser-output root ${root} could not be inspected; nothing was scanned`] };
    }
  }
  const markers = options.markers ?? DEFAULT_MARKERS;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxTextFileBytes = options.maxTextFileBytes ?? DEFAULT_MAX_TEXT_FILE_BYTES;

  const files: AssetInventoryEntry[] = [];
  const findings: Finding[] = [];
  const classifications: ClassificationRecord[] = [];
  const sourceMaps: string[] = [];
  const parseErrors: string[] = [];
  let totalBytes = 0;

  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      // R1-03: lstat — a symlinked build-output directory or file is skipped, not followed.
      const stats = lstatSync(full);
      if (stats.isSymbolicLink()) continue;
      if (stats.isDirectory()) {
        walk(full);
        continue;
      }

      const shown = relative(root, full).split(sep).join('/');
      const isSourceMap = shown.endsWith('.map');
      if (isSourceMap) sourceMaps.push(shown);
      totalBytes += stats.size;

      if (stats.size > maxFileBytes) {
        files.push({ path: shown, bytes: stats.size });
        parseErrors.push(`${shown} is ${stats.size} bytes and was not inspected`);
        continue;
      }
      if (stats.size > maxTextFileBytes) {
        // Recorded in the inventory, but not read: a bundle this large is not text we can search
        // meaningfully, and pretending to have inspected it would overstate coverage.
        files.push({ path: shown, bytes: stats.size });
        parseErrors.push(`${shown} is ${stats.size} bytes and was not read as text`);
        continue;
      }

      let bytes: Buffer;
      try {
        bytes = readFileSync(full);
      } catch {
        parseErrors.push(`${shown} could not be read as text`);
        continue;
      }
      const text = bytes.toString('utf8');
      files.push({ path: shown, bytes: stats.size, digest: sha256Hex(bytes) });

      if (isSourceMap) {
        // A-21: the map is inspected below with the same markers and JWT classification as any
        // other shipped file — its raw text includes any embedded sourcesContent, so a secret in
        // the original source fires exactly as it would in a bundle. The structure check keeps a
        // malformed map from passing as verified coverage.
        try {
          JSON.parse(text) as unknown;
        } catch {
          parseErrors.push(`${shown} is not valid JSON — scanned as text, but the map structure (sources/sourcesContent) is unverified`);
        }
      }

      for (const marker of markers) {
        const pattern = new RegExp(marker.pattern.source, marker.pattern.flags);
        const match = pattern.exec(text);
        if (match === null) continue;

        if (marker.kind === 'publishable') {
          classifications.push({ marker: marker.id, path: shown, kind: marker.kind });
          continue;
        }

        findings.push({
          id: `client-assets:${marker.id}:${shown}`,
          tool: 'client-asset-inspection',
          rule_id: marker.id,
          title: `privileged credential material in browser-shipped output (${marker.id})`,
          severity: 'critical',
          category: 'secret',
          location: shown,
          detail: `marker '${marker.id}' found in a file that ships to the browser; value withheld`,
          redacted: true,
          secret_digest: sha256Hex(match[0] ?? ''),
          control_ids: ['SEC-02'],
          triage: 'unresolved',
        });
      }

      // JWT-shaped values are judged by their decoded role claim, not their shape: the legacy
      // Supabase service-role key is a JWT, and a shape-only rule cannot tell it from an anon key.
      for (const match of text.match(JWT_PATTERN) ?? []) {
        if (classifyJwt(match) === 'publishable') {
          classifications.push({ marker: 'jwt-role-publishable', path: shown, kind: 'publishable' });
          continue;
        }
        findings.push({
          id: `client-assets:jwt-privileged-role:${shown}`,
          tool: 'client-asset-inspection',
          rule_id: 'jwt-privileged-role',
          title: 'a JWT with a privileged or unreadable role claim ships to the browser',
          severity: 'critical',
          category: 'secret',
          location: shown,
          detail: 'the decoded payload claims a privileged role (or could not be decoded); value withheld',
          redacted: true,
          secret_digest: sha256Hex(match),
          control_ids: ['SEC-02'],
          triage: 'unresolved',
        });
      }
    }
  };

  try {
    walk(root);
  } catch (error) {
    return {
      inspectedRoot: root,
      files,
      totalBytes,
      findings,
      classifications,
      sourceMaps,
      coverage: 'unknown',
      scopeStatement: `browser output only: ${root}`,
      parseErrors: [...parseErrors, `could not walk ${root}: ${(error as Error).message}`],
    };
  }

  for (const map of sourceMaps) {
    findings.push({
      id: `client-assets:source-map:${map}`,
      tool: 'client-asset-inspection',
      rule_id: 'browser-source-map',
      title: 'a source map ships to the browser',
      severity: 'medium',
      location: map,
      detail: 'a browser-accessible source map exposes original source, including internal strings',
      control_ids: ['SEC-02', 'WEB-02'],
      triage: 'unresolved',
    });
  }

  return {
    inspectedRoot: root,
    files,
    totalBytes,
    findings,
    classifications,
    sourceMaps,
    // Coverage describes the directory inspected. It is never a claim about server output, other
    // artifacts, or the deployment.
    coverage: files.length === 0 ? 'unknown' : parseErrors.length === 0 ? 'complete' : 'partial',
    scopeStatement: `browser-shipped output under ${root} only; server output, deployment configuration, and other artifacts are outside this scan`,
    parseErrors,
  };
}

/** A deterministic digest over the inspected inventory: the same build yields the same value. */
export function inventoryDigest(report: ClientAssetReport): string {
  const hash = createHash('sha256');
  for (const entry of [...report.files].sort((a, b) => (a.path < b.path ? -1 : 1))) {
    // The per-file content digest makes same-size edits distinguishable in the inventory.
    hash.update(`${entry.path}:${entry.bytes}:${entry.digest ?? ''}\n`);
  }
  return hash.digest('hex');
}

/**
 * The reviewed browser-output directory shapes per stack. A stack with no reviewed browser
 * output has no candidates: Node CLI and server output are never browser-shipped merely because
 * a `dist` directory exists (A-32).
 */
export function browserOutputCandidates(kind: StackKind): readonly string[] {
  switch (kind) {
    case 'nextjs':
      return ['.next/static'];
    case 'sveltekit':
      return ['.svelte-kit/output/client', 'build'];
    case 'react-spa':
      return ['dist', 'build', 'out'];
    default:
      return [];
  }
}

/** The reviewed browser-output shape for their stack, trusted without further evidence. */
const FRAMEWORK_TRUSTED_BROWSER_DIRS: ReadonlySet<string> = new Set(['.next/static', '.svelte-kit/output/client']);

/** Bounded walk: does anything under this directory look like a browser entry point (.html)? */
function hasBrowserEntryPoint(dir: string): boolean {
  const stack: string[] = [dir];
  let visited = 0;
  while (stack.length > 0 && visited < 2000) {
    const current = stack.pop() as string;
    let entries: string[];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      visited += 1;
      if (visited >= 2000) return false;
      const full = join(current, entry);
      let stats;
      try {
        stats = lstatSync(full);
      } catch {
        continue;
      }
      if (stats.isSymbolicLink()) continue;
      if (stats.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (entry.endsWith('.html')) return true;
    }
  }
  return false;
}

export type BrowserOutputSelection =
  | { readonly root: string; readonly basis: string }
  | { readonly unsupported: string };

/**
 * Picks the browser-output root from the detected stack's reviewed candidates. A generic
 * candidate (`dist`, `build`, `out`) qualifies only with a browser entry point — a Node CLI's
 * compiled `dist` is server output and must not be scanned as browser-shipped (A-32).
 */
export function selectBrowserOutput(appRoot: string, kind: StackKind): BrowserOutputSelection {
  const candidates = browserOutputCandidates(kind);
  if (candidates.length === 0) {
    return { unsupported: `the detected stack (${kind}) has no reviewed browser-output shape; Node CLI and server output are not browser-shipped` };
  }
  const rejections: string[] = [];
  for (const candidate of candidates) {
    const full = join(appRoot, candidate);
    if (!existsSync(full)) {
      rejections.push(`${candidate}: not present`);
      continue;
    }
    if (FRAMEWORK_TRUSTED_BROWSER_DIRS.has(candidate)) {
      return { root: full, basis: `${candidate} is the reviewed browser-output directory for the detected ${kind} stack` };
    }
    if (!hasBrowserEntryPoint(full)) {
      rejections.push(`${candidate}: present but has no browser entry point (.html) — server or CLI output is not browser-shipped`);
      continue;
    }
    return { root: full, basis: `${candidate} contains a browser entry point (.html)` };
  }
  return { unsupported: `no browser build output for the detected ${kind} stack (${rejections.join('; ')})` };
}
