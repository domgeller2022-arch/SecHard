import type { Finding } from '../domain/types.js';
import { isRecord, parseJsonReport, severityFromRuleLevel, stableFindingId, type AdapterOutcome } from './types.js';

/**
 * Opengrep adapter.
 *
 * Scope limits, stated rather than implied: these rules are syntactic. Opengrep's
 * `--taint-intrafile` mode includes inter-method flow within a single file; it is not universal
 * cross-file analysis, and this adapter does not claim it. A match is a review candidate to triage,
 * not proof of exploitability, and static analysis is never an authorization proof.
 *
 * Severity is mapped from the tool's rule level: ERROR → high, WARNING → medium, INFO → low. The
 * mapping is a reviewed decision recorded here and asserted in the adapter tests.
 */

interface OpengrepFinding {
  readonly check_id?: unknown;
  readonly path?: unknown;
  readonly start?: { readonly line?: unknown; readonly col?: unknown };
  readonly end?: { readonly line?: unknown };
  readonly extra?: {
    readonly message?: unknown;
    readonly severity?: unknown;
    readonly fingerprint?: unknown;
    readonly lines?: unknown;
    readonly metadata?: { readonly hardening_controls?: unknown };
  };
}

export function parseOpengrepReport(
  raw: string,
  options: { readonly intendedScope?: readonly string[] } = {},
): AdapterOutcome | { error: string } {
  const parsed = parseJsonReport(raw, 'opengrep');
  if (!parsed.ok) return { error: parsed.error };

  if (!isRecord(parsed.value)) {
    return { error: 'opengrep: report is not a JSON object; the output format may have changed or the scan failed' };
  }

  const errors = (parsed.value as { errors?: unknown }).errors;
  const parserErrors: string[] = [];
  if (Array.isArray(errors) && errors.length > 0) {
    for (const [index, error] of errors.entries()) {
      parserErrors.push(`opengrep: reported error ${index}: ${JSON.stringify(error).slice(0, 200)}`);
    }
  }

  const results = (parsed.value as { results?: unknown }).results;
  if (results !== undefined && !Array.isArray(results)) {
    return { error: 'opengrep: results is not an array' };
  }

  const findings: Finding[] = [];
  const scannedFiles = new Set<string>();

  const paths = (parsed.value as { paths?: { scanned?: unknown } }).paths;
  if (isRecord(paths) && Array.isArray((paths as { scanned?: unknown }).scanned)) {
    for (const path of (paths as { scanned: unknown[] }).scanned) {
      if (typeof path === 'string') scannedFiles.add(path);
    }
  }

  for (const [index, entry] of (results ?? []).entries()) {
    if (!isRecord(entry)) {
      parserErrors.push(`opengrep: finding ${index} is not an object and was skipped`);
      continue;
    }
    const item = entry as OpengrepFinding;
    const checkId = typeof item.check_id === 'string' ? item.check_id : undefined;
    if (checkId === undefined) {
      parserErrors.push(`opengrep: finding ${index} has no check_id and was skipped`);
      continue;
    }
    const path = typeof item.path === 'string' ? item.path : undefined;
    if (path !== undefined) scannedFiles.add(path);
    const line = typeof item.start?.line === 'number' ? item.start.line : undefined;
    const fingerprint = typeof item.extra?.fingerprint === 'string' ? item.extra.fingerprint : undefined;

    const controls = Array.isArray(item.extra?.metadata?.hardening_controls)
      ? (item.extra.metadata.hardening_controls as unknown[]).filter((entry): entry is string => typeof entry === 'string')
      : [];

    findings.push({
      id: stableFindingId(['opengrep', checkId, path, line, fingerprint]),
      tool: 'opengrep',
      rule_id: checkId,
      title: typeof item.extra?.message === 'string' ? item.extra.message : checkId,
      severity: severityFromRuleLevel(typeof item.extra?.severity === 'string' ? item.extra.severity : undefined),
      ...(path === undefined ? {} : { location: line === undefined ? path : `${path}:${line}` }),
      ...(fingerprint === undefined ? {} : { resource: fingerprint }),
      ...(typeof item.extra?.lines === 'string' ? { detail: `matched: ${item.extra.lines.trim()}` } : {}),
      ...(controls.length === 0 ? {} : { control_ids: controls }),
      triage: 'unresolved',
    });
  }

  const observed = scannedFiles.size;
  const expected = options.intendedScope?.length ?? observed;

  return {
    tool: 'opengrep',
    findings,
    scope: {
      expected,
      observed,
      files: [...scannedFiles].sort(),
      notes: 'Files opengrep reported scanning. Its rules are syntactic; cross-file analysis is not performed and not claimed.',
    },
    coverage: observed === 0 ? 'unknown' : expected === 0 || observed >= expected ? 'complete' : 'partial',
    parserErrors,
  } satisfies AdapterOutcome;
}
