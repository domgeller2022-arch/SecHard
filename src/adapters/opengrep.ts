import type { Coverage, Finding } from '../domain/types.js';
import { sha256Hex } from '../evidence/digest.js';
import { relativizeLocation } from '../evidence/redaction.js';
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
    readonly metadata?: { readonly hardening_controls?: unknown; readonly hardening_severity?: unknown };
  };
}

export function parseOpengrepReport(
  raw: string,
  options: { readonly intendedScope?: readonly string[]; readonly appRoot?: string } = {},
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
      if (typeof path === 'string') {
        // Opengrep reports absolute machine paths even when run with the application root as its
        // working directory. Ids, locations, and recorded scope are all minted from the
        // root-relative form: the id must not embed the auditing host's layout, and recipe-level
        // scoping keys on path segments. Relativization happens once, here, where the id is built.
        scannedFiles.add(options.appRoot === undefined ? path : relativizeLocation(path, options.appRoot));
      }
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
    // Semgrep-derived tools prefix a local config file's path onto every rule id
    // (`…opengrep-rules.hardening.quality-empty-catch`). The rule's namespace is the reviewed pack
    // directory, so the id is the part after it; a registry-served id passes through unchanged.
    const packMarker = 'opengrep-rules.';
    const ruleId = checkId.includes(packMarker) ? checkId.slice(checkId.lastIndexOf(packMarker) + packMarker.length) : checkId;
    const path = typeof item.path === 'string' ? item.path : undefined;
    // Same root-relative form for the finding's identity and location as for the scanned files.
    const relativePath = path === undefined || options.appRoot === undefined ? path : relativizeLocation(path, options.appRoot);
    if (relativePath !== undefined) scannedFiles.add(relativePath);
    const line = typeof item.start?.line === 'number' ? item.start.line : undefined;
    const fingerprint = typeof item.extra?.fingerprint === 'string' ? item.extra.fingerprint : undefined;

    const controls = Array.isArray(item.extra?.metadata?.hardening_controls)
      ? (item.extra.metadata.hardening_controls as unknown[]).filter((entry): entry is string => typeof entry === 'string')
      : [];

    // The reviewed rule packs may pin a severity above the level mapping (`hardening_severity`):
    // the unverified-Stripe-webhook rule is critical, not high. Only a valid severity name is
    // honoured; anything else falls back to the level mapping.
    const levelSeverity = severityFromRuleLevel(typeof item.extra?.severity === 'string' ? item.extra.severity : undefined);
    const pinned = item.extra?.metadata?.hardening_severity;
    const severity =
      pinned === 'critical' || pinned === 'high' || pinned === 'medium' || pinned === 'low'
        ? pinned
        : levelSeverity;

    findings.push({
      id: stableFindingId(['opengrep', ruleId, relativePath, line, fingerprint]),
      tool: 'opengrep',
      rule_id: ruleId,
      title: typeof item.extra?.message === 'string' ? item.extra.message : ruleId,
      severity,
      ...(relativePath === undefined ? {} : { location: line === undefined ? relativePath : `${relativePath}:${line}` }),
      ...(fingerprint === undefined ? {} : { resource: fingerprint }),
      // A-03 (PR-04): the matched source line is never persisted — it can carry secret material
      // from the audited tree. The match identity is the digest; the location says where to look.
      ...(typeof item.extra?.lines === 'string' ? { detail: `matched line digest: ${sha256Hex(item.extra.lines)}` } : {}),
      ...(controls.length === 0 ? {} : { control_ids: controls }),
      triage: 'unresolved',
    });
  }

  const observed = scannedFiles.size;
  const expected = options.intendedScope?.length ?? observed;
  // P3.1 (A-10): the intended scope is the independent inventory, so coverage is verified against
  // it, never against the scanner's self-report alone. Inventoried files the scanner did not
  // report examining, and any tool-reported failure or malformed report entry, keep the scan from
  // claiming complete.
  const scannerErrorCount = Array.isArray(errors) ? errors.length : 0;
  const unexaminedPaths =
    options.intendedScope === undefined ? [] : options.intendedScope.filter((path) => !scannedFiles.has(path));
  const unexamined = options.intendedScope === undefined ? undefined : unexaminedPaths.length;
  const interrupted = parserErrors.length > 0;
  const coverage: Coverage =
    observed === 0
      ? 'unknown'
      : options.intendedScope === undefined
        ? !interrupted && (expected === 0 || observed >= expected)
          ? 'complete'
          : 'partial'
        : !interrupted && unexamined === 0
          ? 'complete'
          : 'partial';

  const scopeNotes = [
    'Files opengrep reported scanning. Its rules are syntactic; cross-file analysis is not performed and not claimed.',
    ...(options.intendedScope === undefined
      ? []
      : [`intended scope: ${String(expected)} relevant file(s) from the independent inventory`]),
    ...(unexamined !== undefined && unexamined > 0
      ? [`unexamined: ${String(unexamined)} inventoried file(s) the scanner did not report examining (${unexaminedPaths.slice(0, 5).join(', ')}${unexaminedPaths.length > 5 ? ', …' : ''})`]
      : []),
    ...(scannerErrorCount > 0 ? [`scanner-reported failures: ${String(scannerErrorCount)}`] : []),
    ...(parserErrors.length - scannerErrorCount > 0
      ? [`malformed report entries skipped: ${String(parserErrors.length - scannerErrorCount)}`]
      : []),
  ];

  return {
    tool: 'opengrep',
    findings,
    scope: {
      expected,
      observed,
      files: [...scannedFiles].sort(),
      ...(unexamined === undefined ? {} : { unexamined }),
      ...(scannerErrorCount === 0 ? {} : { failed: scannerErrorCount }),
      notes: scopeNotes.join(' '),
    },
    coverage,
    parserErrors,
  } satisfies AdapterOutcome;
}
