import type { Finding } from '../domain/types.js';
import { isRecord, parseJsonReport, severityFromWord, stableFindingId, type AdapterOutcome } from './types.js';

/**
 * zizmor adapter.
 *
 * zizmor audit severities come from its own determinations (`Low`..`High`). They are mapped by word.
 * zizmor reports each workflow as a JSON array of findings, each with a symbolic location naming the
 * file and a concrete location giving the line.
 */

interface ZizmorLocation {
  readonly symbolic?: {
    readonly key?: { readonly Local?: { readonly verbatim_path?: unknown } };
    readonly annotation?: unknown;
  };
  readonly concrete?: { readonly location?: { readonly start_point?: { readonly row?: unknown } } };
}

interface ZizmorFinding {
  readonly ident?: unknown;
  readonly desc?: unknown;
  readonly url?: unknown;
  readonly determinations?: { readonly severity?: unknown; readonly confidence?: unknown };
  readonly locations?: readonly ZizmorLocation[];
  readonly fixes?: readonly { readonly title?: unknown }[];
  readonly ignored?: unknown;
}

export function parseZizmorReport(raw: string, options: { readonly intendedScope?: readonly string[] } = {}): AdapterOutcome | { error: string } {
  const parsed = parseJsonReport(raw, 'zizmor');
  if (!parsed.ok) return { error: parsed.error };

  if (!Array.isArray(parsed.value)) {
    return { error: 'zizmor: report is not a JSON array; the output format may have changed or the audit failed' };
  }

  const findings: Finding[] = [];
  const parserErrors: string[] = [];
  const auditedFiles = new Set<string>();
  let ignoredCount = 0;

  for (const [index, entry] of parsed.value.entries()) {
    if (!isRecord(entry)) {
      parserErrors.push(`zizmor: finding ${index} is not an object and was skipped`);
      continue;
    }
    const item = entry as ZizmorFinding;
    const ident = typeof item.ident === 'string' ? item.ident : undefined;
    if (ident === undefined) {
      parserErrors.push(`zizmor: finding ${index} has no ident and was skipped`);
      continue;
    }

    for (const location of item.locations ?? []) {
      const path = location.symbolic?.key?.Local?.verbatim_path;
      if (typeof path === 'string') auditedFiles.add(path);
    }

    if (item.ignored === true) {
      ignoredCount += 1;
      continue;
    }

    const severity = severityFromWord(
      typeof item.determinations?.severity === 'string' ? item.determinations.severity : undefined,
    );
    const primary = item.locations?.[0];
    const path =
      typeof primary?.symbolic?.key?.Local?.verbatim_path === 'string'
        ? primary.symbolic.key.Local.verbatim_path
        : undefined;
    const row = typeof primary?.concrete?.location?.start_point?.row === 'number' ? primary.concrete.location.start_point.row : undefined;
    const annotation = typeof primary?.symbolic?.annotation === 'string' ? primary.symbolic.annotation : undefined;
    const fix = typeof item.fixes?.[0]?.title === 'string' ? item.fixes[0].title : undefined;

    findings.push({
      id: stableFindingId(['zizmor', ident, path, row]),
      tool: 'zizmor',
      rule_id: ident,
      title: typeof item.desc === 'string' ? item.desc : ident,
      severity,
      ...(path === undefined ? {} : { location: row === undefined ? path : `${path}:${row}` }),
      ...(typeof item.url === 'string' ? { resource: item.url } : {}),
      detail: [annotation, fix === undefined ? undefined : `suggested fixed: ${fix}`].filter((part) => part !== undefined).join('; '),
      control_ids: ['CI-01', 'CI-02'],
      triage: 'unresolved',
    });
  }

  const observed = auditedFiles.size;
  const expected = options.intendedScope?.length ?? observed;

  return {
    tool: 'zizmor',
    findings,
    scope: {
      expected,
      observed,
      ...(observed === 0 ? {} : { files: [...auditedFiles].sort() }),
      ...(ignoredCount === 0 ? {} : { notes: `${ignoredCount} ignored finding(s) reported by inline configuration and excluded` }),
    },
    // zizmor names the files it audited, so a file-level claim is supportable.
    coverage: observed === 0 ? 'unknown' : expected === 0 || observed >= expected ? 'complete' : 'partial',
    parserErrors,
  } satisfies AdapterOutcome;
}
