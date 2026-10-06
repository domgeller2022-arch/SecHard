import type { Finding } from '../domain/types.js';
import { isRecord, parseJsonReport, severityFromCvss, stableFindingId, type AdapterOutcome } from './types.js';

/**
 * OSV-Scanner adapter.
 *
 * Advisories are grouped per package: a group collects the identifiers that describe one issue across
 * ecosystems (GHSA, CVE, and others). The group is the finding, so one advisory produces one finding
 * rather than one per alias.
 *
 * Severity is derived from the group's `max_severity` CVSS score using a documented mapping. When the
 * score is absent the severity stays `unknown`, which the gate requires a human to triage. OSV
 * coverage is per package, not per file, and the adapter reports it that way.
 *
 * Advisory data provenance (online query versus offline database, and when the data was obtained) is
 * the runner's to record; this parser only reads the report it was given.
 */

interface OsvGroup {
  readonly ids?: readonly unknown[];
  readonly aliases?: readonly unknown[];
  readonly max_severity?: unknown;
}

interface OsvPackage {
  readonly package?: { readonly name?: unknown; readonly version?: unknown; readonly ecosystem?: unknown };
  readonly groups?: readonly OsvGroup[];
  readonly vulnerabilities?: readonly { readonly id?: unknown; readonly summary?: unknown; readonly details?: unknown }[];
}

interface OsvResult {
  readonly source?: { readonly path?: unknown; readonly type?: unknown };
  readonly packages?: readonly OsvPackage[];
}

export function parseOsvReport(
  raw: string,
  options: { readonly expectedPackages?: number; readonly intendedScope?: readonly string[] } = {},
): AdapterOutcome | { error: string } {
  const parsed = parseJsonReport(raw, 'osv-scanner');
  if (!parsed.ok) return { error: parsed.error };

  if (!isRecord(parsed.value)) {
    return { error: 'osv-scanner: report is not a JSON object; the output format may have changed or the scan failed' };
  }

  const results = (parsed.value as { results?: unknown }).results;
  if (results !== undefined && !Array.isArray(results)) {
    return { error: 'osv-scanner: results is not an array' };
  }

  const findings: Finding[] = [];
  const parserErrors: string[] = [];
  const scannedPackages = new Set<string>();
  const sources: string[] = [];

  for (const [resultIndex, resultEntry] of (results ?? []).entries()) {
    if (!isRecord(resultEntry)) {
      parserErrors.push(`osv-scanner: result ${resultIndex} is not an object and was skipped`);
      continue;
    }
    const result = resultEntry as OsvResult;
    if (typeof result.source?.path === 'string') sources.push(result.source.path);

    for (const [packageIndex, packageEntry] of (result.packages ?? []).entries()) {
      if (!isRecord(packageEntry)) {
        parserErrors.push(`osv-scanner: package ${resultIndex}.${packageIndex} is not an object and was skipped`);
        continue;
      }
      const pkg = packageEntry as OsvPackage;
      const name = typeof pkg.package?.name === 'string' ? pkg.package.name : undefined;
      const version = typeof pkg.package?.version === 'string' ? pkg.package.version : undefined;
      const ecosystem = typeof pkg.package?.ecosystem === 'string' ? pkg.package.ecosystem : undefined;
      if (name === undefined) {
        parserErrors.push(`osv-scanner: package ${resultIndex}.${packageIndex} has no name and was skipped`);
        continue;
      }
      scannedPackages.add(`${name}@${version ?? 'unknown'}`);

      const details = new Map<string, { summary?: string; details?: string }>();
      for (const vulnerability of pkg.vulnerabilities ?? []) {
        const id = typeof vulnerability.id === 'string' ? vulnerability.id : undefined;
        if (id === undefined) continue;
        details.set(id, {
          ...(typeof vulnerability.summary === 'string' ? { summary: vulnerability.summary } : {}),
          ...(typeof vulnerability.details === 'string' ? { details: vulnerability.details } : {}),
        });
      }

      for (const [groupIndex, group] of (pkg.groups ?? []).entries()) {
        if (!isRecord(group)) {
          parserErrors.push(`osv-scanner: group ${resultIndex}.${packageIndex}.${groupIndex} is not an object and was skipped`);
          continue;
        }
        const rawIds: readonly unknown[] = Array.isArray(group.ids) ? group.ids : [];
        const ids = rawIds.filter((id): id is string => typeof id === 'string');
        const primary = ids[0];
        if (primary === undefined) {
          parserErrors.push(`osv-scanner: group ${resultIndex}.${packageIndex}.${groupIndex} has no identifiers and was skipped`);
          continue;
        }
        const score = typeof group.max_severity === 'string' ? Number(group.max_severity) : undefined;
        const detail = details.get(primary);
        const rawAliases: readonly unknown[] = Array.isArray(group.aliases) ? group.aliases : [];
        const aliases = rawAliases.filter((alias): alias is string => typeof alias === 'string');

        findings.push({
          id: stableFindingId(['osv', primary, name, version]),
          tool: 'osv-scanner',
          rule_id: primary,
          title: detail?.summary ?? `${name}@${version ?? 'unknown'} affected by ${primary}`,
          severity: severityFromCvss(score === undefined || Number.isNaN(score) ? undefined : score),
          resource: `${name}@${version ?? 'unknown'}${ecosystem === undefined ? '' : ` (${ecosystem})`}`,
          detail: [
            aliases.length === 0 ? undefined : `aliases: ${aliases.join(', ')}`,
            score === undefined ? 'no CVSS score reported' : `reported max severity ${score}`,
          ]
            .filter((part) => part !== undefined)
            .join('; '),
          control_ids: ['DEP-03'],
          triage: 'unresolved',
        });
      }
    }
  }

  return {
    tool: 'osv-scanner',
    findings,
    scope: {
      expected: options.expectedPackages ?? scannedPackages.size,
      observed: scannedPackages.size,
      ...(options.intendedScope === undefined ? {} : { files: [...options.intendedScope] }),
      notes: `${scannedPackages.size} package(s) checked across ${sources.length} source(s); coverage is per package`,
    },
    // A scan that checked no package examined nothing. `complete` is claimed only when the caller
    // supplies the lockfile's package count and every one of them was checked; otherwise the honest
    // answer is `partial`, because "some packages were checked" is not "the lockfile was covered".
    coverage:
      scannedPackages.size === 0
        ? 'unknown'
        : options.expectedPackages !== undefined && scannedPackages.size >= options.expectedPackages
          ? 'complete'
          : 'partial',
    parserErrors,
  } satisfies AdapterOutcome;
}
