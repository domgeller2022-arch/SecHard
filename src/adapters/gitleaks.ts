import type { Finding } from '../domain/types.js';
import { relativizeLocation } from '../evidence/redaction.js';
import { isRecord, parseJsonReport, redactValue, stableFindingId, type AdapterOutcome } from './types.js';

/**
 * Gitleaks adapter.
 *
 * Gitleaks reports no severity: a committed credential is not graded, it is present or absent. The
 * adapter therefore records `unknown`, which the gate requires a human to triage. Inventing a
 * severity band for somebody else's secret would be a judgement this tool cannot make.
 *
 * Findings are redacted unconditionally. The recipe also runs Gitleaks with `--redact`, but the
 * adapter does not rely on the caller having done that.
 *
 * **Coverage is reported as `partial`, deliberately.** Gitleaks reports how many bytes it examined
 * and how many leaks it found; it does not report which files it examined. A file-level coverage
 * claim therefore cannot be supported by its output, and this adapter does not make one.
 */

interface GitleaksFinding {
  readonly RuleID?: unknown;
  readonly Description?: unknown;
  readonly File?: unknown;
  readonly StartLine?: unknown;
  readonly EndLine?: unknown;
  readonly Match?: unknown;
  readonly Secret?: unknown;
  readonly Fingerprint?: unknown;
  readonly Entropy?: unknown;
  readonly Commit?: unknown;
  readonly Tags?: unknown;
}

export interface GitleaksOptions {
  /** Tool stderr, used only to record how much content the scan actually examined. */
  readonly stderr?: string;
  /** Files the caller intended to scan, recorded as the expected scope. */
  readonly intendedScope?: readonly string[];
  /**
   * The scan root, when the tool was pointed at an absolute path. Dir mode then reports absolute
   * file paths; relativizing here keeps finding ids and locations root-relative — an id that
   * embeds the auditing host's layout is a leak in every report and unstable across machines
   * (the F-01/F-15 rule: adapters mint ids from the root-relative form). Already-relative paths
   * pass through unchanged, so git mode is unaffected.
   */
  readonly appRoot?: string;
}

export function parseGitleaksReport(raw: string, options: GitleaksOptions = {}): AdapterOutcome | { error: string } {
  const parsed = parseJsonReport(raw, 'gitleaks');
  if (!parsed.ok) return { error: parsed.error };

  if (!Array.isArray(parsed.value)) {
    return { error: 'gitleaks: report is not a JSON array; the output format may have changed or the scan did not complete' };
  }

  const findings: Finding[] = [];
  const parserErrors: string[] = [];

  for (const [index, entry] of parsed.value.entries()) {
    if (!isRecord(entry)) {
      parserErrors.push(`gitleaks: finding ${index} is not an object and was skipped`);
      continue;
    }
    const item = entry as GitleaksFinding;
    const ruleId = typeof item.RuleID === 'string' ? item.RuleID : undefined;
    if (ruleId === undefined) {
      parserErrors.push(`gitleaks: finding ${index} has no RuleID and was skipped`);
      continue;
    }

    const rawFile = typeof item.File === 'string' ? item.File : undefined;
    const file = rawFile === undefined || options.appRoot === undefined ? rawFile : relativizeLocation(rawFile, options.appRoot);
    // Dir mode fingerprints embed the absolute file path too; the same scrub applies, or the
    // fingerprint — carried as `resource` and hashed into the finding id — would leak the
    // auditing host's layout and be unstable across machines.
    const rawFingerprint = typeof item.Fingerprint === 'string' ? item.Fingerprint : undefined;
    const fingerprint =
      rawFingerprint === undefined || options.appRoot === undefined
        ? rawFingerprint
        : rawFingerprint.split(`${options.appRoot}/`).join('');
    const line = typeof item.StartLine === 'number' ? item.StartLine : undefined;
    const entropy = typeof item.Entropy === 'number' ? item.Entropy : undefined;
    const commit = typeof item.Commit === 'string' ? item.Commit : undefined;

    findings.push({
      id: stableFindingId(['gitleaks', ruleId, file, line, fingerprint]),
      tool: 'gitleaks',
      rule_id: ruleId,
      title: typeof item.Description === 'string' ? item.Description : ruleId,
      severity: 'unknown',
      ...(file === undefined ? {} : { location: line === undefined ? file : `${file}:${line}` }),
      ...(fingerprint === undefined ? {} : { resource: fingerprint }),
      ...(commit === undefined ? {} : { commit }),
      detail: `secret material detected${entropy === undefined ? '' : ` (entropy ${entropy.toFixed(2)})`}; value redacted`,
      redacted: true,
      triage: 'unresolved',
    });
  }

  const bytesScanned = extractBytesScanned(options.stderr);

  return {
    tool: 'gitleaks',
    findings,
    scope: {
      // `observed` is the tracked-file inventory the scan was scoped to, not the number of findings:
      // a clean scan over a known inventory is not an empty scope. Coverage stays partial because
      // gitleaks reports bytes, not the files it read.
      expected: options.intendedScope?.length ?? 0,
      observed: options.intendedScope?.length ?? 0,
      ...(options.intendedScope === undefined ? {} : { files: [...options.intendedScope] }),
      notes:
        `gitleaks reported ${bytesScanned === undefined ? 'no byte count' : `${bytesScanned} bytes examined`} and ${findings.length} finding(s). ` +
        'It does not list the files it examined, so file-level coverage cannot be established from its output.',
    },
    coverage: 'partial',
    parserErrors,
  } satisfies AdapterOutcome;
}

/** Reads "scanned ~N bytes" from the tool's diagnostic output. */
export function extractBytesScanned(stderr: string | undefined): number | undefined {
  if (stderr === undefined) return undefined;
  const match = stderr.match(/scanned ~(\d+)\s+bytes/i);
  return match?.[1] === undefined ? undefined : Number(match[1]);
}

/** True when the text still contains recognisable credential material. */
export function containsCredentialMaterial(text: string): boolean {
  return redactValue(text) !== text;
}
