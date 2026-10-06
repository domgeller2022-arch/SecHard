import type { Coverage, Finding, Severity } from '../domain/types.js';

/**
 * Shared shapes for the scanner adapters.
 *
 * An adapter's job is to turn a tool's own report into findings this repository can reason about,
 * and to be honest about what the tool did and did not examine. Two rules apply to every adapter:
 *
 * 1. A parse failure is an error, not an empty result. "The tool produced nothing" and "the report
 *    was unreadable" must never be confused, because only one of them is safe.
 * 2. Coverage is derived from what the tool reported, not from what it was asked to scan. A run over
 *    zero files is not a clean run.
 */

export interface AdapterOutcome {
  readonly tool: string;
  readonly findings: readonly Finding[];
  /** What the tool actually examined, as reported by the tool itself. */
  readonly scope: {
    readonly expected: number;
    readonly observed: number;
    readonly files?: readonly string[];
    readonly notes?: string;
  };
  readonly coverage: Coverage;
  readonly parserErrors: readonly string[];
}

export interface ParseFailure {
  readonly ok: false;
  readonly error: string;
}

/** CVSS score to severity band. A documented mapping, not a guess. */
export function severityFromCvss(score: number | undefined): Severity {
  if (score === undefined || !Number.isFinite(score)) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

/** Opengrep/Semgrep style severities. The mapping is recorded in the adapter test. */
export function severityFromRuleLevel(level: string | undefined): Severity {
  switch ((level ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'low';
    default:
      return 'unknown';
  }
}

export function severityFromWord(word: string | undefined): Severity {
  switch ((word ?? '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'informational':
    case 'info':
      return 'info';
    default:
      return 'unknown';
  }
}

/**
 * Replaces credential material in a finding.
 *
 * Even when a tool is asked to redact, the adapter redacts again: the safe assumption is that a
 * report may contain a live secret, and a finding that leaks the secret it reports is worse than
 * the finding itself.
 */
const SECRET_FIELD_PATTERNS: readonly RegExp[] = [
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

export function redactValue(value: string): string {
  if (value === 'REDACTED' || value.length === 0) return value;
  let output = value;
  for (const pattern of SECRET_FIELD_PATTERNS) {
    output = output.replace(pattern, '[REDACTED]');
  }
  return output;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Parses JSON, converting a failure into a reported error rather than an empty result. */
export function parseJsonReport(raw: string, tool: string): { ok: true; value: unknown } | ParseFailure {
  if (raw.trim().length === 0) {
    return { ok: false, error: `${tool}: report is empty` };
  }
  try {
    return { ok: true, value: JSON.parse(raw) as unknown };
  } catch (error) {
    return { ok: false, error: `${tool}: report is not valid JSON: ${(error as Error).message}` };
  }
}

export function stableFindingId(parts: readonly (string | number | undefined)[]): string {
  return parts.filter((part) => part !== undefined && part !== '').join(':');
}
