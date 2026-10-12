import { classifyJwt } from '../build/client-assets.js';
import { sha256Hex } from './digest.js';
import type { CheckResult, Finding } from '../domain/types.js';

/**
 * Secret-finding classification (fix brief F-02).
 *
 * Gitleaks reports no severity; a committed credential is present or absent. Leaving every
 * exposure `unknown` made a live service-role key waivable and ranked it below workflow hygiene.
 * This module is the post-processing step that turns every secret finding into a classified,
 * readable one, and the de-duplication of the same secret across the repository and history
 * scans. The classifier is total: no secret finding leaves it `unknown` or without a title.
 *
 * The matched text is read from the application source, never from the gitleaks report: the
 * report is generated with `--redact`, and an unredacted report on disk would itself be the
 * leak. Only the SHA-256 of the matched line is recorded; the value itself is never stored.
 */

export interface SecretClass {
  readonly severity: 'critical' | 'high' | 'low';
  readonly title: string;
}

const CRITICAL_VALUE_PATTERNS: readonly { readonly pattern: RegExp; readonly title: string }[] = [
  { pattern: /\bsb_secret_[A-Za-z0-9_-]{10,}/, title: 'Supabase secret key exposed: it bypasses all row-level security' },
  { pattern: /\b[sr]k_live_[A-Za-z0-9]{10,}/, title: 'Stripe live key exposed: it can read and move real money' },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, title: "Anthropic API key exposed: it can spend the account owner's money" },
  // The negative lookahead keeps Stripe's sk_test_/sk_live_ formats out of the OpenAI class.
  { pattern: /\bsk-(?!(?:live|test)_)[A-Za-z0-9_-]{20,}/, title: "OpenAI API key exposed: it can spend the account owner's money" },
  { pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, title: 'AWS access key exposed: rotate it and its paired secret now' },
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, title: 'GitHub token exposed: it acts with every permission it was granted' },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, title: 'Private key material exposed: it is a full credential, not a hint' },
  { pattern: /(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?):\/\/[^:\s/@]+:[^@\s/]+@/i, title: 'Database URL with an embedded password exposed' },
];

const LOW_VALUE_PATTERNS: readonly { readonly pattern: RegExp; readonly title: string }[] = [
  { pattern: /\bsb_publishable_[A-Za-z0-9_-]{10,}/, title: 'Supabase publishable key: designed to ship to browsers; informational' },
];

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;

/**
 * Rule-id fallback for when the matched text cannot be read — a secret removed from the worktree
 * before the scan, an unreadable revision. The rule id still says what kind of material this is,
 * and the safe reading of an unreadable credential is the privileged one.
 */
const CRITICAL_RULE = /stripe|openai|anthropic|aws|github|supabase|service[-_]?role|private[-_]?key/i;

/** Total classification: value first, rule id second, `high` last. Never `unknown`. */
export function classifySecret(ruleId: string, matchedText: string | undefined): SecretClass {
  if (matchedText !== undefined && matchedText.length > 0) {
    if (JWT_PATTERN.test(matchedText)) {
      // Judged by the decoded role claim, reusing the client-asset logic: an anon/publishable JWT
      // is designed to be public, a legacy service-role JWT is a containment incident.
      return classifyJwt(matchedText) === 'privileged'
        ? { severity: 'critical', title: 'Supabase service-role key exposed: it bypasses all row-level security' }
        : { severity: 'low', title: 'Supabase anon/publishable key: designed to be public; informational' };
    }
    for (const { pattern, title } of CRITICAL_VALUE_PATTERNS) {
      if (pattern.test(matchedText)) return { severity: 'critical', title };
    }
    for (const { pattern, title } of LOW_VALUE_PATTERNS) {
      if (pattern.test(matchedText)) return { severity: 'low', title };
    }
    // The value was examined and matches no privileged or publishable class — for example a
    // Stripe test key, which the tool's rule matches exactly like a live one. It is still a
    // credential: high. The rule-id fallback does not apply here; the value was read.
    return { severity: 'high', title: 'Committed credential material: rotate the secret and review what it protects' };
  }
  // The value could not be read (removed from the worktree, unreadable revision): the rule id
  // still says what kind of material this is, and the safe reading of an unreadable credential
  // is the privileged one.
  return CRITICAL_RULE.test(ruleId)
    ? { severity: 'critical', title: `Privileged credential material exposed (rule '${ruleId}'): rotate it and review the history` }
    : { severity: 'high', title: 'Committed credential material: rotate the secret and review what it protects' };
}

/** Splits a `file:line` location; a location without a numeric suffix is all file. */
export function splitLocation(location: string | undefined): { readonly file: string; readonly line?: number } | undefined {
  if (location === undefined || location === '') return undefined;
  const match = /^(.*):(\d+)$/.exec(location);
  return match === null || match[1] === undefined
    ? { file: location }
    : { file: match[1], line: Number(match[2]) };
}

/**
 * Classifies every finding and records the digest of the matched line (when the reader can
 * produce it). The category marker is what the evaluator's waiver ban keys on, so it is set here,
 * the one place secret findings are post-processed.
 */
export function annotateSecretFindings(
  findings: readonly Finding[],
  readMatchedText: (finding: Finding) => string | undefined,
): Finding[] {
  return findings.map((finding) => {
    const matchedText = readMatchedText(finding);
    const classification = classifySecret(finding.rule_id, matchedText);
    return {
      ...finding,
      severity: classification.severity,
      title: classification.title,
      category: 'secret' as const,
      ...(matchedText === undefined || matchedText.length === 0 ? {} : { secret_digest: sha256Hex(matchedText) }),
    };
  });
}

/**
 * The same secret found by both the repository scan (HEAD) and the history scan is one finding,
 * not two: it is kept once, preferring the repository scan, and noted as also present in
 * committed history. The key is rule + file + the digest of the matched line, falling back to
 * the line number when the value could not be read; without either, the finding is left alone
 * rather than guessed at.
 */
export function dedupeSecretFindings(results: readonly CheckResult[]): CheckResult[] {
  const repositoryFindingIdByKey = new Map<string, string>();
  for (const result of results) {
    if (result.recipe !== 'gitleaks/repository') continue;
    for (const finding of result.findings ?? []) {
      const key = dedupeKey(finding);
      if (key !== undefined) repositoryFindingIdByKey.set(key, finding.id);
    }
  }
  if (repositoryFindingIdByKey.size === 0) return [...results];

  const historyCountByRepositoryFinding = new Map<string, number>();
  const intermediate = results.map((result) => {
    if (result.recipe !== 'gitleaks/history') return result;
    const findings = result.findings ?? [];
    const kept = findings.filter((finding) => {
      const key = dedupeKey(finding);
      const duplicateOf = key === undefined ? undefined : repositoryFindingIdByKey.get(key);
      if (duplicateOf === undefined) return true;
      historyCountByRepositoryFinding.set(duplicateOf, (historyCountByRepositoryFinding.get(duplicateOf) ?? 0) + 1);
      return false;
    });
    return kept.length === findings.length ? result : { ...result, findings: kept };
  });
  if (historyCountByRepositoryFinding.size === 0) return intermediate;

  return intermediate.map((result) => {
    if (result.recipe !== 'gitleaks/repository') return result;
    return {
      ...result,
      findings: (result.findings ?? []).map((finding) => {
        const historyCount = historyCountByRepositoryFinding.get(finding.id);
        if (historyCount === undefined) return finding;
        const note = `also present in committed history (${String(historyCount)} history occurrence(s)); removing it from the worktree does not remove it from the repository`;
        return { ...finding, detail: finding.detail === undefined ? note : `${finding.detail}; ${note}` };
      }),
    };
  });
}

function dedupeKey(finding: Finding): string | undefined {
  const parts = splitLocation(finding.location);
  if (parts === undefined) return undefined;
  const identity = finding.secret_digest ?? (parts.line === undefined ? undefined : `line:${String(parts.line)}`);
  if (identity === undefined) return undefined;
  return `${finding.rule_id}|${parts.file}|${identity}`;
}
