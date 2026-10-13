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
 * Exposure grading for the current-files scan (owner decisions, 13 October 2026): where the file
 * sits relative to git decides the grade, because that decides whether the secret is or will be
 * exposed through the repository.
 *
 * - **Tracked file** — the classifier's grade stands; the content is in the repository.
 * - **Untracked and gitignored** (e.g. `.env.local`) — not exposed through the repository: graded
 *   **medium**, a local-file risk. The danger is shipping it to the client, not committing it.
 * - **Untracked but not gitignored** — one `git add -A` away from being committed: graded
 *   **high** ("will be committed by git add").
 *
 * Critical stays for secrets in tracked files, committed history, or browser output; the fold
 * restores the committed severity, title, and detail when a committed duplicate proves the secret
 * reached the repository. A target with no git at all is never graded down: nothing there is
 * tracked or committed, so the tree is the whole truth.
 */
export const IGNORED_FILE_SECRET_NOTE = 'local file, keep it out of git and client code (git does not track this file, so the secret is not exposed through the repository)';
export const UNTRACKED_FILE_SECRET_NOTE = 'untracked and not gitignored: a plain git add will commit this file — gitignore it, or move the secret into the environment and rotate it if it was ever committed';

const IGNORED_TITLE_MARKER = 'in a local file (not committed to git)';
const UNTRACKED_TITLE_MARKER = 'in an untracked file (git add will commit it)';

function retitle(title: string | undefined, marker: string, fallback: string): string {
  return title !== undefined && title.includes(' exposed')
    ? title.replace(' exposed', ` ${marker}`)
    : fallback;
}

/** Grades one current-files finding whose file git does not track and does ignore: medium. */
export function gradeIgnoredFileFinding(finding: Finding): Finding {
  if (finding.severity !== 'critical' && finding.severity !== 'high') return finding;
  return {
    ...finding,
    severity: 'medium',
    title: retitle(finding.title, IGNORED_TITLE_MARKER, `Credential material ${IGNORED_TITLE_MARKER}: keep it out of git and client code`),
    detail: `${finding.detail ?? ''}; ${IGNORED_FILE_SECRET_NOTE}`,
  };
}

/** Grades one current-files finding whose file git neither tracks nor ignores: high. */
export function gradeUntrackedFinding(finding: Finding): Finding {
  if (finding.severity !== 'critical' && finding.severity !== 'high') return finding;
  return {
    ...finding,
    severity: 'high',
    title: retitle(finding.title, UNTRACKED_TITLE_MARKER, `Credential material ${UNTRACKED_TITLE_MARKER}: gitignore the file or move the secret into the environment`),
    detail: `${finding.detail ?? ''}; ${UNTRACKED_FILE_SECRET_NOTE}`,
  };
}

const SEVERITY_RANK: Readonly<Record<string, number>> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

function higherSeverity(a: Finding['severity'], b: Finding['severity']): Finding['severity'] {
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

/** True when a finding's title carries one of this module's exposure-grading markers. */
function hasGradedTitle(title: string | undefined): boolean {
  return title !== undefined && (title.includes(IGNORED_TITLE_MARKER) || title.includes(UNTRACKED_TITLE_MARKER));
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
 * The same secret found by more than one scan is one finding, not duplicate rows. Three scans can
 * report the same credential (F-02 follow-up, owner's auditor 13 October 2026):
 *
 * - `gitleaks/files` — what exists on disk right now. **The primary**, because it is the evidence
 *   about the present state and the only scan that runs at every depth, on every target.
 * - `gitleaks/repository` — the newest commit's change set. Folds into the files finding when both
 *   saw the same secret; it stays a row of its own when the worktree no longer has the secret.
 * - `gitleaks/history` — everything ever committed. Folds into whichever current scan found the
 *   secret; when neither did (removed from the worktree, absent from the newest commit's change
 *   set), the history finding is the row, as before.
 */
export function dedupeSecretFindings(results: readonly CheckResult[]): CheckResult[] {
  const keyCache = new Map<'gitleaks/files' | 'gitleaks/repository', Map<string, string>>();
  const findingIdsByKey = (recipe: 'gitleaks/files' | 'gitleaks/repository'): Map<string, string> => {
    let map = keyCache.get(recipe);
    if (map === undefined) {
      map = new Map<string, string>();
      keyCache.set(recipe, map);
      for (const result of results) {
        if (result.recipe !== recipe) continue;
        for (const finding of result.findings ?? []) {
          const key = dedupeKey(finding);
          if (key !== undefined) map.set(key, finding.id);
        }
      }
    }
    return map;
  };

  // History duplicates fold into the most current scan that reported the secret.
  const historyCountByFinding = new Map<string, number>();
  const committedSeverityByFinding = new Map<string, Finding['severity']>();
  const committedTitleByFinding = new Map<string, string>();
  const afterHistory = results.map((result) => {
    if (result.recipe !== 'gitleaks/history') return result;
    const findings = result.findings ?? [];
    const kept = findings.filter((finding) => {
      const key = dedupeKey(finding);
      if (key === undefined) return true;
      const duplicateOf = findingIdsByKey('gitleaks/files').get(key) ?? findingIdsByKey('gitleaks/repository').get(key);
      if (duplicateOf === undefined) return true;
      historyCountByFinding.set(duplicateOf, (historyCountByFinding.get(duplicateOf) ?? 0) + 1);
      committedSeverityByFinding.set(duplicateOf, higherSeverity(committedSeverityByFinding.get(duplicateOf) ?? 'low', finding.severity));
      if (finding.title !== undefined) committedTitleByFinding.set(duplicateOf, finding.title);
      return false;
    });
    return kept.length === findings.length ? result : { ...result, findings: kept };
  });

  // Repository duplicates fold into the files finding when both saw the same current secret.
  const repositoryCountByFilesFinding = new Map<string, number>();
  const afterRepository = afterHistory.map((result) => {
    if (result.recipe !== 'gitleaks/repository') return result;
    const findings = result.findings ?? [];
    const kept = findings.filter((finding) => {
      const key = dedupeKey(finding);
      const filesId = key === undefined ? undefined : findingIdsByKey('gitleaks/files').get(key);
      if (filesId === undefined) return true;
      repositoryCountByFilesFinding.set(filesId, (repositoryCountByFilesFinding.get(filesId) ?? 0) + 1);
      committedSeverityByFinding.set(filesId, higherSeverity(committedSeverityByFinding.get(filesId) ?? 'low', finding.severity));
      if (finding.title !== undefined) committedTitleByFinding.set(filesId, finding.title);
      return false;
    });
    return kept.length === findings.length ? result : { ...result, findings: kept };
  });

  if (historyCountByFinding.size === 0 && repositoryCountByFilesFinding.size === 0) return afterRepository;

  const historyNote = (count: number): string =>
    `also present in committed history (${String(count)} history occurrence(s)); removing it from the worktree does not remove it from the repository`;
  const repositoryNote = "also present in the newest commit's change set: the secret is committed, not only on disk";

  return afterRepository.map((result) => {
    if (result.recipe !== 'gitleaks/files' && result.recipe !== 'gitleaks/repository') return result;
    return {
      ...result,
      findings: (result.findings ?? []).map((finding) => {
        const notes: string[] = [];
        const historyCount = historyCountByFinding.get(finding.id);
        if (historyCount !== undefined) notes.push(historyNote(historyCount));
        if (repositoryCountByFilesFinding.has(finding.id)) notes.push(repositoryNote);
        // Committed evidence proves exposure: restore the committed severity and title and drop
        // the exposure-grading note — it would contradict the history it is being merged with.
        const committedSeverity = committedSeverityByFinding.get(finding.id);
        const hasCommittedEvidence = historyCount !== undefined || repositoryCountByFilesFinding.has(finding.id);
        const detail = hasCommittedEvidence && finding.detail !== undefined
          ? finding.detail.replace(`; ${IGNORED_FILE_SECRET_NOTE}`, '').replace(`; ${UNTRACKED_FILE_SECRET_NOTE}`, '')
          : finding.detail;
        const severity = committedSeverity === undefined ? finding.severity : higherSeverity(finding.severity, committedSeverity);
        const restoredTitle =
          hasCommittedEvidence && hasGradedTitle(finding.title)
            ? committedTitleByFinding.get(finding.id)
            : undefined;
        if (
          notes.length === 0 &&
          detail === finding.detail &&
          severity === finding.severity &&
          (restoredTitle === undefined || restoredTitle === finding.title)
        ) {
          return finding;
        }
        const note = notes.join('; ');
        const mergedDetail = note === ''
          ? (detail ?? finding.detail)
          : detail === undefined
            ? note
            : `${detail}; ${note}`;
        return {
          ...finding,
          severity,
          ...(mergedDetail === finding.detail ? {} : { detail: mergedDetail }),
          ...(restoredTitle === undefined || restoredTitle === finding.title ? {} : { title: restoredTitle }),
        };
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
