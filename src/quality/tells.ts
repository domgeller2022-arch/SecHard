import type { Finding } from '../domain/types.js';
import { commentLines, identifiersOf, isTestFile, scanSourceFiles, type ScannedFile } from './common.js';

/**
 * The "vibe-coded tells" analyser (QUAL-09, remediation-plan task Q4).
 *
 * No mature open-source tool exists for this, so SecHard owns it — which means owning its error
 * rate too: every rule was calibrated on the corpus (`tests/corpus/`) and on this repository's own
 * self-audit, and the measured recall/precision are reported, not implied. Two rules govern every
 * finding this module emits:
 *
 * 1. **A finding is a signal with an explanation, never proof of authorship.** The confidence is
 *    `signal`; a human wrote code with any of these habits just as often as a model did.
 * 2. **Rationale is not a tell.** A comment that explains WHY code is the way it is — with a
 *    because-clause, a named trade-off, a pointer to a control or a decision — is exactly what
 *    good engineering looks like. The narration rules test for comments that restate WHAT the
 *    next line does or assert quality in adjectives. This distinction is the analyser's central
 *    design decision and is calibrated, not assumed.
 *
 * Deliberate omissions, recorded rather than implied: near-duplicate helper functions, several
 * utility files doing one job, and mixed-paradigm usage (structural tells from Q4) need cross-file
 * analysis this build does not have; hallucinated imports of nonexistent packages need registry
 * access (Batch X); env vars read but never documented need framework knowledge.
 */

const RATIONALE_MARKERS = /\b(because|since|why|rationale|purpose|on purpose|deliberate(?:ly)?|intentional|per the|per [a-z-]+|instead of|rather than|otherwise|so that|prevents|avoids|required by|control)\b/i;
const MARKETING_PHRASES = /\b(this ensures|robust and|comprehensive|seamless|bulletproof|clean and simple|state-of-the-art)\b/i;
const NARRATION_PREFIX = /^(step|part|phase|stage)\s*\d+\s*[:-]/i;
const BANNER = /^[-=*_#]{8,}$/;
const PLACEHOLDER = new RegExp(['(todo:? (implement|add|finish|real|actual)', '|in a real (implementation|app|production)', '|not implemented yet', '|for now,? (just|we|this|return)', ')'].join(''), 'i');
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/u;
const DEBUGGER = /^\s*debugger\s*;?\s*$/;
const COMMENTED_CODE = /(import\s+\w|const\s+\w|let\s+\w|function\s+\w|=>|\w+\([^)]*\)\s*;|\w+\s*=\s*[^=;\s])|\w+\.\w+\s*=/;

export interface TellsResult {
  readonly findings: Finding[];
  readonly scope: { readonly filesRead: number; readonly filesSkippedByLimit: number };
}

const MAX_FINDINGS_PER_RULE = 60;

function finding(ruleId: string, severity: Finding['severity'], file: ScannedFile, line: number, what: string, fix: string): Finding {
  return {
    id: `quality:tells:${ruleId}:${file.relative}:${line}`,
    tool: 'quality-vibe-tells',
    rule_id: `tell.${ruleId}`,
    severity,
    title: what,
    location: `${file.relative}:${line}`,
    detail: fix,
    control_ids: ['QUAL-09'],
    triage: 'unresolved',
  };
}

export function analyzeVibeTells(root: string, options: { maxFilesListed: number }): TellsResult {
  const files = scanSourceFiles(root);
  const findings: Finding[] = [];
  let perFileCapRemaining = Math.max(1, options.maxFilesListed);

  const emit = (ruleId: string, severity: Finding['severity'], file: ScannedFile, line: number, what: string, fix: string, counts: Record<string, number>): void => {
    counts[ruleId] = (counts[ruleId] ?? 0) + 1;
    if (counts[ruleId] as number > MAX_FINDINGS_PER_RULE) return;
    if (perFileCapRemaining <= 0) return;
    perFileCapRemaining -= 1;
    findings.push(finding(ruleId, severity, file, line, what, fix));
  };
  const counts: Record<string, number> = {};

  const codeLinesOf = (text: string): readonly string[] => text.split(/\r?\n/);

  for (const file of files) {
    if (isTestFile(file.relative)) continue;
    if (/\.d\.ts$/.test(file.path)) continue; // generated declarations have no author to review
    const lines = codeLinesOf(file.text);
    const comments = commentLines(file.text);

    // 1. Narration: a comment that restates the next code line. Tests the shared-identifier
    // vocabulary between the comment and the following line, and treats rationale markers as the
    // distinguishing signal — "why" comments survive by design.
    for (const comment of comments) {
      // A comment run (the next line is itself a comment) is block commentary, not narration of a
      // code line; the narration rule only judges a comment against the code that follows it.
      const nextLine = lines[comment.line] ?? '';
      if (/^\s*(?:\/\/|#)/.test(nextLine)) continue;
      // Narration restates the NEXT line's mechanics. Comparing against the next line only — not a
      // three-line window — and requiring the overlap to be a partial (not near-total) match keeps
      // wrapped prose and policy comments out: calibration on this repository showed the wider
      // window misread rationale comments as narration.
      const commentWords = identifiersOf(comment.text);
      const nextWords = identifiersOf(nextLine);
      const overlap = [...commentWords].filter((word) => nextWords.has(word));
      const short = comment.text.length <= 60;
      const nearTotalProse = commentWords.size > 0 && overlap.length / commentWords.size >= 0.8;
      if (short && overlap.length >= 2 && !nearTotalProse && !RATIONALE_MARKERS.test(comment.text)) {
        emit('narration-comment', 'low', file, comment.line,
          'a comment restates what the next line does instead of explaining why it does it',
          'Delete the comment or replace it with the reason the code exists — the code already says what it does.',
          counts);
      }

      if (NARRATION_PREFIX.test(comment.text)) {
        emit('step-narration', 'low', file, comment.line,
          'a "Step N" narration comment tracks the writing process, not the code',
          'Remove the step narration; name things and structure the code so the steps are unnecessary.',
          counts);
      }

      if (MARKETING_PHRASES.test(comment.text) && !RATIONALE_MARKERS.test(comment.text)) {
        emit('marketing-comment', 'low', file, comment.line,
          'a comment asserts quality in adjectives ("robust", "comprehensive", "this ensures") without a reason',
          'Replace the adjectives with the constraint, invariant, or test that actually demonstrates the claim — or delete the claim.',
          counts);
      }

      if (BANNER.test(comment.text)) {
        emit('banner-comment', 'info', file, comment.line,
          'a decorative banner comment line',
          'Section markers are noise when the file is small; delete or use the language\'s own structure.',
          counts);
      }
    }

    // 2. Emoji anywhere in source files (code or comments) — they break plain-text logs, diffs, and
    // some terminals, and they are a strong generated-content tell.
    const emojiMatch = EMOJI.exec(file.text);
    if (emojiMatch !== null) {
      const line = file.text.slice(0, emojiMatch.index).split(/\r?\n/).length;
      emit('emoji-in-source', 'low', file, line,
        'source files contain emoji',
        'Remove emoji from code, comments, and log messages; they are unreliable in plain-text contexts.',
        counts);
    }

    // 3. Placeholders and stubs in production paths.
    for (const comment of comments) {
      if (PLACEHOLDER.test(comment.text)) {
        emit('placeholder-comment', 'medium', file, comment.line,
          'a comment marks unfinished work as if it were finished ("TODO: implement", "in a real implementation")',
          'Finish the implementation, or make the gap explicit in the issue tracker and fail loudly instead of shipping a silent stub.',
          counts);
      }
    }
    for (const [index, line] of lines.entries()) {
      const trimmed = line.trim();
      const isCommentOnly = trimmed.startsWith('//') || trimmed.startsWith('#');
      // The placeholder must BE the assigned or compared value — a line that merely mentions the
      // word (diagnostics, rule definitions, documentation strings) is prose, not placeholder data.
      const isPlaceholderValue = /['"`]\s*(placeholder|dummy|fake|sample|todo)\b/i.test(line) && /===|!==|=/.test(line);
      if (!isCommentOnly && isPlaceholderValue) {
        emit('placeholder-code', 'medium', file, index + 1,
          'production code uses placeholder or dummy data',
          'Replace placeholder data with the real implementation or a reviewed fixture that is clearly labelled and separate from production paths.',
          counts);
      }
    }

    // 4. Hallucination-adjacent leftovers: hardcoded localhost/example URLs in non-test source. A
    // mention in a comparison or matcher is detection logic, not a runtime assumption; test,
    // e2e, and config files are legitimate homes for local addresses.
    const isConfigOrTool = /(?:config|setup|sync|fixtures?)\.[cm]?[jt]sx?$/.test(file.path) || /(^|\/)e2e\//.test(file.relative) || /(^|\/)tools\//.test(file.relative) || /(^|\/)scripts\//.test(file.relative);
    for (const [index, line] of lines.entries()) {
      // The scheme is required: a bare 'localhost' in prose or an error message is a mention, not
      // a runtime address. Mentions inside comparisons are detection logic, not configuration.
      const mentioned = /['"`]https?:\/\/(localhost|127\.0\.0\.1|example\.com)/i.test(line);
      const inComparison = /===|!==|\.includes\(|\.test\(|match\(|exec\(/.test(line);
      if (mentioned && !inComparison && !isConfigOrTool) {
        emit('hardcoded-local-url', 'low', file, index + 1,
          'a hardcoded localhost or example.com address in source',
          'Read hostnames from configuration or environment; a hardcoded address is a deployment assumption that will break silently.',
          counts);
      }
    }

    // 5. debugger statements.
    for (const [index, line] of lines.entries()) {
      if (DEBUGGER.test(line)) {
        emit('debugger-statement', 'high', file, index + 1,
          'a debugger statement will halt production execution where debuggers attach',
          'Remove the debugger statement; use conditional breakpoints in development tooling instead.',
          counts);
      }
    }

    // 6. Commented-out code blocks: three or more consecutive comment lines that parse as code.
    const commentByLine = new Map(comments.map((comment) => [comment.line, comment.text]));
    let run: { line: number; text: string }[] = [];
    const flushRun = (): void => {
      if (run.length >= 3 && run.filter((entry) => COMMENTED_CODE.test(entry.text)).length >= 2) {
        emit('commented-out-code', 'low', file, run[0]?.line ?? 0,
          'a block of commented-out code is kept in the source',
          'Delete it — version control remembers. Uncommented dead code confuses every reader about what runs.',
          counts);
      }
      run = [];
    };
    for (const [index] of lines.entries()) {
      const comment = commentByLine.get(index + 1);
      if (comment === undefined) {
        flushRun();
        continue;
      }
      if (run.length === 0 || (run[run.length - 1]?.line ?? 0) === index) {
        run.push({ line: index + 1, text: comment });
      } else {
        flushRun();
        run = [{ line: index + 1, text: comment }];
      }
    }
    flushRun();

    // 7. Comment density: far more comment than code in one file is itself a reviewability signal —
    //    it usually means prose is doing the code's job. The floor is high (60%) so rationale-rich
    //    files are not findings by default; the corpus sets what "far above" means.
    const totalLines = lines.filter((line) => line.trim().length > 0).length;
    const commentCount = comments.length;
    if (totalLines >= 20 && commentCount / totalLines > 0.6) {
      emit('comment-dominance', 'info', file, 1,
        'comments make up more than 60% of this file\'s non-empty lines',
        'Check whether the file is prose with some code attached; if the explanation is essential, it may belong in documentation instead.',
        counts);
    }
  }

  findings.sort((a, b) => (a.location ?? '') < (b.location ?? '') ? -1 : (a.location ?? '') > (b.location ?? '') ? 1 : 0);
  return { findings, scope: { filesRead: files.length, filesSkippedByLimit: 0 } };
}
