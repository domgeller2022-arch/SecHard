import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
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
/** Node builtin module names: a bare import of one is not a package.json declaration issue. */
const NODE_BUILTINS = /^(node:)?(assert|buffer|child_process|cluster|crypto|dgram|dns|events|fs|http|http2|https|net|os|path|perf_hooks|process|querystring|readline|stream|string_decoder|timers|tls|url|util|v8|vm|worker_threads|zlib)$/;

export interface TellsResult {
  readonly findings: Finding[];
  readonly scope: { readonly filesRead: number; readonly filesSkippedByLimit: number };
}


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

export function analyzeVibeTells(root: string): TellsResult {
  const files = scanSourceFiles(root);
  const findings: Finding[] = [];

  // P4.4 (A-20): every detected tell enters the machine results — no scan-time cap hides a late
  // high finding behind early low ones. The report renders the highest-severity rows first, and
  // its display caps reconcile the omitted counts; this analyser's output is complete.

  // P4.4 (F-08): the repo-level data the remaining families need — the documented environment
  // keys and the declared dependencies. Both are read once as data; neither is executed.
  const envExamplePath = join(root, '.env.example');
  const documentedEnvKeys = existsSync(envExamplePath)
    ? new Set([...readFileSync(envExamplePath, 'utf8').matchAll(/^\s*([A-Z0-9_]+)\s*=/gm)].map((match) => match[1] ?? ''))
    : undefined;
  let declaredPackages: ReadonlySet<string> = new Set();
  let declaredPackagesKnown = false;
  try {
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    declaredPackages = new Set([
      ...Object.keys(manifest.dependencies ?? {}),
      ...Object.keys(manifest.devDependencies ?? {}),
      ...Object.keys(manifest.peerDependencies ?? {}),
    ]);
    declaredPackagesKnown = true;
  } catch {
    // No parsable package.json at the analyser root: the hallucinated-import route cannot know
    // the declared set and does not guess — the limitation is recorded in the control note.
  }

  const emit = (ruleId: string, severity: Finding['severity'], file: ScannedFile, line: number, what: string, fix: string): void => {
    findings.push(finding(ruleId, severity, file, line, what, fix));
  };

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
          'Delete the comment or replace it with the reason the code exists — the code already says what it does.');
      }

      if (NARRATION_PREFIX.test(comment.text)) {
        emit('step-narration', 'low', file, comment.line,
          'a "Step N" narration comment tracks the writing process, not the code',
          'Remove the step narration; name things and structure the code so the steps are unnecessary.');
      }

      if (MARKETING_PHRASES.test(comment.text) && !RATIONALE_MARKERS.test(comment.text)) {
        emit('marketing-comment', 'low', file, comment.line,
          'a comment asserts quality in adjectives ("robust", "comprehensive", "this ensures") without a reason',
          'Replace the adjectives with the constraint, invariant, or test that actually demonstrates the claim — or delete the claim.');
      }

      if (BANNER.test(comment.text)) {
        emit('banner-comment', 'info', file, comment.line,
          'a decorative banner comment line',
          'Section markers are noise when the file is small; delete or use the language\'s own structure.');
      }
    }

    // 2. Emoji anywhere in source files (code or comments) — they break plain-text logs, diffs, and
    // some terminals, and they are a strong generated-content tell.
    const emojiMatch = EMOJI.exec(file.text);
    if (emojiMatch !== null) {
      const line = file.text.slice(0, emojiMatch.index).split(/\r?\n/).length;
      emit('emoji-in-source', 'low', file, line,
        'source files contain emoji',
        'Remove emoji from code, comments, and log messages; they are unreliable in plain-text contexts.');
    }

    // 3. Placeholders and stubs in production paths.
    for (const comment of comments) {
      if (PLACEHOLDER.test(comment.text)) {
        emit('placeholder-comment', 'medium', file, comment.line,
          'a comment marks unfinished work as if it were finished ("TODO: implement", "in a real implementation")',
          'Finish the implementation, or make the gap explicit in the issue tracker and fail loudly instead of shipping a silent stub.');
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
          'Replace placeholder data with the real implementation or a reviewed fixture that is clearly labelled and separate from production paths.');
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
          'Read hostnames from configuration or environment; a hardcoded address is a deployment assumption that will break silently.');
      }
    }

    // 5. debugger statements.
    for (const [index, line] of lines.entries()) {
      if (DEBUGGER.test(line)) {
        emit('debugger-statement', 'high', file, index + 1,
          'a debugger statement will halt production execution where debuggers attach',
          'Remove the debugger statement; use conditional breakpoints in development tooling instead.');
      }
    }

    // 6. Commented-out code blocks: three or more consecutive comment lines that parse as code.
    const commentByLine = new Map(comments.map((comment) => [comment.line, comment.text]));
    let run: { line: number; text: string }[] = [];
    const flushRun = (): void => {
      if (run.length >= 3 && run.filter((entry) => COMMENTED_CODE.test(entry.text)).length >= 2) {
        emit('commented-out-code', 'low', file, run[0]?.line ?? 0,
          'a block of commented-out code is kept in the source',
          'Delete it — version control remembers. Uncommented dead code confuses every reader about what runs.');
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
        'Check whether the file is prose with some code attached; if the explanation is essential, it may belong in documentation instead.');
    }
    // F-07: mock or demo data in production paths. Placeholder users, example mailboxes, and
    // lorem text shipped in source render to real users and rot into the UI.
    const MOCK_DATA = /\b(mockUsers|mockData|mockDB|mockDatabase|fakeData|Lorem ipsum|john@example\.com|test@example\.com)\b/;
    for (const [index, line] of lines.entries()) {
      if (isTestFile(file.relative)) break;
      // A comment that names the pattern is documentation, not shipped mock data; the rule's own
      // source must not flag itself either.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // The pattern's own definition line contains the alternation text; it is not mock data.
      if (line.includes('MOCK_DATA')) continue;
      const match = MOCK_DATA.exec(line);
      if (match === null) continue;
      emit('quality.mock-data', 'medium', file, index + 1,
        'mock or demo data in a production path',
        'Replace placeholder data with real data sources (a database query or configuration); demo fixtures belong behind a feature flag or in test code only.');
    }

    // F-07: a swallowed Supabase error. `const { data } = await supabase.from(...)` discards the
    // error side of the result, so a failed query silently renders as empty. Same for
    // `.then(({ data }) => ...)`.
    if (/@supabase\/supabase-js|supabase/i.test(file.text)) {
      for (const [index, line] of lines.entries()) {
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        if (/const\s*\{\s*data\s*\}\s*=\s*await/.test(line) && /from\s*\(/.test(line)) {
          emit('quality.swallowed-supabase-error', 'medium', file, index + 1,
            'a Supabase query discards its error',
            'Destructure error as well (const { data, error }) and handle a non-null error; an ignored error renders failure as empty data.');
        }
        if (/\.then\s*\(\s*\(\s*\{\s*data\s*\}\s*\)/.test(line)) {
          emit('quality.swallowed-supabase-error', 'medium', file, index + 1,
            'a Supabase query promise drops its error',
            'Destructure error in the callback (or use await with try/catch) so failures are handled instead of silently empty.');
        }
      }
    }

    // 8. P4.4 (F-08): undocumented environment variables — a process.env key that the reviewed
    // .env.example does not document is an undeclared runtime dependency. The check applies only
    // when the documentation file exists; its absence is repo-hygiene's finding (QUAL-11).
    if (documentedEnvKeys !== undefined) {
      for (const [index, line] of lines.entries()) {
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
        for (const match of line.matchAll(/process\.env\.([A-Z0-9_]+)/g)) {
          const key = match[1] ?? '';
          if (key.length === 0 || documentedEnvKeys.has(key)) continue;
          emit('undocumented-env', 'low', file, index + 1,
            `the environment variable ${key} is read but not documented in .env.example`,
            'Add the variable to .env.example with a safe placeholder value so deployments declare what they need; an undocumented variable fails silently in a fresh environment.');
        }
      }
    }

    // 9. P4.4 (F-08): hallucinated imports — a bare package specifier that package.json never
    // declares is a strong generated-content signal (an import of a package that does not
    // exist). Node builtins, relative paths and path-alias imports are not package specifiers.
    // The route applies only when the declared set is known: without it the analyser does not
    // guess (a subdirectory root has no manifest of its own).
    if (declaredPackagesKnown) {
      for (const [index, line] of lines.entries()) {
        // The analyser's own emit and pattern-definition lines are detection logic, not imports;
        // the rule's own source must not flag itself (the exemption the other families use).
        if (/^\s*emit\(|matchAll\(|new RegExp\(/.test(line)) continue;
        for (const match of line.matchAll(/(?:import|require)\s*\(?\s*['"]([^'"]+)['"]/g)) {
          const specifier = (match[1] ?? '').trim();
          // A package specifier starts with @, a letter, or a digit — anything else (a quoted
          // gap between string literals, prose) is not an import.
          if (specifier.length === 0 || !/^[@a-z0-9]/i.test(specifier)) continue;
          if (specifier.startsWith('.') || specifier.startsWith('@/')) continue;
          if (specifier.startsWith('node:') || NODE_BUILTINS.test(specifier)) continue;
          if (declaredPackages.has(specifier) || declaredPackages.has(specifier.split('/')[0] ?? '')) continue;
          emit('hallucinated-import', 'medium', file, index + 1,
            `an import of '${specifier}' that package.json never declares`,
            'Verify the package exists and add it to package.json deliberately, or remove the import; an undeclared dependency fails in every fresh install.');
        }
      }
    }

    // 10. P4.4 (F-08): inconsistent helper naming — a file whose function declarations mix
    // camelCase and snake_case is a signal the file was assembled from different sources.
    const camelNamed: string[] = [];
    const snakeNamed: string[] = [];
    for (const line of lines) {
      for (const match of line.matchAll(/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
        const name = match[1] ?? '';
        if (name.includes('_')) snakeNamed.push(name);
        else if (/[a-z][A-Z]/.test(name)) camelNamed.push(name);
      }
    }
    if (camelNamed.length > 0 && snakeNamed.length > 0) {
      emit('inconsistent-naming', 'low', file, 1,
        `the file mixes naming conventions: ${String(camelNamed.length)} camelCase and ${String(snakeNamed.length)} snake_case function declaration(s)`,
        'Pick one convention for the file and rename the outliers; mixed conventions are a signal the file was assembled from different sources.');
    }

    // 11. P4.4 (F-08): redundant validation — the same guard repeated on consecutive lines is a
    // cargo-cult signal (a copy-paste of a check that already ran). Labelled a signal: some
    // repetition is intentional type narrowing.
    for (let index = 1; index < lines.length; index += 1) {
      const previous = (lines[index - 1] ?? '').trim();
      const current = (lines[index] ?? '').trim();
      if (previous.length > 0 && previous === current && /^(if\s*\(|return\s+|throw\s+)/.test(current)) {
        emit('redundant-validation', 'low', file, index + 1,
          'the same validation statement is repeated on consecutive lines',
          'Remove the duplicate check, or make the second one assert something new; repeated identical guards are usually copy-paste leftovers.');
      }
    }
  }

  findings.sort((a, b) => (a.location ?? '') < (b.location ?? '') ? -1 : (a.location ?? '') > (b.location ?? '') ? 1 : 0);
  return { findings, scope: { filesRead: files.length, filesSkippedByLimit: 0 } };
}
