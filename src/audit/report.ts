import type { ControlDefinition } from '../domain/definitions.js';
import type { CheckResult, ExecutionPlan, Finding, GateDecision, ReleaseEvidence, Severity } from '../domain/types.js';
import { escapeMarkdown, redactSecrets } from '../evidence/redaction.js';
import { explainFinding, type Confidence, type Effort } from './explanations.js';
import type { Detection } from './detect.js';
import type { ApprovedUrl } from './url-guard.js';

/**
 * The audit report: a plain-English document for an owner who does not read code.
 *
 * It is generated from the same evaluation the gate produced (results, findings, and the decision);
 * formatting cannot change the decision. Quality and security are reported separately and neither
 * can change the other's verdict. Everything untrusted is redacted, and — for Markdown and HTML —
 * structurally escaped.
 */

export type Depth = 'quick' | 'standard' | 'deep';

export interface AuditReportInput {
  readonly target: string;
  readonly targetName: string;
  readonly detection: Detection;
  readonly plan: ExecutionPlan;
  readonly results: readonly CheckResult[];
  readonly decision: GateDecision;
  readonly evidence: ReleaseEvidence;
  readonly controls: readonly ControlDefinition[];
  readonly depth: Depth;
  readonly url?: ApprovedUrl;
  readonly generatedAt: Date;
  readonly policyCommit: string;
}

export interface AnnotatedFinding {
  readonly id: string;
  readonly severity: Severity;
  readonly tool: string;
  readonly rule_id: string;
  readonly title: string;
  readonly location: string;
  readonly detail?: string;
  readonly control_ids: readonly string[];
  readonly standards: readonly string[];
  readonly what: string;
  readonly fix: string;
  readonly effort: Effort;
  readonly confidence: Confidence;
  readonly prompt: string;
  readonly exposure: 'deployed-surface' | 'source';
}

export interface AuditReport {
  readonly markdown: string;
  readonly html: string;
  readonly sarif: string;
  readonly json: string;
  readonly findings: readonly AnnotatedFinding[];
  readonly couldNotCheck: readonly string[];
  readonly securityScore: { readonly score: number | null; readonly verdict: string };
  readonly qualityScore: { readonly score: number | null; readonly verdict: string };
  readonly fixFirst: readonly AnnotatedFinding[];
}

const SEVERITY_WEIGHT: Readonly<Record<Severity, number>> = {
  critical: 40, high: 20, medium: 8, low: 3, info: 0, unknown: 5,
};
const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

/** Markdown-safety for untrusted text: the reviewed redact-then-escape pair, not a local variant. */
function mdSafe(value: string): string {
  return escapeMarkdown(value);
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&' + 'amp;')
    .replace(/</g, '&' + 'lt;')
    .replace(/>/g, '&' + 'gt;')
    .replace(/"/g, '&' + 'quot;')
    .replace(/'/g, '&' + '#39;');
}

function safe(value: unknown): string {
  return mdSafe(redactSecrets(String(value ?? '')));
}

function h(value: unknown): string {
  return htmlEscape(redactSecrets(String(value ?? '')));
}

function standardsFor(finding: Finding, controlsById: Map<string, ControlDefinition>): string[] {
  const refs: string[] = [];
  for (const controlId of finding.control_ids ?? []) {
    const control = controlsById.get(controlId);
    for (const mapping of control?.standards ?? []) {
      const ref = `${mapping.framework}${mapping.edition === undefined ? '' : ` ${mapping.edition}`}${mapping.requirement === undefined ? '' : ` ${mapping.requirement}`}`;
      if (!refs.includes(ref)) refs.push(ref);
      if (refs.length >= 4) return refs;
    }
  }
  return refs;
}

function locationOf(finding: Finding, result: CheckResult): string {
  const raw = finding.location ?? finding.resource ?? '';
  if (raw.length > 0) return raw;
  const files = result.scope?.files ?? [];
  return files[0] ?? '';
}

function annotate(input: AuditReportInput): AnnotatedFinding[] {
  const controlsById = new Map(input.controls.map((control) => [control.id, control]));
  const deployedSurfaceTools = new Set(['client-asset-inspection', 'live-http-check']);

  const annotated: AnnotatedFinding[] = [];
  for (const result of input.results) {
    for (const finding of result.findings ?? []) {
      const explanation = explainFinding(finding);
      annotated.push({
        id: finding.id,
        severity: finding.severity,
        tool: finding.tool,
        rule_id: finding.rule_id,
        title: finding.title ?? `${finding.rule_id} reported by ${finding.tool}`,
        location: locationOf(finding, result),
        ...(finding.detail === undefined ? {} : { detail: finding.detail }),
        control_ids: finding.control_ids ?? result.control_ids,
        standards: standardsFor(finding, controlsById),
        what: explanation.what,
        fix: explanation.fix,
        effort: explanation.effort,
        confidence: explanation.confidence,
        prompt: explanation.prompt,
        exposure: deployedSurfaceTools.has(finding.tool) ? 'deployed-surface' : 'source',
      });
    }
  }

  annotated.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byExposure = (b.exposure === 'deployed-surface' ? 1 : 0) - (a.exposure === 'deployed-surface' ? 1 : 0);
    if (byExposure !== 0) return byExposure;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return annotated;
}

function securityScore(annotated: readonly AnnotatedFinding[]): { score: number | null; verdict: string } {
  if (annotated.length === 0) {
    return { score: null, verdict: 'No findings among the checks that ran — read the "could not check" list before trusting this.' };
  }
  const penalty = annotated.reduce((total, finding) => total + (SEVERITY_WEIGHT[finding.severity] ?? 0), 0);
  const score = Math.max(0, 100 - penalty);
  const hasCritical = annotated.some((finding) => finding.severity === 'critical');
  const hasHigh = annotated.some((finding) => finding.severity === 'high');
  const verdict = hasCritical
    ? 'Critical findings exist. Act on them before anything else ships.'
    : hasHigh
      ? 'High-severity findings exist. Fix them before the next release.'
      : score >= 80
        ? 'No blocking findings among the checks that ran; medium and low items remain.'
        : 'Findings need attention; work through them by priority.';
  return { score, verdict };
}

function qualityScore(input: AuditReportInput): { score: number | null; verdict: string } {
  // No quality control beyond QUAL-01 is defined in this build; QUAL-01's recipes are not wired
  // (Batch Q). An audit therefore reports quality as not assessed rather than inventing a score.
  const qualResults = input.results.filter((result) => result.control_ids.includes('QUAL-01'));
  const ran = qualResults.filter((result) => result.outcome === 'pass' || result.outcome === 'fail');
  if (ran.length === 0) {
    return { score: null, verdict: 'Not assessed in this build: the quality controls (QUAL-02 onwards) arrive with the quality batch, and no quality recipe ran.' };
  }
  const failed = ran.some((result) => result.outcome === 'fail');
  return { score: failed ? 0 : 100, verdict: failed ? 'The application\'s own build or test suite failed when run.' : "The application's own build or test suite passed; deeper quality analysis arrives with the quality batch." };
}

function couldNotCheck(input: AuditReportInput): string[] {
  const items: string[] = [];

  if (input.detection.unsupported_stack !== undefined) {
    items.push(`UNSUPPORTED STACK: ${input.detection.unsupported_stack.reason}. Generic checks that still ran: ${input.detection.unsupported_stack.generic_checks.join(', ')}.`);
  }
  items.push(...input.detection.gaps.map((gap) => `DETECTION: ${gap}`));

  const manualObligations: string[] = [];
  for (const result of input.results) {
    if (result.outcome === 'error') {
      items.push(`ERROR in ${result.recipe}: ${result.diagnostic ?? 'no diagnostic recorded'}`);
    } else if (result.outcome === 'unsupported') {
      items.push(`NOT RUN ${result.recipe}: ${result.diagnostic ?? 'not applicable'}`);
    }
  }
  const manualChecks = input.plan.expected_checks.filter((check) => check.execution?.mode === 'manual');
  if (manualChecks.length > 0) {
    manualObligations.push(`${manualChecks.length} manual/operational obligations (restore drills, incident exercises, credential lifecycle, data review) require operator evidence; they cannot be audited from source alone and are listed as unmet for this audit`);
  }
  items.push(...manualObligations);


  if (input.depth === 'quick') {
    items.push('DEPTH: quick mode does not run the git-history secret scan, the browser-bundle inspection, or live HTTP checks; rerun without --depth quick for those');
  }
  if (input.depth === 'deep') {
    items.push('DEPTH: deep mode runs the same set as standard in this build. Deeper work (executing the application\'s own build and tests, exposure probes) requires the audit isolation model and is not implemented; it is refused rather than silently run');
  }
  items.push('TLS assessment is not part of this audit: the transport requirements beyond certificate validity need current testssl.sh output (manual evidence)');
  return items;
}

function countRan(input: AuditReportInput): { ran: number; planned: number } {
  const executable = input.plan.expected_checks.filter((check) => check.execution?.mode !== 'manual');
  const answered = input.results.filter((result) => result.outcome === 'pass' || result.outcome === 'fail').length;
  return { ran: answered, planned: executable.length };
}

export function buildAuditReport(input: AuditReportInput): AuditReport {
  const findings = annotate(input);
  const fixFirst = findings.slice(0, 10);
  const could = couldNotCheck(input);
  const sec = securityScore(findings);
  const qual = qualityScore(input);
  const coverage = countRan(input);

  const json = buildJson(input, findings, fixFirst, sec, qual, could, coverage);
  const markdown = buildMarkdown(input, findings, fixFirst, sec, qual, could, coverage);
  const html = buildHtml(input, findings, fixFirst, sec, qual, could, coverage);
  const sarif = buildSarif(input, findings);

  return {
    markdown, html, sarif, json,
    findings,
    couldNotCheck: could,
    securityScore: sec,
    qualityScore: qual,
    fixFirst,
  };
}

// --- JSON ---------------------------------------------------------------------

function buildJson(
  input: AuditReportInput,
  findings: readonly AnnotatedFinding[],
  fixFirst: readonly AnnotatedFinding[],
  sec: { score: number | null; verdict: string },
  qual: { score: number | null; verdict: string },
  could: readonly string[],
  coverage: { ran: number; planned: number },
): string {
  const document = {
    schema_version: 'audit-report/v1',
    target: input.target,
    generated_at: input.generatedAt.toISOString(),
    depth: input.depth,
    ...(input.url === undefined ? {} : { live_target: input.url }),
    detection: input.detection,
    scores: {
      security: { ...sec, checks_that_ran: `${coverage.ran} of ${coverage.planned} planned checks produced an answer` },
      quality: qual,
    },
    fix_first: fixFirst.map((finding) => redactFinding(finding)),
    findings: findings.map((finding) => redactFinding(finding)),
    could_not_check: could,
    gate: {
      decision: input.decision.satisfied ? 'satisfied' : 'blocked',
      blocking_reasons: input.decision.reasons.length,
      controls_satisfied: input.decision.control_outcomes.filter((outcome) => outcome.outcome === 'satisfied').length,
      controls_total: input.decision.control_outcomes.length,
    },
    policy_commit: input.policyCommit,
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

function redactFinding(finding: AnnotatedFinding): AnnotatedFinding {
  return {
    ...finding,
    title: redactSecrets(finding.title),
    location: redactSecrets(finding.location),
    ...(finding.detail === undefined ? {} : { detail: redactSecrets(finding.detail) }),
    prompt: redactSecrets(finding.prompt),
  };
}

// --- Markdown -----------------------------------------------------------------

function buildMarkdown(
  input: AuditReportInput,
  findings: readonly AnnotatedFinding[],
  fixFirst: readonly AnnotatedFinding[],
  sec: { score: number | null; verdict: string },
  qual: { score: number | null; verdict: string },
  could: readonly string[],
  coverage: { ran: number; planned: number },
): string {
  const lines: string[] = [
    `# Security audit — ${safe(input.targetName)}`,
    '',
    `Audited on ${input.generatedAt.toISOString()} at depth \`${input.depth}\`. SecHard audits and suggests; it never modified the audited code.`,
    ...(input.url === undefined
      ? []
      : [`Live target: \`${input.url.scheme}://${input.url.host}${input.url.port === undefined ? '' : `:${input.url.port}`}\` (approved by the operator; resolved to ${input.url.resolvedAddresses.map((address) => `\`${address}\``).join(', ')})`]),
    '',
    '## Summary',
    '',
    '| Area | Score | Verdict |',
    '| --- | --- | --- |',
    `| Security | ${sec.score === null ? '—' : String(sec.score)} | ${safe(sec.verdict)} |`,
    `| Quality | ${qual.score === null ? '—' : String(qual.score)} | ${safe(qual.verdict)} |`,
    '',
    `Of the checks planned for this audit, **${coverage.ran} of ${coverage.planned}** produced an answer. A score is only a signal over what ran — read the "What we could not check" list before trusting it.`,
    '',
    '## Fix these first',
    '',
  ];

  if (fixFirst.length === 0) {
    lines.push('No findings among the checks that ran.');
  } else {
    lines.push('| # | Severity | Where | What it is | Effort | Confidence |', '| --- | --- | --- | --- | --- | --- |');
    fixFirst.forEach((finding, index) => {
      lines.push(`| ${index + 1} | ${finding.severity} | \`${safe(finding.location || '(no location)')}\` | ${safe(finding.title)} | ${finding.effort} | ${finding.confidence} |`);
    });
  }

  lines.push('', '## What we could not check', '');
  if (could.length === 0) {
    lines.push('Everything planned ran.');
  } else {
    for (const item of could) lines.push(`- ${safe(item)}`);
  }

  lines.push('', '## Findings', '');
  if (findings.length === 0) {
    lines.push('No findings were reported by the checks that ran.');
  } else {
    for (const finding of findings) {
      lines.push(
        `### ${finding.severity}: ${safe(finding.title)}`,
        '',
        `- **Where:** \`${safe(finding.location || '(no location)')}\``,
        `- **Reported by:** ${safe(finding.tool)} (rule \`${safe(finding.rule_id)}\`)`,
        ...(finding.detail === undefined ? [] : [`- **Detail:** ${safe(finding.detail)}`]),
        `- **Why it matters:** ${safe(finding.what)}`,
        `- **How to fix it:** ${safe(finding.fix)}`,
        `- **Effort:** ${finding.effort} · **Confidence:** ${finding.confidence}`,
        ...(finding.control_ids.length === 0 ? [] : [`- **Controls:** ${finding.control_ids.join(', ')}`]),
        ...(finding.standards.length === 0 ? [] : [`- **Standards references:** ${finding.standards.map((ref) => safe(ref)).join('; ')} (related-risk references, not verified conformance)`]),
        `- **Ready-to-paste prompt for your AI assistant:**`,
        '',
        '  ```text',
        `  ${safe(finding.prompt)}`,
        '  ```',
        '',
      );
    }
  }

  lines.push(
    '## Gaps and coverage',
    '',
    `- Detected stack: \`${input.detection.stack.kind}\``,
    `- Composed profiles: ${input.detection.profiles.map((profile) => `\`${profile.id}\``).join(', ')}`,
    `- Languages seen: ${Object.entries(input.detection.languages).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([language, count]) => `\`${language}\` (${count})`).join(', ') || 'none detected'}`,
    `- Gate-mode obligations (manual attestations, release evidence) are reported by the gate as unmet for an audit; an audit is advisory and produces no release evidence.`,
    '',
    '## How the gate saw it',
    '',
    `The same evaluation the gate produced, unchanged: decision \`${input.decision.satisfied ? 'satisfied' : 'blocked'}\` with ${input.decision.reasons.length} blocking reason(s); ${input.decision.control_outcomes.filter((outcome) => outcome.outcome === 'satisfied').length} of ${input.decision.control_outcomes.length} applicable controls satisfied. An audit is advisory: a blocked gate here means "requirements exist that source alone cannot satisfy", not "the application failed".`,
    '',
    '---',
    '',
    'Generated from the same evaluation as the gate. Formatting does not change the decision.',
  );

  return `${lines.join('\n')}\n`;
}

// --- HTML ---------------------------------------------------------------------

const CSS = `
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1, h2 { border-bottom: 2px solid #ddd; padding-bottom: .3rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; vertical-align: top; font-size: .95rem; }
.critical, .high { color: #b00020; font-weight: 600; }
.medium { color: #b00020; }
pre { background: #f4f4f4; padding: .8rem; overflow-x: auto; border-radius: 4px; font-size: .85rem; }
.gaps li { margin: .2rem 0; }
.finding { border: 1px solid #e0e0e0; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
.finding h3 { margin-top: 0; }
.banner { background: #fff3cd; border: 1px solid #ffe08a; padding: .8rem 1rem; border-radius: 6px; }
footer { color: #777; font-size: .85rem; margin-top: 3rem; }
`;

function buildHtml(
  input: AuditReportInput,
  findings: readonly AnnotatedFinding[],
  fixFirst: readonly AnnotatedFinding[],
  sec: { score: number | null; verdict: string },
  qual: { score: number | null; verdict: string },
  could: readonly string[],
  coverage: { ran: number; planned: number },
): string {
  const fixRows = fixFirst.map((finding, index) =>
    `<tr><td>${index + 1}</td><td class="${h(finding.severity)}">${h(finding.severity)}</td><td><code>${h(finding.location || '(no location)')}</code></td><td>${h(finding.title)}</td><td>${h(finding.effort)}</td><td>${h(finding.confidence)}</td></tr>`,
  ).join('\n');

  const gapItems = could.map((item) => `<li>${h(item)}</li>`).join('\n');

  const findingBlocks = findings.map((finding) => {
    const standards = finding.standards.length === 0 ? '' : `<li><strong>Standards references:</strong> ${h(finding.standards.join('; '))} (related-risk references, not verified conformance)</li>`;
    const controls = finding.control_ids.length === 0 ? '' : `<li><strong>Controls:</strong> ${h(finding.control_ids.join(', '))}</li>`;
    return `<div class="finding">
<h3 class="${h(finding.severity)}">${h(finding.severity)}: ${h(finding.title)}</h3>
<ul>
<li><strong>Where:</strong> <code>${h(finding.location || '(no location)')}</code></li>
<li><strong>Reported by:</strong> ${h(finding.tool)} (rule <code>${h(finding.rule_id)}</code>)</li>
<li><strong>Why it matters:</strong> ${h(finding.what)}</li>
<li><strong>How to fix it:</strong> ${h(finding.fix)}</li>
<li><strong>Effort:</strong> ${h(finding.effort)} &middot; <strong>Confidence:</strong> ${h(finding.confidence)}</li>
${controls}
${standards}
</ul>
<p><strong>Ready-to-paste prompt for your AI assistant:</strong></p>
<pre>${h(finding.prompt)}</pre>
</div>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security audit — ${h(input.targetName)}</title><style>${CSS}</style></head>
<body>
<h1>Security audit — ${h(input.targetName)}</h1>
<p>Audited on ${h(input.generatedAt.toISOString())} at depth <code>${h(input.depth)}</code>. SecHard audits and suggests; it never modified the audited code.</p>
${input.url === undefined ? '' : `<p>Live target: <code>${h(`${input.url.scheme}://${input.url.host}${input.url.port === undefined ? '' : `:${input.url.port}`}`)}</code> (approved by the operator; resolved to ${input.url.resolvedAddresses.map((address) => `<code>${h(address)}</code>`).join(', ')})</p>`}
${input.detection.unsupported_stack === undefined ? '' : `<div class="banner"><strong>Unsupported stack.</strong> ${h(input.detection.unsupported_stack.reason)} Generic checks that still ran: ${h(input.detection.unsupported_stack.generic_checks.join(', '))}.</div>`}
<h2>Summary</h2>
<table><tr><th>Area</th><th>Score</th><th>Verdict</th></tr>
<tr><td>Security</td><td>${sec.score === null ? '—' : h(String(sec.score))}</td><td>${h(sec.verdict)}</td></tr>
<tr><td>Quality</td><td>${qual.score === null ? '—' : h(String(qual.score))}</td><td>${h(qual.verdict)}</td></tr></table>
<p>Of the checks planned for this audit, <strong>${coverage.ran} of ${coverage.planned}</strong> produced an answer. A score is only a signal over what ran — read the &ldquo;What we could not check&rdquo; list before trusting it.</p>
<h2>Fix these first</h2>
${fixFirst.length === 0 ? '<p>No findings among the checks that ran.</p>' : `<table><tr><th>#</th><th>Severity</th><th>Where</th><th>What it is</th><th>Effort</th><th>Confidence</th></tr>\n${fixRows}</table>`}
<h2>What we could not check</h2>
${could.length === 0 ? '<p>Everything planned ran.</p>' : `<ul class="gaps">\n${gapItems}\n</ul>`}
<h2>Findings</h2>
${findings.length === 0 ? '<p>No findings were reported by the checks that ran.</p>' : findingBlocks}
<h2>How the gate saw it</h2>
<p>The same evaluation the gate produced, unchanged: decision <code>${h(input.decision.satisfied ? 'satisfied' : 'blocked')}</code> with ${h(String(input.decision.reasons.length))} blocking reason(s); ${h(String(input.decision.control_outcomes.filter((outcome) => outcome.outcome === 'satisfied').length))} of ${h(String(input.decision.control_outcomes.length))} applicable controls satisfied. An audit is advisory: a blocked gate here means &ldquo;requirements exist that source alone cannot satisfy&rdquo;, not &ldquo;the application failed&rdquo;.</p>
<footer>Generated from the same evaluation as the gate. Formatting does not change the decision.</footer>
</body></html>
`;
}

// --- SARIF (GitHub code scanning) ----------------------------------------------

/**
 * Minimal SARIF 2.1.0: one run, one result per finding, rule ids preserved.
 *
 * Safety rules (gap analysis D5): the document must validate against the SARIF 2.1.0 schema; all
 * text is redacted; no snippets are ever included (a secret finding's snippet would be the secret);
 * artifact URIs are relative paths or the approved URL, never absolute local paths.
 */
function buildSarif(input: AuditReportInput, findings: readonly AnnotatedFinding[]): string {
  const results = findings.map((finding) => ({
    ruleId: finding.rule_id === '' ? `${finding.tool}/${finding.id}` : finding.rule_id,
    level: sarifLevel(finding.severity),
    message: { text: redactSecrets(`${finding.title}. ${finding.what} ${finding.fix}`) },
    locations: [{
      physicalLocation: {
        artifactLocation: sarifUri(finding.location),
      },
    }],
  }));

  const document = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0' as const,
    runs: [
      {
        tool: {
          driver: {
            name: 'sechard-audit',
            informationUri: 'https://github.com/domgeller2022-arch/SecHard',
            version: '0.1.0-dev.0',
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: input.generatedAt.toISOString(),
          },
        ],
        originalUriBaseIds: {
          AUDITROOT: { uri: pathToFileUri(input.target), description: { text: 'The audited directory' } },
        },
        results,
      },
    ],
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium' || severity === 'low') return 'warning';
  return 'note';
}

function sarifUri(location: string): { uri: string; uriBaseId: string } | { uri: string } {
  const redacted = redactSecrets(location);
  if (/^https?:\/\//.test(redacted)) return { uri: redacted };
  // SARIF requires artifact URIs to be valid uri-references. Scanner locations are file paths with
  // line suffixes (`src/x.ts:3`) or free text (`requests@2.19.1 (PyPI)`); percent-encoding each
  // path segment keeps the location readable and the document valid, strips control characters,
  // and never emits an absolute local path (those carry a uriBaseId instead).
  const cleaned = redacted.replace(/[\u0000-\u001f\u007f]/g, '');
  const encoded = cleaned.split('/').map(encodeURIComponent).join('/');
  if (cleaned.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(cleaned)) {
    return { uri: encoded.replace(/\\/g, '/'), uriBaseId: 'AUDITROOT' };
  }
  return { uri: encoded };
}

function pathToFileUri(target: string): string {
  const encoded = target.replace(/\\/g, '/').replace(/[\u0000-\u001f\u007f"<>^`{|}]/g, encodeURIComponent);
  return `file://${encoded.startsWith('/') ? '' : '/'}${encoded}`;
}
