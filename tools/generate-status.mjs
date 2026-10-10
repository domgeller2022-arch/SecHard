#!/usr/bin/env node
// Generates docs/status.md from the progress record.
//
// The status document is derived, never hand-written: a claim cannot drift from the record because
// there is nothing to drift. Every section is a heading in docs/implementation-progress.md that
// carries a `- **State:** ...` line.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const progressPath = join(root, 'docs', 'implementation-progress.md');
const statusPath = join(root, 'docs', 'status.md');
const checkOnly = process.argv.includes('--check');

const source = readFileSync(progressPath, 'utf8');
const digest = createHash('sha256').update(source).digest('hex');

const sections = [];
let current;
for (const line of source.split(/\r?\n/)) {
  const heading = line.match(/^(#{2,3})\s+(.+?)\s*$/);
  if (heading !== null) {
    current = { level: heading[1].length, title: heading[2], state: undefined };
    sections.push(current);
    continue;
  }
  // A state is only recognised when it is backticked and follows the label directly: prose like
  // "State: resolved and verified" or "verified except ... `blocked`" must not be parsed as a state.
  const state = line.match(/^-\s+\*\*State:\*\*\s+`([a-z_]+)`/);
  if (state !== null && current !== undefined && current.state === undefined) {
    current.state = state[1];
  }
}

// The progress record is append-only and later sections revisit earlier steps, so the first
// state-bearing heading for a step is its main log entry. Batch headings are kept as-is.
const latestStep = new Map();
const batches = [];
for (const section of sections) {
  if (section.state === undefined) continue;
  const step = section.title.match(/^Step (\d+)/);
  if (step !== null) {
    if (!latestStep.has(Number(step[1]))) latestStep.set(Number(step[1]), section);
  } else if (/^Batch\b/.test(section.title)) {
    batches.push(section);
  }
}
const reported = [...[...latestStep.entries()].sort((a, b) => a[0] - b[0]).map(([, section]) => section), ...batches];

const lines = [
  '# Status',
  '',
  `> Generated from \`docs/implementation-progress.md\` (source SHA-256 \`${digest}\`) by`,
  '> `node tools/generate-status.mjs`. Do not edit by hand: edit the progress record and regenerate.',
  '> A section appears here only when the record states its state; "verified" means the record\'s',
  '> stated acceptance checks ran, nothing more.',
  '',
  '| Section | State |',
  '| --- | --- |',
  ...reported.map((section) => `| ${section.title.replace(/\|/g, '\\|')} | \`${section.state}\` |`),
  '',
  '## Open findings and blockers',
  '',
  'These are not generated: the authoritative list is in `docs/implementation-progress.md` and',
  '`CHANGELOG.md`. The short version, as of Batch S:',
  '',
  '- standards (Batch S): 518 requirement-level mapping entries across eight standards, generated',
  '  coverage matrices, a per-application standards statement in every audit; catalogue v3 (48',
  '  controls, AUTH-03 added); WSTG citations invalidated 14 v1 approvals deliberately - Batch D',
  '  re-approves the sheet;',
  '- quality (Batch Q): six calibrated recipes wired; the twelve QUAL definitions remain draft',
  '  pending owner approval, which blocks release evaluation; external-analyser recipes report',
  '  unsupported with the tool named;',
  '- audit mode exists (Batch U) with stated limits: local folder only, `deep` equals `standard`',
  '  until the isolation model exists, and Python static analysis is not run (JS/TS rule pack only);',
  '- the scanner, client-asset, and live-HTTP recipes are wired (Batch W); the authorization,',
  '  functional, dependency-policy, agent, and release recipes are not, so no app fully passes yet;',
  '- the PR workflow now evaluates the base branch\'s records (Batch W3); its platform behaviour is',
  '  unverified until a real pull request runs on the private repository;',
  '- TLS remains manual (testssl unpinned, Batch X); ZAP is not a control recipe;',
  '- the local development stack is reachable from the LAN (open finding; no batch owns it yet);',
  '- AUTH-02 recovery isolation and genuine session expiry are untested;',
  '- no `LICENSE` and no security contact **by owner decision**: private, sole-maintainer, and\n  undistributed; OPS-03 stays unmet and release evaluation blocks, which is correct while no release\n  is planned;',
  '- platform verification (Step 13) awaits the owner\'s throwaway GitHub account;',
  '- the vendored SARIF schema is OASIS material: licence review before any distribution (Batch D).',
  '',
];

const output = `${lines.join('\n')}\n`;

if (checkOnly) {
  let existing = '';
  try {
    existing = readFileSync(statusPath, 'utf8');
  } catch {
    // Missing is out of date.
  }
  if (existing !== output) {
    process.stderr.write('docs/status.md is out of date; run `pnpm run generate:status`\n');
    process.exit(1);
  }
  process.stdout.write('docs/status.md is current\n');
} else {
  writeFileSync(statusPath, output, 'utf8');
  process.stdout.write(`generated ${statusPath}\n`);
}
