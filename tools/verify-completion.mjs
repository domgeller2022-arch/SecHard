#!/usr/bin/env node
// P0.1 (plan section 2): the bounded completion verifier. It fails for: an unparsable ledger,
// a ledger task marked done without existing evidence files, an acceptance-matrix case whose
// suite/runner file is missing, a dangling ledger reference, or a changelog that no longer
// matches its recorded hash. It never derives success from ledger status text alone.
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const fail = (message) => { failures += 1; console.error(`FAIL: ${message}`); };

const ledgerPath = join(repo, 'docs', 'completion-ledger.yaml');
if (!existsSync(ledgerPath)) fail('docs/completion-ledger.yaml is missing');
const ledger = parseYaml(readFileSync(ledgerPath, 'utf8'));

const matrixPath = join(repo, 'tests', 'completion', 'acceptance-matrix.yaml');
if (!existsSync(matrixPath)) {
  fail('tests/completion/acceptance-matrix.yaml is missing');
} else {
  const matrix = parseYaml(readFileSync(matrixPath, 'utf8'));
  for (const caseEntry of matrix.cases ?? []) {
    const ref = caseEntry.suite ?? caseEntry.runner;
    const refPath = typeof ref === 'string' ? ref.replace(/^node\s+/, '') : undefined;
    if (refPath === undefined || !existsSync(join(repo, refPath))) {
      fail(`case ${caseEntry.id}: referenced file missing: ${String(ref)}`);
    }
  }
  if ((matrix.cases ?? []).length === 0) fail('the acceptance matrix has no cases');
}

const expectedHash = ledger?.baseline?.changelog_hash_after_governance_note;
if (typeof expectedHash !== 'string' || expectedHash.length !== 64) {
  fail('the ledger records no changelog hash');
} else {
  const actual = createHash('sha256').update(readFileSync(join(repo, 'CHANGELOG.md'))).digest('hex');
  if (actual !== expectedHash) fail(`changelog hash drift: recorded ${expectedHash.slice(0, 12)}…, actual ${actual.slice(0, 12)}… — record the new hash in the same change`);
}

// Every ledger task marked done must point at existing evidence.
const walk = (node, path) => {
  if (Array.isArray(node)) return;
  if (node && typeof node === 'object') {
    if (node.state === 'done') {
      const evidence = node.evidence ?? node.evidence_paths;
      if (evidence === undefined) {
        fail(`${path} is marked done without evidence paths`);
      } else {
        const list = Array.isArray(evidence) ? evidence : [evidence];
        for (const entry of list) {
          if (typeof entry !== 'string' || !existsSync(join(repo, entry))) {
            fail(`${path} marked done: evidence missing: ${String(entry)}`);
          }
        }
      }
    }
    for (const [key, value] of Object.entries(node)) walk(value, `${path}.${String(key)}`);
  }
};
walk(ledger, 'ledger');

if (failures > 0) {
  console.error(`verify-completion: ${String(failures)} failure(s)`);
  process.exit(1);
}
console.log('verify-completion: OK (ledger parsable, evidence present, matrix references exist, changelog intact)');
