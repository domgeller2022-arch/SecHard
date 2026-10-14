#!/usr/bin/env node
// The completion verifier (P0, auditor correction sections 3-4).
//
// verify:completion        — the FINAL gate: exits nonzero while any mandatory task is not
//                            done-with-verified-evidence. Success is only possible when the
//                            programme's own ledger says everything is closed.
// verify:completion --preflight — structural preflight only: parses, references, confinement,
//                            changelog bytes. Prints an explicitly LIMITED success message; it
//                            never implies completion.
//
// Bounds: reads are byte-limited at open time (never buffer-unbounded), traversal covers arrays
// with a depth budget, evidence/test references are confined under the repository root (no
// traversal, no symlinks, regular files only), and every failure is a structured diagnostic.
const IMMUTABLE_CHANGELOG_SHA256 = '18a37123aeba715d607318c0c458aaf6b914599ea91da929a815026fff9b602e'; // 15 Oct: superseded from 858bb9cf by owner instruction (decision p0_d_02)
const MAX_LEDGER_BYTES = 512 * 1024;
const MAX_MATRIX_BYTES = 512 * 1024;
const MAX_CHANGELOG_BYTES = 2 * 1024 * 1024;
const MAX_WALK_DEPTH = 16;

import { closeSync, lstatSync, openSync, readSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const repo = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const preflightOnly = process.argv.includes('--preflight');
const failures = [];
const unresolved = [];
const fail = (message) => { failures.push(message); };

function readBounded(path, maxBytes) {
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(maxBytes);
    const read = readSync(fd, buffer, 0, maxBytes, 0);
    return { text: buffer.subarray(0, read).toString('utf8'), bytes: read };
  } finally {
    closeSync(fd);
  }
}

function confinedExistingFile(root, ref) {
  if (typeof ref !== 'string' || ref === '' || isAbsolute(ref)) return `not a repository-relative path: ${String(ref)}`;
  const full = resolve(join(root, ref));
  const rel = relative(root, full);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`)) return `escapes the repository root: ${String(ref)}`;
  let stats;
  try {
    stats = lstatSync(full);
  } catch {
    return `missing: ${String(ref)}`;
  }
  if (stats.isSymbolicLink()) return `is a symlink: ${String(ref)}`;
  if (!stats.isFile()) return `is not a regular file: ${String(ref)}`;
  return undefined;
}

function loadYaml(name, path, maxBytes) {
  try {
    const { text, bytes } = readBounded(path, maxBytes);
    return { parsed: parseYaml(text), bytes };
  } catch (error) {
    fail(`${name} could not be read/parsed: ${(error).message}`);
    return undefined;
  }
}

const ledger = loadYaml('ledger', join(repo, 'docs', 'completion-ledger.yaml'), MAX_LEDGER_BYTES);
const matrix = loadYaml('acceptance matrix', join(repo, 'tests', 'completion', 'acceptance-matrix.yaml'), MAX_MATRIX_BYTES);

// Changelog: frozen bytes.
try {
  const { text } = readBounded(join(repo, 'CHANGELOG.md'), MAX_CHANGELOG_BYTES);
  const actual = createHash('sha256').update(text, 'utf8').digest('hex');
  if (actual !== IMMUTABLE_CHANGELOG_SHA256) {
    fail(`changelog is not the frozen programme hash (expected ${IMMUTABLE_CHANGELOG_SHA256.slice(0, 12)}…, found ${actual.slice(0, 12)}…). No changelog edit is authorised during this programme.`);
  }
} catch (error) {
  fail(`changelog could not be read: ${(error).message}`);
}

// Matrix references: confined, existing, regular files. IDs unique.
if (matrix?.parsed !== undefined) {
  const cases = matrix.parsed.cases ?? [];
  if (!Array.isArray(cases) || cases.length === 0) fail('the acceptance matrix has no cases');
  const seen = new Set();
  for (const entry of cases) {
    if (typeof entry.id !== 'string' || entry.id === '') { fail('a matrix case has no stable ID'); continue; }
    if (seen.has(entry.id)) fail(`duplicate matrix case ID: ${entry.id}`);
    seen.add(entry.id);
    const ref = entry.suite ?? entry.runner;
    const refPath = typeof ref === 'string' ? ref.replace(/^node\s+/, '') : undefined;
    const problem = confinedExistingFile(repo, refPath);
    if (problem !== undefined) fail(`case ${entry.id}: ${problem}`);
  }
} else {
  fail('the acceptance matrix is absent or unparsable');
}

// Ledger traversal: arrays included, depth-budgeted. Every non-done task is unresolved
// mandatory work; every done task needs non-empty, confined evidence; unknown shapes rejected.
const KNOWN_STATES = new Set(['pending', 'in_progress', 'done', 'blocked']);
const visitTask = (node, path) => {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    fail(`ledger task ${path}: unsupported shape (expected a task mapping)`);
    return;
  }
  const state = node.state;
  if (typeof state !== 'string' || !KNOWN_STATES.has(state)) {
    fail(`ledger task ${path}: unknown state ${String(state)}`);
    return;
  }
  if (state !== 'done') {
    unresolved.push(`${path} (${state}${node.note !== undefined ? `: ${String(node.note)}` : ''})`);
    return;
  }
  const evidence = node.evidence;
  if (!Array.isArray(evidence) || evidence.length === 0) {
    fail(`ledger task ${path} is done without non-empty evidence`);
    return;
  }
  for (const entry of evidence) {
    const problem = confinedExistingFile(repo, entry);
    if (problem !== undefined) fail(`ledger task ${path}: evidence ${problem}`);
  }
};
const walk = (node, path, depth) => {
  if (depth > MAX_WALK_DEPTH) { fail(`ledger nesting exceeds budget at ${path}`); return; }
  if (node !== null && typeof node === 'object') {
    if (node.state !== undefined) { visitTask(node, path); return; }
    for (const [key, value] of Object.entries(node)) {
      if (Array.isArray(value)) value.forEach((item, index) => walk(item, `${path}.${String(key)}[${String(index)}]`, depth + 1));
      else if (value !== null && typeof value === 'object') walk(value, `${path}.${String(key)}`, depth + 1);
    }
  }
};
if (ledger?.parsed !== undefined) walk(ledger.parsed, 'ledger', 0);
else fail('the ledger is absent or unparsable');

if (failures.length > 0) {
  for (const message of failures) console.error(`FAIL: ${message}`);
  process.exit(1);
}
if (preflightOnly) {
  console.log(`preflight OK (structure, references, confinement, frozen changelog). NOT completion: ${String(unresolved.length)} mandatory task(s) still open.`);
  process.exit(0);
}
if (unresolved.length > 0) {
  console.error(`completion NOT met: ${String(unresolved.length)} mandatory task(s) unresolved:`);
  for (const item of unresolved) console.error(`  - ${item}`);
  process.exit(1);
}
console.log('completion: all ledger tasks done with confined, non-empty evidence and the changelog frozen.');
