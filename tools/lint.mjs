#!/usr/bin/env node
// Repository hygiene check. Deliberately dependency-free: no linter is installed yet, so this
// checks only the properties that actually matter for this repository and that a type checker
// cannot see. `npm run typecheck` covers types; this covers hygiene.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'coverage',
  '.hardening',
  'runs',
  '.next',
  '.turbo',
]);
const TEXT_EXTENSIONS = new Set([
  '.ts',
  '.mjs',
  '.js',
  '.json',
  '.yaml',
  '.yml',
  '.md',
  '.txt',
  '.sql',
  '.sh',
]);
const problems = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (IGNORED_DIRS.has(entry)) continue;
    // Provisioning output (downloaded tools) is not source and is gitignored.
    if (entry === 'bin' && dir === join(ROOT, 'tools')) continue;
    if (statSync(full).isDirectory()) {
      walk(full);
      continue;
    }
    check(full);
  }
}

function check(file) {
  const shown = relative(ROOT, file);
  const ext = extname(file);

  if (ext === '.json') {
    try {
      JSON.parse(readFileSync(file, 'utf8'));
    } catch (error) {
      problems.push(`${shown}: invalid JSON (${error.message})`);
      return;
    }
  }

  if (!TEXT_EXTENSIONS.has(ext)) return;

  const bytes = readFileSync(file);
  if (bytes.includes(0x0d)) {
    problems.push(`${shown}: contains CR/CRLF line endings`);
  }
  const text = bytes.toString('utf8');
  if (text.includes('\t')) {
    problems.push(`${shown}: contains a tab character`);
  }
  if (!text.endsWith('\n')) {
    problems.push(`${shown}: missing final newline`);
  }
  for (const [index, line] of text.split('\n').entries()) {
    if (line !== line.trimEnd()) {
      problems.push(`${shown}:${index + 1}: trailing whitespace`);
    }
  }
}

walk(ROOT);

const lockfiles = readdirSync(ROOT).filter((name) => /^(package-lock|npm-shrinkwrap)\.json$/.test(name));
for (const name of lockfiles) {
  problems.push(
    `${name}: pnpm is the pinned package manager. Remove this lockfile; do not commit two lockfiles.`,
  );
}

if (problems.length > 0) {
  process.stderr.write(`lint: ${problems.length} problem(s)\n`);
  for (const problem of problems) process.stderr.write(`  ${problem}\n`);
  process.exit(1);
}

process.stdout.write('lint: OK\n');
