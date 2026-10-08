#!/usr/bin/env node
// Points the example application's policy lock at the repository's current reviewed commit.
//
// The example lives inside the hardening repository, so its policy pin moves every time the
// repository is committed. This script keeps the pin honest instead of letting a stale lock make
// validation fail for the wrong reason. A real consumer pins a released commit and re-locks
// deliberately; that difference is stated in the example's README.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPolicy } from '../dist/commands/io.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const { gitExecutable } = await import('../dist/agent/review-manifest.js');

const git = gitExecutable();
if (git === undefined) {
  process.stderr.write('git is not available; cannot resolve the policy commit\n');
  process.exit(2);
}
const commit = execFileSync(git, ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();

const policy = loadPolicy({ appRoot: root, policyRoot: root });
if (policy.value === undefined || policy.issues.length > 0) {
  process.stderr.write('policy inputs are invalid; refusing to write a lock\n');
  process.exit(2);
}

const manifestPath = join(root, 'examples', 'nextjs-supabase', '.hardening', 'app.yaml');
const manifest = readFileSync(manifestPath, 'utf8');
const updated = manifest
  .replace(/^(\s*commit:\s*)"[0-9a-f]{40}"/m, `$1"${commit}"`)
  .replace(/^(\s*policy_digest:\s*)"[0-9a-f]{64}"/m, `$1"${policy.value.controlCatalogueDigest}"`)
  .replace(/^(\s*locked_at:\s*)"[^"]*"/m, `$1"${new Date().toISOString()}"`);

writeFileSync(manifestPath, updated, 'utf8');
process.stdout.write(`relinked example policy lock to ${commit.slice(0, 12)}\n`);
