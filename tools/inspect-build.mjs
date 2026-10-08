#!/usr/bin/env node
// Produces build evidence for a browser output directory.
//
// What this connects, per the plan: the assessed source, the pinned policy, the actual build output,
// and the inspection result — with a digest over the inspected inventory so a later run can tell
// whether the artifact changed. It also re-reads the source identity after inspection: a build
// inspected while the tree moved underneath it describes a source that no longer exists.
//
// Usage: node tools/inspect-build.mjs [browser-output-dir] [evidence-out.json]
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectBrowserAssets, inventoryDigest } from '../dist/build/client-assets.js';
import { loadPolicy, resolveSourceIdentity } from '../dist/commands/io.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const target = resolve(process.argv[2] ?? join(root, 'examples', 'nextjs-supabase', '.next', 'static'));
const out = resolve(process.argv[3] ?? join(root, 'build-evidence.json'));

if (!existsSync(target)) {
  console.error(`no build output at ${target}; run the application build first`);
  process.exit(2);
}

const planPolicy = loadPolicy({ appRoot: root, policyRoot: root });
if (planPolicy.value === undefined || planPolicy.issues.length > 0) {
  console.error('policy inputs are invalid; refusing to produce build evidence');
  process.exit(2);
}

const sourceBefore = resolveSourceIdentity(root);
const report = inspectBrowserAssets(target);
const digest = inventoryDigest(report);
const sourceAfter = resolveSourceIdentity(root);

const sourceChanged = sourceBefore.commit !== sourceAfter.commit || sourceBefore.dirty !== sourceAfter.dirty;

const evidence = {
  schema: 'hardening/build-evidence/v1',
  generated_at: new Date().toISOString(),
  source: {
    commit: sourceBefore.commit,
    dirty: sourceBefore.dirty,
    // A release decision needs a clean, stable source identity. This records both facts rather than
    // assuming them.
    changed_during_run: sourceChanged,
    changed_detail: sourceChanged ? `${sourceBefore.commit}/${sourceBefore.dirty} -> ${sourceAfter.commit}/${sourceAfter.dirty}` : undefined,
  },
  policy: {
    commit: planPolicy.value.policyCommit,
    control_catalogue_digest: planPolicy.value.controlCatalogueDigest,
  },
  artifact: {
    inspected_root: report.inspectedRoot,
    file_count: report.files.length,
    total_bytes: report.totalBytes,
    inventory_digest: digest,
    scope_statement: report.scopeStatement,
  },
  inspection: {
    coverage: report.coverage,
    findings: report.findings,
    classifications: report.classifications,
    source_maps: report.sourceMaps,
    parse_errors: report.parseErrors,
  },
  // Quality information is reported separately from the security result, and no threshold is applied
  // to it here: a bundle-size limit that fails a build is a policy decision nobody has made yet.
  quality_information: {
    file_count: report.files.length,
    total_bytes: report.totalBytes,
    largest_files: [...report.files].sort((a, b) => b.bytes - a.bytes).slice(0, 5),
  },
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');

console.log(`build evidence: ${out}`);
console.log(`  source ${evidence.source.commit.slice(0, 12)}${evidence.source.dirty ? ' (dirty)' : ''}${sourceChanged ? ' — CHANGED DURING RUN' : ''}`);
console.log(`  policy ${evidence.policy.commit.slice(0, 12)}`);
console.log(`  artifact ${report.files.length} files, ${report.totalBytes} bytes, digest ${digest.slice(0, 12)}…`);
console.log(`  coverage ${report.coverage}: ${report.scopeStatement}`);
console.log(`  classifications ${report.classifications.length}, findings ${report.findings.length}, source maps ${report.sourceMaps.length}`);
for (const finding of report.findings) console.log(`  FINDING ${finding.severity} ${finding.rule_id}: ${finding.location}`);

const failed = report.findings.length > 0 || sourceChanged || report.coverage === 'unknown';
process.exit(failed ? 1 : 0);
