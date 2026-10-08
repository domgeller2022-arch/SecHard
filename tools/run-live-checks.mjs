#!/usr/bin/env node
// Runs the live HTTP recipe against an approved target inventory and writes evidence.
//
// Usage: node tools/run-live-checks.mjs <inventory.yaml> <environment> [evidence-out.json]
//
// Exit codes: 0 satisfied, 1 findings or incomplete coverage, 2 invalid input.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadTargetInventory, runHttpChecks } from '../dist/adapters/http.js';
import { resolveSourceIdentity } from '../dist/commands/io.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const [inventoryPath, environment, outArg] = process.argv.slice(2);

if (!inventoryPath || !environment) {
  console.error('usage: node tools/run-live-checks.mjs <inventory.yaml> <local|preview|staging|production> [evidence-out.json]');
  process.exit(2);
}

const loaded = loadTargetInventory(resolve(inventoryPath));
if (loaded.inventory === undefined || loaded.issues.length > 0) {
  console.error('the target inventory is not usable; refusing to contact anything');
  for (const issue of loaded.issues) console.error(`  ${issue}`);
  process.exit(2);
}

const source = resolveSourceIdentity(root);
const outcome = await runHttpChecks(loaded.inventory, { environment });

const evidence = {
  schema: 'hardening/live-check-evidence/v1',
  generated_at: new Date().toISOString(),
  environment,
  source: { commit: source.commit, dirty: source.dirty },
  inventory: { path: resolve(inventoryPath), targets: loaded.inventory.targets.map((target) => `${target.id} (${target.scheme}://${target.host})`) },
  scope: outcome.scope,
  coverage: outcome.coverage,
  findings: outcome.findings,
  parser_errors: outcome.parserErrors,
  limits: outcome.scope.notes,
};

const out = resolve(outArg ?? `${root}/live-check-evidence.json`);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');

console.log(`live checks: environment ${environment}`);
console.log(`  source ${source.commit.slice(0, 12)}${source.dirty ? ' (dirty)' : ''}`);
console.log(`  routes ${outcome.scope.observed}/${outcome.scope.expected} observed, coverage ${outcome.coverage}`);
console.log(`  findings ${outcome.findings.length}`);
for (const finding of outcome.findings) console.log(`  ${finding.severity.toUpperCase()} ${finding.rule_id}: ${finding.location ?? ''} — ${finding.title}`);
console.log(`  limits: ${outcome.scope.notes}`);
console.log(`evidence: ${out}`);

// Incomplete coverage is not a pass: an unreachable route means the requirement was not verified.
const blocked = outcome.findings.length > 0 || outcome.coverage !== 'complete' || outcome.scope.expected === 0;
process.exit(blocked ? 1 : 0);
