#!/usr/bin/env node
// Reports security-test and sensitive-path changes between two revisions.
//
// Use:  node tools/review-changes.mjs <base-ref> [head-ref]
// It exits 0 when nothing needs review and 1 when something does, so a CI job can use the exit code
// while a human reads the detail.
import { buildChangeReport, formatChangeReport } from '../dist/agent/change-report.js';

const [base, head] = process.argv.slice(2);
if (base === undefined) {
  process.stderr.write('usage: node tools/review-changes.mjs <base-ref> [head-ref]\n');
  process.exit(2);
}

const report = buildChangeReport({ base, ...(head === undefined ? {} : { head }) });
process.stdout.write(`${formatChangeReport(report)}\n`);
process.exit(report.requiresReview ? 1 : 0);
