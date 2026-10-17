#!/usr/bin/env node
// Workstream M (R1-M1): the executable calibration baseline for the Appendix A corpus.
//
// One seed table, mapped to the brief's Appendix A (SecHard-fix-brief-2026-10-10.md, "Appendix A"):
// every item has a stable ID, the file it lives in, the rule expected to report it, and its
// statically-checkable classification. The runner composes the corpus (secret shapes at runtime),
// runs the compiled `hardening audit`, and derives each seed's outcome from the actual
// results.json — statuses are never hand-labelled. Output: EXPECTED-outcomes.json with per-seed
// results, totals, the measured commit and the audit's own run identity.
//
// Usage: node tests/corpus/measure-corpus.mjs [--audit <path to dist/cli.js>]
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const cli = process.argv.includes('--audit') ? process.argv[process.argv.indexOf('--audit') + 1] : join(repo, 'dist', 'cli.js');

const GRADE_RANK = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

// ---- The seed table (Appendix A). staticallyCheckable=false carries the brief's exclusion reason.
const S = (id, file, rule, opts = {}) => ({ id, kind: 'security', file, rule, ...opts });
const Q = (id, file, rule, opts = {}) => ({ id, kind: 'quality', file, rule, ...opts });
export const SEEDS = [
  // security (Appendix A "Files and seeds")
  S('S01', 'next.config.js', 'hardening.dangerous-next-config', { line: 3, note: 'productionBrowserSourceMaps' }),
  S('S02', 'next.config.js', 'hardening.dangerous-next-config', { line: 4, note: 'ignoreBuildErrors' }),
  S('S03', 'next.config.js', 'hardening.dangerous-next-config', { line: 5, note: 'ignoreDuringBuilds' }),
  S('S04', 'components/ChatBox.tsx', 'generic-api-key', { note: 'OpenAI key literal; classifier row' }),
  S('S05', 'components/ChatBox.tsx', 'hardening.client-ai-sdk'),
  S('S06', 'components/ChatBox.tsx', 'hardening.nonliteral-html-sink', { minSeverity: 'medium', note: 'at least medium' }),
  S('S07', 'lib/supabase.ts', 'jwt', { severity: 'critical', note: 'service-role literal, critical' }),
  S('S08', 'app/api/users/route.ts', 'hardening.taint-sql-injection', { line: 7, note: 'concat' }),
  S('S09', 'app/api/users/route.ts', 'hardening.taint-sql-injection', { line: 13, note: 'template' }),
  S('S10', 'app/api/proxy/route.ts', 'hardening.taint-ssrf-fetch'),
  S('S11', 'app/api/login/route.ts', 'hardening.weak-password-hash'),
  S('S12', 'app/api/login/route.ts', 'hardening.jwt-hardcoded-secret', { line: 10, note: 'sign' }),
  S('S13', 'app/api/login/route.ts', 'hardening.jwt-none-alg', { line: 10, note: 'sign' }),
  S('S14', 'app/api/login/route.ts', 'hardening.jwt-none-alg', { line: 11, note: 'verify' }),
  S('S15', 'app/api/login/route.ts', 'hardening.logging-secret-value', { note: 'console.log of the password' }),
  S('S16', 'app/api/login/route.ts', 'hardening.weak-random-token'),
  S('S17', 'app/api/login/route.ts', 'hardening.taint-open-redirect'),
  S('S18', 'app/api/login/route.ts', 'hardening.insecure-cookie'),
  S('S19', 'app/api/login/route.ts', 'hardening.cors-wildcard-credentials'),
  S('S20', 'app/api/webhook/route.ts', 'hardening.stripe-webhook-unverified', { severity: 'critical', note: 'critical BIZ-01; see S41 for the plan:pro disposition' }),
  S('S21', 'supabase/migrations/0001_init.sql', 'supabase.rls-missing'),
  S('S22', 'supabase/migrations/0001_init.sql', 'supabase.permissive-policy'),
  S('S23', 'supabase/migrations/0001_init.sql', 'supabase.grant-anon-write'),
  S('S24', 'supabase/migrations/0001_init.sql', 'supabase.security-definer-search-path'),
  S('S25', 'supabase/migrations/0001_init.sql', 'supabase.public-bucket'),
  S('S26', '.env', 'database-url-with-password', { severity: 'critical' }),
  S('S27', '.env', 'stripe-access-token', { severity: 'critical' }),
  S('S28', '.env', 'jwt', { severity: 'critical' }),
  S('S29', '.github/workflows/ci.yml', 'dangerous-triggers', { note: 'pull_request_target + head checkout + secrets (zizmor)' }),
  S('S30', '.github/workflows/ci.yml', 'template-injection', { note: 'zizmor' }),
  S('S31', '.github/workflows/ci.yml', 'unpinned-uses', { note: 'zizmor' }),
  S('S32', '.github/workflows/ci.yml', 'artipacked', { note: 'zizmor' }),
  S('S33', '.github/workflows/ci.yml', 'excessive-permissions', { note: 'zizmor, auditor persona' }),
  S('S34', 'utils/admin.ts', 'hardening.no-eval'),
  S('S35', 'utils/admin.ts', 'hardening.path-traversal-concat'),
  S('S36', 'utils/admin.ts', 'hardening.child-process-exec-interpolation'),
  S('S37', 'app/dashboard/page.tsx', 'hardening.taint-xss-innerhtml', { note: 'stored XSS from rows' }),
  S('S38', '.env', 'generic', { note: '.gitignore lacks .env — an untracked-secret exposure seed; reported by the current-files scan', rule: 'generic-api-key' }),
  // exclusions the brief marks non-static:
  S('S39', 'app/api/users/route.ts', null, { staticallyCheckable: false, note: 'no auth check — the brief marks it "listed as not run"' }),
  S('S40', 'app/api/webhook/route.ts', null, { staticallyCheckable: false, note: 'payments profile composition is behaviour, not a finding' }),
  // quality
  Q('Q01', 'package.json', 'duplicate-role', { note: 'moment + dayjs' }),
  Q('Q02', 'package.json', 'duplicate-role', { note: 'axios + node-fetch' }),
  Q('Q03', 'package.json', 'knip-unused-dependency', { note: 'unused left-pad', analyzer: 'knip' }),
  Q('Q04', 'utils/format.ts', 'jscpd-clone', { note: 'formatPrice/legacyFormatter clone', analyzer: 'jscpd' }),
  Q('Q05', 'utils/format.ts', 'knip-unused-file', { note: 'dead file with the legacyFormatter export', analyzer: 'knip' }),
  Q('Q06', 'utils/format.ts', 'tell.narration-comment', { note: 'narration family, recall >= 0.7 target (F-08)' }),
  Q('Q07', 'lib/money.ts', 'tell.narration-comment', { note: 'narration family' }),
  Q('Q08', 'lib/supabase.ts', 'tell.narration-comment', { note: 'narration family' }),
  Q('Q09', 'app/api/users/route.ts', 'tell.narration-comment', { note: 'narration family' }),
  Q('Q10', 'components/ChatBox.tsx', 'tell.narration-comment', { note: 'narration family' }),
  Q('Q11', 'components/ChatBox.tsx', 'tell.emoji-in-source'),
  Q('Q12', 'app/api/users/route.ts', 'any-type'),
  Q('Q13', 'app/api/login/route.ts', 'any-type', { note: 'x2, one row per rule/file pair' }),
  Q('Q14', 'utils/format.ts', 'any-type'),
  Q('Q15', 'app/dashboard/page.tsx', 'any-type', { note: 'x4' }),
  Q('Q16', 'app/dashboard/page.tsx', 'tell.floating-promise', { note: 'x2' }),
  Q('Q17', 'app/dashboard/page.tsx', 'ts-suppression'),
  Q('Q18', 'app/dashboard/page.tsx', 'hardening.quality-empty-catch'),
  Q('Q19', 'app/dashboard/page.tsx', 'lizard-cyclomatic-complexity', { note: 'computeScore at CCN 10', analyzer: 'lizard' }),
  Q('Q20', 'app/dashboard/page.tsx', 'tell.placeholder-comment', { line: 34, note: 'TODO' }),
  Q('Q21', 'app/dashboard/page.tsx', 'tell.placeholder-comment', { line: 40, note: 'In a real implementation' }),
  Q('Q22', 'app/dashboard/page.tsx', 'quality.mock-data', { note: 'mockUsers + john@example.com' }),
  Q('Q23', 'app/dashboard/page.tsx', 'tell.commented-out-code'),
  Q('Q24', 'app/dashboard/page.tsx', 'tell.debugger-statement'),
  Q('Q25', 'app/dashboard/page.tsx', 'hardening.quality-console-log-production'),
  Q('Q26', 'app/dashboard/page.tsx', 'quality.swallowed-supabase-error'),
  Q('Q27', 'app/dashboard/page.tsx', 'depcruise-no-ui-database-access', { note: 'data access in UI', analyzer: 'dependency-cruiser' }),
  Q('Q28', 'app/dashboard/page.tsx', 'tell.hardcoded-local-url'),
  Q('Q29', 'tests/app.test.ts', 'focused-test'),
  Q('Q30', 'tests/app.test.ts', 'skipped-test'),
  Q('Q31', 'tests/app.test.ts', 'tautological-assertion'),
  Q('Q32', 'tests/app.test.ts', 'assertion-free-test'),
  Q('Q33', 'README.md', 'readme-phantom-scripts'),
  Q('Q34', '.', 'no-changelog'),
  Q('Q35', 'package.json', 'no-licence'),
  Q('Q36', '.', 'no-lockfile', { note: 'Appendix A: the corpus ships without a lockfile (the lockfile variant is generated separately)' }),
  S('S41', 'app/api/webhook/route.ts', null, { staticallyCheckable: false, note: 'plan: pro upgrade from client-controlled client_reference_id — an authorization consequence of the unverified webhook (S20); recorded per the re-check rather than folded silently' }),
];

// (composition is synchronous below — see main())
import { writeFileSync } from 'node:fs';

function main() {
  const work = mkdtempSync(join(tmpdir(), 'sechard-corpus-'));
  const app = join(work, 'app');
  const out = join(work, 'out');
  cpSync(join(repo, 'tests', 'corpus', 'independent-nextjs'), app, { recursive: true });
  const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({ role: 'service_role', iss: 'supabase' })}.${'a'.repeat(43)}`;
  const substitute = (file, pairs) => {
    const p = join(app, file);
    let text = readFileSync(p, 'utf8');
    for (const [from, to] of pairs) text = text.split(from).join(to);
    writeFileSync(p, text);
  };
  // Clean-checkout safe: the fixture .env is git-ignored, so the runner writes it itself.
  const stripeLive = 'sk_live_' + '51Hq8xYz3kT' + '4mLpQ9wRz' + '7vNsA2bCx';
  writeFileSync(join(app, '.env'), `DATABASE_URL=postgres://app_owner:drill_pw_composed@db.example.invalid:5432/app\nSTRIPE_SECRET_KEY=${stripeLive}\nSUPABASE_SERVICE_ROLE_KEY=${jwt}\n`);
  substitute('lib/supabase.ts', [['__JWT_SERVICE_ROLE__', jwt]]);
  substitute('components/ChatBox.tsx', [['__OPENAI_KEY__', `sk-proj-${'A1b2C3d4E5f6G7h8I9j0K1l2'}`]]);
  execFileSync('git', ['init', '-q'], { cwd: app });
  execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: app });
  execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: app });
  execFileSync('git', ['add', '-A'], { cwd: app });
  execFileSync('git', ['commit', '-q', '-m', 'calibration corpus'], { cwd: app });

  execFileSync(process.execPath, [cli, 'audit', app, '--out', out, '--depth', 'standard'], { stdio: 'inherit' });
  const results = JSON.parse(readFileSync(join(out, 'results.json'), 'utf8'));
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
  const findings = results.flatMap((result) => (result.findings ?? []).map((f) => ({ ...f, check: result.check_id })));

  const outcomes = SEEDS.map((seed) => {
    if (!seed.staticallyCheckable === false && seed.rule === null) {
      return { ...seed, fired: false, status: 'excluded-nonstatic' };
    }
    if (seed.staticallyCheckable === false) {
      return { ...seed, fired: false, status: 'excluded-nonstatic' };
    }
    const lineOf = (f) => Number.parseInt((f.location ?? '').split(':').pop() ?? '', 10);
    const fileOf = (f) => (f.location ?? '').split(':')[0];
    const hit = findings.find((f) => f.rule_id === seed.rule
      && fileOf(f) === seed.file
      && (seed.line === undefined || lineOf(f) === seed.line)
      && (seed.severity === undefined || f.severity === seed.severity)
      && (seed.minSeverity === undefined || GRADE_RANK[f.severity ?? 'unknown'] >= GRADE_RANK[seed.minSeverity]));
    return {
      ...seed,
      fired: hit !== undefined,
      severity: hit?.severity,
      finding_location: hit?.location,
    };
  });

  const by = (kind, pred) => outcomes.filter((o) => o.kind === kind && pred(o));
  const staticSecurity = by('security', (o) => o.staticallyCheckable !== false);
  const staticQuality = by('quality', (o) => o.staticallyCheckable !== false);
  const report = {
    generated_at: new Date().toISOString(),
    measured_build: { commit, tool: 'hardening audit --depth standard from this checkout' },
    reference_baseline_note: 'b71a073d1425fc55c36a5f5d3863ad18b1971949 is recorded as the pre-R1 reference commit only; a MEASURED baseline of that build (per-seed outcomes from a pinned build of it) is still outstanding and is not claimed here.',
    tool: 'hardening audit --depth standard',
    audit_out_digest: createHash('sha256').update(readFileSync(join(out, 'report.json'))).digest('hex'),
    denominators: { security: staticSecurity.length, quality: staticQuality.length },
    brief_declared_denominators: { security: 31, quality: 30 },
    pre_r1_baseline_commit: 'b71a073d1425fc55c36a5f5d3863ad18b1971949',
    denominator_reconciliation: 'The brief declares 31 security / 30 quality statically checkable items. This runner enumerates the Appendix A itemization as it can be derived from the brief text and measures every enumerated seed. Where the enumeration exceeds the declared 31/30, the reconciliation (which items the brief counts as one) requires the auditor\'s itemization; every seed is measured either way, and the declared denominators are never used to hide a miss.',
    totals: {
      security_reported: staticSecurity.filter((o) => o.fired).length,
      quality_reported: staticQuality.filter((o) => o.fired).length,
    },
    outcomes,
    notes: [
      'Staged-tool seeds (analyzer: knip/jscpd/lizard/dependency-cruiser) stay inside the quality denominator with their actual measured status.',
      'A-16 detection shapes land as new seed IDs in a separate extension list when their rules land; they do not mutate this set.',
      'Non-static items carry the brief\'s exclusion reason and sit outside the denominators.',
    ],
  };
  writeFileSync(join(repo, 'tests', 'corpus', 'EXPECTED-outcomes.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`security ${report.totals.security_reported}/${report.denominators.security}; quality ${report.totals.quality_reported}/${report.denominators.quality}`);
  console.log(`outcomes written to tests/corpus/EXPECTED-outcomes.json (baseline ${commit.slice(0, 12)})`);
  rmSync(work, { recursive: true, force: true });
}

main();
