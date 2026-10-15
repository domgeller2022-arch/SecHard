import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import formatsPlugin from 'ajv-formats';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * Batch U acceptance, through the compiled CLI: `hardening audit` on three different sample apps
 * (the remediation plan's A-section acceptance), an Expo gap banner, depth semantics, the
 * never-writes contract as a tree digest, and the --url guard.
 *
 * This suite needs the fetched scanner tools (`pnpm run fetch:tools`), exactly like the other
 * scanner acceptance tests: audit mode is only proven by producing real results on real targets.
 * Audits are cached per (app, arguments) so every property is asserted from one real run rather
 * than re-scanning per assertion.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');
const AUDIT_FIXTURES = join(REPO, 'tests', 'fixtures', 'audit');
const SCANNER_FIXTURES = join(REPO, 'tests', 'fixtures', 'scanners');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-audit-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

interface RunResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

function cli(args: readonly string[], cwd: string): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 600_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

/** A content digest of a whole tree: names and bytes. The never-writes contract is checked with it. */
function treeDigest(root: string): string {
  const hash = createHash('sha256');
  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir).sort()) {
      const full = join(dir, entry);
      const stats = statSync(full);
      if (stats.isDirectory()) {
        hash.update(`d:${prefix}${entry}\n`);
        walk(full, `${prefix}${entry}/`);
      } else {
        hash.update(`f:${prefix}${entry}\n`);
        hash.update(readFileSync(full));
      }
    }
  };
  walk(root, '');
  return hash.digest('hex');
}

interface GitleaksSecretFinding {
  rule_id: string;
  severity?: string;
  category?: string;
  title?: string;
  detail?: string;
  secret_digest?: string;
  commit?: string;
  location?: string;
}

interface AuditOutput {
  readonly run: RunResult;
  readonly outDir: string;
  readonly report: string;
  readonly reportJson: Record<string, unknown>;
  readonly results: { check_id: string; outcome: string; diagnostic?: string; findings?: unknown[] }[];
}

const auditCache = new Map<string, AuditOutput>();

function auditApp(target: string, extra: readonly string[] = []): AuditOutput {
  const key = `${target}|${extra.join(' ')}`;
  const cached = auditCache.get(key);
  if (cached !== undefined) return cached;

  mkdirSync(join(scratch, 'out'), { recursive: true });
  const outDir = join(scratch, 'out', `run-${auditCache.size}`);
  const run = cli(['audit', target, '--out', outDir, ...extra], scratch);
  const report = existsSync(join(outDir, 'report.md')) ? readFileSync(join(outDir, 'report.md'), 'utf8') : '';
  const reportJson = existsSync(join(outDir, 'report.json'))
    ? (JSON.parse(readFileSync(join(outDir, 'report.json'), 'utf8')) as Record<string, unknown>)
    : {};
  const results = existsSync(join(outDir, 'results.json'))
    ? (JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'])
    : [];
  const output: AuditOutput = { run, outDir, report, reportJson, results };
  auditCache.set(key, output);
  return output;
}

const findingsFor = (
  results: AuditOutput['results'],
  recipe: string,
): { rule_id: string; severity?: string; category?: string; detail?: string }[] => {
  const result = results.find((entry) => entry.check_id.includes(recipe));
  expect(result, `no result for ${recipe}`).toBeDefined();
  return ((result?.findings ?? []) as { rule_id: string; severity?: string; category?: string; detail?: string }[]);
};

const appCache = new Map<string, string>();

/** Copies an audit fixture into scratch (once per name) and optionally gives it git history. */
function fixtureApp(name: string, withGit: boolean): string {
  const key = `${name}:${withGit}`;
  const cached = appCache.get(key);
  if (cached !== undefined) return cached;

  const root = join(scratch, 'apps', `${name}${withGit ? '' : '-nogit'}`);
  cpSync(join(AUDIT_FIXTURES, name), root, { recursive: true });

  if (name === 'vite-supabase') {
    // The vulnerable scanner fixtures, so the audit has real findings to find through the CLI.
    mkdirSync(join(root, '.github', 'workflows'), { recursive: true });
    cpSync(join(SCANNER_FIXTURES, 'secrets', 'vulnerable.ts'), join(root, 'src', 'leaky.ts'));
    cpSync(join(SCANNER_FIXTURES, 'sast', 'vulnerable.ts'), join(root, 'src', 'sast.ts'));
    cpSync(join(SCANNER_FIXTURES, 'workflows', 'vulnerable.yaml'), join(root, '.github', 'workflows', 'vulnerable.yaml'));
    cpSync(join(SCANNER_FIXTURES, 'dependencies', 'package-lock.json'), join(root, 'package-lock.json'));
  }
  if (name === 'expo') {
    // A lockfile with a known advisory, so the generic checks demonstrably run on an unsupported
    // stack rather than silently doing nothing.
    cpSync(join(SCANNER_FIXTURES, 'dependencies', 'package-lock.json'), join(root, 'package-lock.json'));
  }

  if (withGit) {
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: root });
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'audit fixture'], { cwd: root });
  }
  appCache.set(key, root);
  return root;
}

function validateSarif(sarif: unknown): true | string {
  const ajv = new Ajv2020({ allErrors: true });
  formatsPlugin.default(ajv);
  ajv.addMetaSchema(JSON.parse(readFileSync(join(REPO, 'node_modules', 'ajv', 'dist', 'refs', 'json-schema-draft-07.json'), 'utf8')) as object);
  const validate = ajv.compile(JSON.parse(readFileSync(join(REPO, 'schemas', 'sarif-2.1.0.schema.json'), 'utf8')) as object);
  return validate(sarif) ? true : JSON.stringify(validate.errors);
}

describe('hardening audit on three sample applications', () => {
  it('audits a Vite + Supabase app: real findings from every wired scanner, tree unchanged, valid SARIF', () => {
    const app = fixtureApp('vite-supabase', true);
    const before = treeDigest(app);

    const audit = auditApp(app, ['--depth', 'standard']);

    // Every wired scanner applies here, so no result may error.
    expect(audit.run.status, audit.run.stderr).toBe(0);
    expect(audit.results.filter((result) => result.outcome === 'error')).toEqual([]);

    const filesSecrets = findingsFor(audit.results, 'gitleaks/files');
    expect(filesSecrets.length).toBeGreaterThan(0);
    // One commit of history: every history and repository finding duplicates the current-files
    // scan, so the fold leaves one row per secret on the files scan — with the history and the
    // newest commit noted — rather than reporting the same secret three times.
    expect(findingsFor(audit.results, 'gitleaks/history').length).toBe(0);
    expect(findingsFor(audit.results, 'gitleaks/repository').length).toBe(0);
    expect(
      filesSecrets.some((finding) => (finding.detail ?? '').includes('also present in committed history')),
      JSON.stringify(filesSecrets),
    ).toBe(true);
    expect(
      filesSecrets.every((finding) => (finding.detail ?? '').includes("also present in the newest commit's change set")),
      JSON.stringify(filesSecrets),
    ).toBe(true);
    // F-02: classified, never `unknown`, with the category marker.
    expect(filesSecrets.every((finding) => finding.severity !== 'unknown' && finding.category === 'secret')).toBe(true);

    // A-03 (Batch R1): no secret material from the audited tree reaches the persisted artifacts,
    // and raw scanner output is not retained in ordinary audit mode.
    const artifacts = (['report.md', 'report.json', 'report.sarif', 'evidence.json'] as const)
      .map((name) => readFileSync(join(audit.outDir as string, name), 'utf8'))
    const blob = artifacts.join('\n');
    expect(blob).not.toContain('AKIAQ7Z2XW9PLM4NVK8T');
    expect(blob).not.toContain('ghp_Qz3vN8pR2mXwL7yK5tJ1aB4cD9eF6gH0iJ2k');
    expect(existsSync(join(audit.outDir as string, 'raw')), 'raw scanner output must not be retained in audit mode').toBe(false);
    expect(findingsFor(audit.results, 'opengrep/rules').length).toBeGreaterThan(0);
    expect(findingsFor(audit.results, 'zizmor/workflows').length).toBeGreaterThan(0);
    expect(findingsFor(audit.results, 'osv/lockfile').length).toBeGreaterThan(0);

    // Detection and composition are in the report, in the plan's required shape.
    expect(audit.report).toContain('Detected stack: `react-spa`');
    expect(audit.report).toContain('Composed profiles: `core`, `quality`, `react-spa`, `supabase`, `payments`');
    expect(audit.report).toContain('## Fix these first');
    expect(audit.report).toContain('## What we could not check');
    expect(audit.report).toContain('Ready-to-paste prompt');
    expect(audit.report).toContain('Effort:');
    expect(audit.report).toContain('Confidence:');
    expect(audit.reportJson['schema_version']).toBe('audit-report/v1');
    expect(audit.reportJson['detection']).toMatchObject({ stack: { kind: 'react-spa' } });

    // The audited tree is byte-identical: audit mode never writes to the audited project.
    expect(treeDigest(app)).toBe(before);
    expect(existsSync(join(app, '.hardening'))).toBe(false);
    // All four formats were produced outside the target.
    for (const file of ['report.md', 'report.html', 'report.json', 'report.sarif', 'evidence.json', 'plan.json', 'results.json']) {
      expect(existsSync(join(audit.outDir, file)), `${file} missing`).toBe(true);
    }

    // SARIF from the same run validates against the vendored schema; no snippets; no absolute
    // local paths in artifact URIs.
    const sarif = JSON.parse(readFileSync(join(audit.outDir, 'report.sarif'), 'utf8')) as object;
    expect(validateSarif(sarif)).toBe(true);
    expect(JSON.stringify(sarif)).not.toContain('snippet');
    const uris = ((sarif as { runs: { results: { locations?: { physicalLocation?: { artifactLocation?: { uri?: string } } }[] }[] }[] }).runs[0]?.results ?? [])
      .map((result) => result.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '');
    for (const uri of uris) {
      expect(uri.startsWith('/Users/') || uri.startsWith('/tmp/'), `absolute local path in SARIF: ${uri}`).toBe(false);
    }
  }, 600_000);

  it('audits a Python FastAPI app: dependency advisories found, static analysis honestly not required', () => {
    const app = fixtureApp('fastapi', false);
    const audit = auditApp(app, ['--depth', 'standard']);

    expect(audit.run.status, audit.run.stderr).toBe(0);
    expect(audit.report).toContain('Detected stack: `python-web`');
    expect(audit.report).toContain('Composed profiles: `core`, `quality`, `python-web`');
    // osv scans requirements.txt and finds the advisories pinned in the fixture.
    expect(findingsFor(audit.results, 'osv/lockfile').length).toBeGreaterThan(0);
    // The git-mode scans honestly report why they cannot run (no git worktree), never a pass.
    const gitleaks = audit.results.find((result) => result.check_id.includes('gitleaks/repository'));
    expect(gitleaks?.outcome).toBe('unsupported');
    expect(gitleaks?.diagnostic).toContain('git worktree');
    // The F-02 follow-up: a folder that is not a git repository still gets its secret scan —
    // the current-files scan reads the tree as it exists, and this fixture has no secrets.
    const filesScan = audit.results.find((result) => result.check_id.includes('gitleaks/files')) as
      | { outcome?: string; scope?: { observed?: number } }
      | undefined;
    expect(filesScan?.outcome).toBe('pass');
    expect(filesScan?.scope?.observed ?? 0).toBeGreaterThan(0);
    // The Python static-analysis gap is stated in the report, not implied away.
    expect(audit.report).toContain('static analysis does not support Python in this build');
  }, 600_000);

  it('audits an Expo app with a prominent unsupported-stack banner, while generic checks still run', () => {
    const app = fixtureApp('expo', false);
    const audit = auditApp(app, ['--depth', 'standard']);

    expect(audit.run.status, audit.run.stderr).toBe(0);
    expect(audit.report).toContain('UNSUPPORTED STACK');
    expect(audit.report).toContain("stack 'expo' is not supported");
    // The generic checks still produced real results: the advisory scan found the pinned lockfile.
    expect(findingsFor(audit.results, 'osv/lockfile').length).toBeGreaterThan(0);
    expect(audit.reportJson['detection']).toMatchObject({ stack: { kind: 'expo' } });
  }, 600_000);

  it("audits the repository's own reference application end to end", () => {
    const app = join(REPO, 'examples', 'nextjs-supabase');
    const audit = auditApp(app, ['--depth', 'standard']);
    // Tools are fetched, so no wired recipe may error on the reference stack.
    expect(audit.run.status, audit.run.stderr).toBe(0);
    expect(audit.report).toContain('Detected stack: `nextjs`');
    expect(audit.report).toContain('Composed profiles: `core`, `quality`, `nextjs`, `supabase`');
    // The reference application has no committed secrets; the git-mode scans prove it, not an
    // assumption. The current-files scan reads the tree as it exists on the auditing machine,
    // where a local, gitignored `.env.local` generated by `env:sync` holds the publishable key by
    // design — an informational low row is expected there and on any machine; privileged rows are
    // not. (The CI checkout has no such file at all, so the assertion holds in both worlds.)
    expect(audit.results.find((entry) => entry.check_id.includes('gitleaks/repository'))?.findings ?? []).toEqual([]);
    const referenceFilesFindings = (audit.results.find((entry) => entry.check_id.includes('gitleaks/files'))?.findings ?? []) as { severity?: string }[];
    expect(referenceFilesFindings.every((finding) => finding.severity === 'low')).toBe(true);
    // The secret scans must not carry the auditing host's layout through ids, resources, locations,
    // or diagnostics. (An osv result may record an out-of-root lockfile path when the target is a
    // subdirectory of a git repository — pre-existing behaviour, recorded for the next batch.)
    const gitleaksResults = JSON.stringify(audit.results.filter((result) => result.check_id.includes('gitleaks')));
    expect(gitleaksResults).not.toContain(REPO);
  }, 600_000);
});

describe('audit depth semantics', () => {
  it('quick mode skips the history scan, client bundle, and live HTTP with a stated reason', () => {
    const app = fixtureApp('vite-supabase', true);
    const quick = auditApp(app, ['--depth', 'quick']);
    expect(quick.run.status, quick.run.stderr).toBe(0);

    // (Live HTTP is also excluded at quick depth; for a local-environment audit the transport
    // controls are not even planned, so there is no result to inspect — the report note below
    // states the exclusion, and the --url test exercises the planned live path at production.)
    for (const recipe of ['gitleaks/history', 'build/client-assets']) {
      const result = quick.results.find((entry) => entry.check_id.includes(recipe));
      expect(result?.outcome, `${recipe} at quick depth`).toBe('unsupported');
      expect(result?.diagnostic, `${recipe} at quick depth`).toContain('quick');
    }
    // The current-files scan runs at every depth and finds the committed secret; the repository
    // scan's duplicate folds into it.
    expect(findingsFor(quick.results, 'gitleaks/files').length).toBeGreaterThan(0);
    expect(findingsFor(quick.results, 'gitleaks/repository')).toHaveLength(0);
    // The report states what quick mode does not run — and that the files scan still ran.
    expect(quick.report).toContain('quick mode does not run the git-history secret scan');
    expect(quick.report).toContain('the current-files secret scan still runs at every depth');
  }, 600_000);

  it('deep mode states honestly that it adds nothing beyond standard in this build', () => {
    const app = fixtureApp('vite-supabase', true);
    const deep = auditApp(app, ['--depth', 'deep']);
    expect(deep.run.status, deep.run.stderr).toBe(0);
    expect(deep.report).toContain('same set as standard in this build');
    // Everything standard runs still ran: the history scan produced its real result — it examined
    // the tracked-file inventory (never an empty scope), and its findings are covered, folded into
    // the current-files rows (single-commit fixture, F-02) or reported as their own.
    const history = deep.results.find((entry) => entry.check_id.includes('gitleaks/history')) as
      | { outcome?: string; scope?: { observed?: number } }
      | undefined;
    expect(history?.outcome).toBe('pass');
    expect(history?.scope?.observed ?? 0).toBeGreaterThan(0);
    expect(findingsFor(deep.results, 'gitleaks/files').length).toBeGreaterThan(0);
  }, 600_000);
});

describe('audit input guards', () => {
  it('refuses an output directory inside the audited project', () => {
    const app = fixtureApp('fastapi', false);
    const run = cli(['audit', app, '--out', join(app, 'audit-out')], scratch);
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('outside the audited project');
    expect(existsSync(join(app, 'audit-out'))).toBe(false);
  });

  it('refuses a private --url target without --allow-local, before any request is made', () => {
    const app = fixtureApp('fastapi', false);
    for (const url of ['http://127.0.0.1:9/', 'http://169.254.169.254/', 'http://192.168.0.1/']) {
      const run = cli(['audit', app, '--url', url], scratch);
      expect(run.status, url).toBe(2);
      expect(run.stderr, url).toContain('refused');
    }
  });

  it('runs the production live-check path against an --allow-local https target, and reports the unverified TLS honestly', async () => {
    // The catalogue scopes transport controls (WEB-02, DEPLOY-01) to staging/production, so the
    // live path an audit can exercise is an https target. A self-signed local server makes Node's
    // fetch fail certificate verification, which is a real, honest finding — exactly what the
    // recipe must report for an unverified certificate.
    //
    // The server runs as an independent child process: the CLI helper blocks this process's event
    // loop synchronously, and a server in this process could never complete a TLS handshake
    // during the audit. That exact shape was the first version of this test, and it produced a
    // 10-second timeout misread as an unreachable route.
    const app = fixtureApp('vite-supabase', true);

    const certDir = join(scratch, 'cert');
    mkdirSync(certDir, { recursive: true });
    const keyFile = join(certDir, 'key.pem');
    const certFile = join(certDir, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyFile, '-out', certFile, '-days', '2', '-nodes', '-subj', '/CN=127.0.0.1'], {
      cwd: scratch,
      stdio: 'ignore',
      timeout: 30_000,
    });

    const serverScript = `
      import { createServer } from 'node:https';
      import { readFileSync } from 'node:fs';
      const server = createServer(
        { key: readFileSync(${JSON.stringify(keyFile)}), cert: readFileSync(${JSON.stringify(certFile)}) },
        (_request, response) => { response.writeHead(200, { 'content-type': 'text/plain' }); response.end('fixture root'); },
      );
      server.listen(0, '127.0.0.1', () => process.stdout.write(String(server.address().port)));
      setInterval(() => {}, 60000);
    `;
    const server = spawn(process.execPath, ['--input-type=module', '-e', serverScript], { stdio: ['ignore', 'pipe', 'inherit'] });
    const port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('the fixture TLS server never announced its port')), 15_000);
      server.stdout.on('data', (chunk: Buffer) => {
        clearTimeout(timer);
        resolve(Number.parseInt(chunk.toString('utf8'), 10));
      });
    });

    try {
      const audit = auditApp(app, ['--url', `https://127.0.0.1:${port}`, '--allow-local']);
      expect(audit.run.status, audit.run.stderr).toBe(0);

      // The live check ran at production environment and produced its honest finding.
      const live = audit.results.find((entry) => entry.check_id.includes('web/http-requirements'));
      expect(live?.outcome).toBe('pass');
      const liveFindings = (live?.findings ?? []) as { rule_id: string; severity: string; detail?: string }[];
      expect(liveFindings.map((finding) => finding.rule_id), JSON.stringify(liveFindings)).toContain('tls-invalid');
      expect(liveFindings[0]?.severity).toBe('critical');

      expect(audit.report).toContain('Live target: `https://127.0.0.1:');
      expect(audit.report).toContain('approved by the operator');
      // The critical TLS finding leads "fix these first".
      expect(audit.report).toMatch(/\| 1 \| critical \|/);
    } finally {
      server.kill();
    }
  }, 300_000);
});

describe('F-01/F-15: absolute audit targets still scope the console.log rule, and no report leaks the machine path', () => {
  it('reports an app/ console.log from an absolute target, holds back scripts/, and relativizes every location', () => {
    // The unique directory name is part of the acceptance: if the audit root leaks into any
    // report format, this string is what the assertion finds.
    const unique = `sechard-f15-${randomUUID().slice(0, 8)}`;
    const root = join(scratch, 'apps', unique);
    mkdirSync(join(root, 'app'), { recursive: true });
    mkdirSync(join(root, 'scripts'), { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: unique, dependencies: { next: '14.0.0' } }, null, 2));
    writeFileSync(join(root, 'app', 'x.ts'), 'export const log = (): void => { console.log("app"); };\n');
    writeFileSync(join(root, 'scripts', 'y.ts'), 'console.log("scripts");\n');

    const outDir = join(scratch, 'out', `run-${unique}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'quick'], scratch);
    expect(run.status, run.stderr).toBe(0);

    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];
    const quality = results.find((entry) => entry.check_id.includes('quality/error-handling'));
    expect(quality, 'no quality/error-handling result').toBeDefined();

    // F-01: the app/ finding is reported even though the target was passed as an absolute path.
    const locations = ((quality?.findings ?? []) as { rule_id: string; location?: string }[])
      .filter((finding) => finding.rule_id.includes('quality-console-log-production'))
      .map((finding) => finding.location);
    expect(locations, JSON.stringify(quality?.findings)).toEqual(['app/x.ts:1']);
    // The scripts/ console.log is still held back by the reviewed scoping, with the count stated.
    expect(locations.some((location) => (location ?? '').startsWith('scripts/'))).toBe(false);
    expect(quality?.diagnostic ?? '').toContain('held back');

    // F-15: no report format contains the audit root's absolute path.
    for (const name of ['report.md', 'report.html', 'report.json', 'report.sarif', 'results.json']) {
      const text = readFileSync(join(outDir, name), 'utf8');
      expect(text, `${name} leaks the audit root`).not.toContain(root);
    }
  }, 600_000);
});

// Synthetic, non-functional credentials composed at runtime (the repository's technique),
// shared by the F-02 suite and the follow-up suite: a structurally valid service-role JWT and a
// Stripe live-format key. None of these is issued by any provider.
const f02B64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const f02Jwt = (role: string): string => `${f02B64({ alg: 'HS256', typ: 'JWT' })}.${f02B64({ role, iss: 'supabase' })}.${'a'.repeat(43)}`;
const serviceRoleJwt = f02Jwt('service_role');
const stripeLive = `sk_live_${'51Hq8xYz3kT' + '4mLpQ9wRz' + '7vNsA2bC'}`;
const f02Env = (): string =>
  [
    `SUPABASE_SERVICE_ROLE_KEY=${serviceRoleJwt}`,
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${f02Jwt('anon')}`,
    `STRIPE_SECRET_KEY=${stripeLive}`,
    '',
  ].join('\n');

/** The F-02 test app: package.json plus an .env holding the three synthetic keys, one commit. */
function makeApp(name: string): string {
  const root = join(scratch, 'apps', name);
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { next: '14.0.0' } }, null, 2));
  writeFileSync(join(root, '.env'), f02Env());
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
  execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: root });
  execFileSync('git', ['add', '-A'], { cwd: root });
  execFileSync('git', ['commit', '-q', '-m', 'add configuration'], { cwd: root });
  return root;
}

describe('F-02: leaked secrets are classified, de-duplicated across the three secret scans, and readable', () => {
  interface SecretFinding {
    rule_id: string;
    severity?: string;
    category?: string;
    title?: string;
    detail?: string;
    secret_digest?: string;
    commit?: string;
    location?: string;
  }

  function auditFindings(root: string): { files: SecretFinding[]; repository: SecretFinding[]; history: SecretFinding[] } {
    const outDir = join(scratch, 'out', `run-f02-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'standard'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];
    return {
      files: findingsFor(results, 'gitleaks/files') as SecretFinding[],
      repository: findingsFor(results, 'gitleaks/repository') as SecretFinding[],
      history: findingsFor(results, 'gitleaks/history') as SecretFinding[],
    };
  }

  it('classifies the service-role key and the Stripe live key critical, exactly one row each, on the current-files scan', () => {
    // The brief's scenario: the secrets were introduced in the newest commit, so all three scans
    // report them, and the duplicates must be folded into one row per secret on the current-files
    // scan — the scan that reads the tree as it exists — with the other scans' occurrences noted.
    const { files, repository, history } = auditFindings(makeApp(`sechard-f02-fresh-${randomUUID().slice(0, 8)}`));

    const serviceRole = files.find((finding) => (finding.title ?? '').includes('service-role'));
    expect(serviceRole, JSON.stringify(files)).toBeDefined();
    expect(serviceRole?.severity).toBe('critical');
    expect(serviceRole?.category).toBe('secret');
    expect(serviceRole?.secret_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(serviceRole?.detail ?? '').toContain('also present in committed history');
    expect(serviceRole?.detail ?? '').toContain("also present in the newest commit's change set");
    // The digest is recorded; the value itself appears nowhere on the finding.
    expect(JSON.stringify(files)).not.toContain(serviceRoleJwt);
    expect(JSON.stringify(files)).not.toContain(stripeLive);

    // Exactly one row for the service-role key and one for the Stripe key: the repository and
    // history copies are folded, not repeated.
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(1);
    expect(files.filter((finding) => finding.rule_id === 'stripe-access-token')).toHaveLength(1);
    expect(files.find((finding) => finding.rule_id === 'stripe-access-token')?.severity).toBe('critical');
    expect(repository, 'repository duplicates must be folded into the files rows').toHaveLength(0);
    expect(history, 'history duplicates must be folded').toHaveLength(0);

    // The anon key is informational, not a leak: low, same category, still visible.
    const anon = files.find((finding) => (finding.title ?? '').includes('anon/publishable'));
    expect(anon?.severity).toBe('low');

    // Totality: no gitleaks finding is left unknown or uncategorized.
    for (const finding of [...files, ...repository, ...history]) {
      expect(finding.severity, JSON.stringify(finding)).not.toBe('unknown');
      expect(finding.category).toBe('secret');
    }
  }, 600_000);

  it('finds and classifies a secret that only exists in history by reading its own commit', () => {
    // A second commit removes the Stripe key from the worktree. It must still be reported —
    // classified critical by reading the line from the commit that introduced it, not by
    // guessing from the rule id. The current-files scan cannot see it (it reads the tree as it
    // exists), which is exactly why the history scan is kept for standard depth and above.
    const root = makeApp(`sechard-f02-removed-${randomUUID().slice(0, 8)}`);
    writeFileSync(join(root, '.env'), f02Env().split('\n').filter((line: string) => !line.startsWith('STRIPE_SECRET_KEY')).join('\n'));
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'remove stripe key'], { cwd: root });

    const { files, repository, history } = auditFindings(root);

    const stripe = history.find((finding) => finding.rule_id === 'stripe-access-token');
    expect(stripe, JSON.stringify(history)).toBeDefined();
    expect(stripe?.severity).toBe('critical');
    expect(stripe?.category).toBe('secret');
    expect(stripe?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect((stripe?.detail ?? '') + (stripe?.title ?? '')).not.toContain(stripeLive);
    // The service-role key survived to HEAD and is still on disk: the current-files scan reports
    // it and the history scan's duplicate folds in — still critical, one row.
    const serviceRole = files.find((finding) => (finding.title ?? '').includes('service-role'));
    expect(serviceRole?.severity).toBe('critical');
    expect(serviceRole?.detail ?? '').toContain('also present in committed history');
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(1);
    expect(repository, 'the newest commit only removes the Stripe key, so nothing new is its change set').toHaveLength(0);
    expect(history.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(0);
    for (const finding of [...files, ...repository, ...history]) {
      expect(finding.severity, JSON.stringify(finding)).not.toBe('unknown');
      expect(finding.category).toBe('secret');
    }
  }, 600_000);
});

describe('secret coverage over time and in the working tree (owner query, superseded by the F-02 follow-up, 13 October 2026)', () => {
  it('finds a secret committed several commits ago and an uncommitted untracked secret at every depth, with the coverage stated', () => {
    // Synthetic, non-functional credentials composed at runtime.
    const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const jwt = (role: string, signature: string): string =>
      `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.${signature.repeat(43)}`;
    const oldSecret = jwt('service_role', 'a');
    const untrackedSecret = jwt('service_role', 'b');

    const unique = `sechard-q1-${randomUUID().slice(0, 8)}`;
    const root = join(scratch, 'apps', unique);
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: unique, dependencies: { next: '14.0.0' } }, null, 2));
    writeFileSync(join(root, '.env'), `OLD_SERVICE_ROLE=${oldSecret}\n`);

    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: root });
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'c1: add configuration'], { cwd: root });
    // Two later commits that touch neither the secret file nor anything secret.
    writeFileSync(join(root, 'notes-one.txt'), 'unrelated\n');
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'c2: unrelated'], { cwd: root });
    writeFileSync(join(root, 'notes-two.txt'), 'unrelated too\n');
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'c3: unrelated'], { cwd: root });

    // An uncommitted, untracked file holding a second secret. The owner's auditor rejected the
    // old contract that left it unreported: a security audit scans the files as they currently
    // exist, at every depth.
    const untrackedLine = `const K = "${untrackedSecret}";`;
    writeFileSync(join(root, 'scratch-untracked.js'), `${untrackedLine}\n`);
    const untrackedDigest = createHash('sha256').update(untrackedLine).digest('hex');

    const standard = auditApp(root, ['--depth', 'standard']);
    expect(standard.run.status, standard.run.stderr).toBe(0);

    // Found, one row each: the old committed secret (history folded in, critical — it is in the
    // repository) and the untracked secret (never committed, so no history note — graded high
    // per the owner's exposure rule: the file is untracked and not gitignored, so a plain
    // `git add -A` will commit it).
    const filesSecrets = findingsFor(standard.results, 'gitleaks/files') as GitleaksSecretFinding[];
    expect(filesSecrets, JSON.stringify(filesSecrets)).toHaveLength(2);
    expect(filesSecrets.every((finding) => (finding.title ?? '').includes('service-role'))).toBe(true);
    const committedRow = filesSecrets.find((finding) => finding.secret_digest !== untrackedDigest);
    expect(committedRow?.severity).toBe('critical');
    expect(committedRow?.detail ?? '').toContain('also present in committed history');
    const untrackedRow = filesSecrets.find((finding) => finding.secret_digest === untrackedDigest);
    expect(untrackedRow, JSON.stringify(filesSecrets)).toBeDefined();
    expect((untrackedRow?.location ?? '').includes('scratch-untracked')).toBe(true);
    expect(untrackedRow?.severity).toBe('high');
    expect(untrackedRow?.detail ?? '').toContain('a plain git add will commit this file');
    expect(untrackedRow?.detail ?? '').not.toContain('also present in committed history');
    // The duplicates folded: history and the newest commit's change set hold neither secret.
    expect(findingsFor(standard.results, 'gitleaks/history')).toHaveLength(0);
    expect(findingsFor(standard.results, 'gitleaks/repository')).toHaveLength(0);

    // Stated: the working-tree coverage, because the tree has uncommitted changes.
    expect(standard.report).toContain('WORKING TREE:');
    expect(standard.report).toContain('The current-files secret scan covers uncommitted and untracked files');

    // Quick depth: the history scan is excluded and the report states it, but both secrets are
    // still reported — the current-files scan runs at every depth, with the same grading.
    const quick = auditApp(root, ['--depth', 'quick']);
    expect(quick.run.status, quick.run.stderr).toBe(0);
    const quickFiles = findingsFor(quick.results, 'gitleaks/files') as GitleaksSecretFinding[];
    expect(quickFiles).toHaveLength(2);
    expect(quickFiles.find((finding) => finding.secret_digest === untrackedDigest)?.severity).toBe('high');
    expect(quickFiles.find((finding) => finding.secret_digest !== untrackedDigest)?.severity).toBe('critical');
    expect(quick.report).toContain('quick mode does not run the git-history secret scan');
    expect(quick.report).toContain('the current-files secret scan still runs at every depth');
    expect(quick.report).toContain('WORKING TREE:');

    // Deep runs the same set as standard, so the same two rows — at every depth, as the
    // auditor's acceptance requires.
    const deep = auditApp(root, ['--depth', 'deep']);
    expect(deep.run.status, deep.run.stderr).toBe(0);
    expect((findingsFor(deep.results, 'gitleaks/files') as GitleaksSecretFinding[])).toHaveLength(2);
  }, 600_000);
});

describe('F-02 follow-ups (owner\'s auditor, 13 October 2026): current-files scanning at every depth and on non-git targets', () => {
  it('keeps the two critical secrets as the top findings after .git is removed from the app', () => {
    // The auditor's first test: apps downloaded from Lovable or Bolt have no .git folder, and the
    // old scans reported zero critical findings for exactly such a folder. The same app with .git
    // deleted must still surface the service-role key and the Stripe live key, critical, one row
    // each, at the top of "Fix these first".
    const root = makeApp(`sechard-followup-nogit-${randomUUID().slice(0, 8)}`);
    rmSync(join(root, '.git'), { recursive: true, force: true });

    const outDir = join(scratch, 'out', `run-followup-nogit-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'standard'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];

    // The git-mode scans state why they cannot run; the current-files scan carries the findings.
    const repository = results.find((result) => result.check_id.includes('gitleaks/repository'));
    expect(repository?.outcome).toBe('unsupported');
    const history = results.find((result) => result.check_id.includes('gitleaks/history'));
    expect(history?.outcome).toBe('unsupported');
    const files = findingsFor(results, 'gitleaks/files') as GitleaksSecretFinding[];
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(1);
    expect(files.filter((finding) => finding.rule_id === 'stripe-access-token')).toHaveLength(1);
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))[0]?.severity).toBe('critical');
    expect(files.find((finding) => finding.rule_id === 'stripe-access-token')?.severity).toBe('critical');
    // Totality still holds for every row the scan produced (the anon key is low, not a leak).
    expect(files.every((finding) => finding.severity !== 'unknown' && finding.category === 'secret')).toBe(true);

    // The report leads with the two critical rows.
    const reportJson = JSON.parse(readFileSync(join(outDir, 'report.json'), 'utf8')) as {
      fix_first: { title?: string; severity?: string }[];
    };
    const topTwo = reportJson['fix_first'].slice(0, 2);
    expect(topTwo).toHaveLength(2);
    expect(topTwo.every((finding) => finding.severity === 'critical')).toBe(true);
    expect(topTwo.some((finding) => (finding.title ?? '').includes('service-role'))).toBe(true);
    expect(topTwo.some((finding) => (finding.title ?? '').includes('Stripe live key'))).toBe(true);
  }, 600_000);

  it('keeps the two critical secrets findable at quick depth after two commits hide them from the head scan', () => {
    // The auditor's second test: two harmless commits after the ones containing the keys, audited
    // at quick depth. The head scan never sees the older commits and history is out of scope at
    // quick, so the current-files scan is what must still report both keys.
    const root = makeApp(`sechard-followup-quick-${randomUUID().slice(0, 8)}`);
    for (const name of ['later-one.txt', 'later-two.txt']) {
      writeFileSync(join(root, name), 'unrelated\n');
      execFileSync('git', ['add', '-A'], { cwd: root });
      execFileSync('git', ['commit', '-q', '-m', `unrelated ${name}`], { cwd: root });
    }

    const outDir = join(scratch, 'out', `run-followup-quick-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'quick'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];

    // The head scan is blind to the older commits: its change set is the last unrelated commit.
    expect(findingsFor(results, 'gitleaks/repository')).toHaveLength(0);
    const files = findingsFor(results, 'gitleaks/files') as GitleaksSecretFinding[];
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(1);
    expect(files.filter((finding) => finding.rule_id === 'stripe-access-token')).toHaveLength(1);
    expect(files.filter((finding) => (finding.title ?? '').includes('service-role'))[0]?.severity).toBe('critical');
    expect(files.find((finding) => finding.rule_id === 'stripe-access-token')?.severity).toBe('critical');
    expect(files.every((finding) => finding.severity !== 'unknown' && finding.category === 'secret')).toBe(true);

    const reportJson = JSON.parse(readFileSync(join(outDir, 'report.json'), 'utf8')) as {
      fix_first: { title?: string; severity?: string }[];
    };
    const topTwo = reportJson['fix_first'].slice(0, 2);
    expect(topTwo.every((finding) => finding.severity === 'critical')).toBe(true);
    expect(topTwo.some((finding) => (finding.title ?? '').includes('service-role'))).toBe(true);
    expect(topTwo.some((finding) => (finding.title ?? '').includes('Stripe live key'))).toBe(true);
  }, 600_000);

  it('reports a database URL with an embedded password as a critical current-file finding', () => {
    // The "smaller item" the auditor listed: the database password in .env was still missed. The
    // new gitleaks rule catches the connection string, and the F-02 classifier grades it critical.
    const dbUrl = `postgres://app_owner:${'p' + 'w_' + '9f2k7x4q'}@db.fixture.example.invalid:5432/app`;
    const name = `sechard-followup-dburl-${randomUUID().slice(0, 8)}`;
    const root = join(scratch, 'apps', name);
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { next: '14.0.0' } }, null, 2));
    writeFileSync(join(root, '.env'), `DATABASE_URL=${dbUrl}\n`);

    const outDir = join(scratch, 'out', `run-followup-dburl-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'quick'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];

    const files = findingsFor(results, 'gitleaks/files') as GitleaksSecretFinding[];
    const dbUrlFinding = files.find((finding) => finding.rule_id === 'database-url-with-password');
    expect(dbUrlFinding, JSON.stringify(files)).toBeDefined();
    expect(dbUrlFinding?.severity).toBe('critical');
    expect(dbUrlFinding?.category).toBe('secret');
    expect(dbUrlFinding?.title ?? '').toContain('Database URL with an embedded password');
    // The value itself appears nowhere on the finding.
    expect(JSON.stringify(files)).not.toContain(dbUrl);
  }, 600_000);

  it('grades the same secret by where its file sits: tracked critical, gitignored medium, untracked high', () => {
    // The owner's exposure tiers (13 October 2026), all three cases in one app: the service-role
    // key committed in the tracked .env stays critical (it is in the repository); the same shape
    // in the gitignored .env.local is medium (not exposed through the repository, a local-file
    // risk); and the same shape in an untracked file that is NOT gitignored is high, because the
    // next plain `git add -A` will commit it.
    const localJwt = (signature: string): string =>
      `${f02B64({ alg: 'HS256', typ: 'JWT' })}.${f02B64({ role: 'service_role', iss: 'supabase' })}.${signature.repeat(43)}`;
    const root = makeApp(`sechard-followup-exposure-${randomUUID().slice(0, 8)}`);
    writeFileSync(join(root, '.env.local'), `LOCAL_SERVICE_ROLE=${localJwt('b')}\n`);
    writeFileSync(join(root, '.gitignore'), '.env.local\n');
    writeFileSync(join(root, 'scratch-notes.js'), `const K = "${localJwt('c')}";\n`);
    execFileSync('git', ['add', '.gitignore'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'ignore local env'], { cwd: root });

    const outDir = join(scratch, 'out', `run-followup-exposure-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'standard'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];

    const files = findingsFor(results, 'gitleaks/files') as GitleaksSecretFinding[];
    const trackedRow = files.find((finding) => (finding.location ?? '').startsWith('.env:'));
    const ignoredRow = files.find((finding) => (finding.location ?? '').startsWith('.env.local:'));
    const untrackedRow = files.find((finding) => (finding.location ?? '').startsWith('scratch-notes.js:'));
    expect(trackedRow, JSON.stringify(files)).toBeDefined();
    expect(ignoredRow, JSON.stringify(files)).toBeDefined();
    expect(untrackedRow, JSON.stringify(files)).toBeDefined();
    // Tracked and committed: critical, no grading note.
    expect(trackedRow?.severity).toBe('critical');
    expect(trackedRow?.detail ?? '').not.toContain('git add');
    expect(trackedRow?.detail ?? '').not.toContain('local file');
    // Gitignored and untracked: medium, with the local-file explanation and a non-exposure title.
    expect(ignoredRow?.severity).toBe('medium');
    expect(ignoredRow?.detail ?? '').toContain('local file, keep it out of git and client code');
    expect(ignoredRow?.title ?? '').toContain('in a local file (not committed to git)');
    expect(ignoredRow?.title ?? '').not.toContain(' exposed');
    // Untracked and not gitignored: high — the next git add commits it.
    expect(untrackedRow?.severity).toBe('high');
    expect(untrackedRow?.detail ?? '').toContain('a plain git add will commit this file');
    expect(untrackedRow?.title ?? '').toContain('in an untracked file (git add will commit it)');
    for (const finding of files) {
      expect(finding.severity, JSON.stringify(finding)).not.toBe('unknown');
      expect(finding.category).toBe('secret');
    }
  }, 600_000);

  it('keeps the database-URL rule identical in the git-mode and dir-mode configs', () => {
    // The rule is written twice because the dir-mode exclusions must not weaken the git-mode
    // scan. This pins the two copies so they cannot drift apart.
    const ruleText = (file: string): string => {
      const text = readFileSync(join(REPO, 'ci', 'configs', file), 'utf8');
      const match = /\[\[rules\]\][\s\S]*?id = "database-url-with-password"[\s\S]*?(?=\n\[\[|\n*$)/.exec(text);
      return match?.[0] ?? '';
    };
    expect(ruleText('gitleaks.toml')).not.toBe('');
    expect(ruleText('gitleaks-dir.toml')).toBe(ruleText('gitleaks.toml'));
  });
});

describe('P1.1: scanner-owned Git cannot execute repository-configured helpers (comprehensive plan; auditor R1-01)', () => {
  it('gitleaks git-mode scans run no textconv helper while a history-only secret stays detectable', () => {
    // Counterexample-first: the fixture must execute the helper through an UNHARDENED patch log
    // (the auditor's exact vector: .gitattributes textconv + .git/config driver), or the
    // regression proves nothing.
    const name = `sechard-p11-gitchild-${randomUUID().slice(0, 8)}`;
    const root = join(scratch, 'apps', name);
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { next: '14.0.0' } }, null, 2));
    const marker = join(root, 'helper-ran.txt');
    const helper = join(root, 'helper.sh');
    writeFileSync(helper, `#!/bin/sh\necho ran >> "${marker}"\nexit 0\n`);
    chmodSync(helper, 0o755);
    writeFileSync(join(root, '.gitattributes'), '*.key diff=obfuscate\n');
    const secretJwt = `${f02B64({ alg: 'HS256', typ: 'JWT' })}.${f02B64({ role: 'service_role', iss: 'supabase' })}.${'a'.repeat(43)}`;
    writeFileSync(join(root, 'leak.key'), `K=${secretJwt}\n`);
    const git = (...args: string[]): void => { execFileSync('git', args, { cwd: root }); };
    git('init', '-q');
    git('config', 'user.email', 'fixture@example.invalid');
    git('config', 'user.name', 'fixture');
    git('config', 'diff.obfuscate.textconv', helper);
    git('add', '-A');
    git('commit', '-q', '-m', 'add key');

    execFileSync('git', ['log', '-p', '-U0', 'HEAD'], { cwd: root, stdio: 'ignore' });
    expect(existsSync(marker), 'fixture invalid: the textconv helper did not run unhardened').toBe(true);
    rmSync(marker);

    // B-06 (p0_d_04): the secret must be HISTORY-ONLY. The second commit removes leak.key, so the
    // current-files scan cannot see it and only the hardened history scan can prove detection —
    // the earlier version left the file in the worktree, which let the files scan satisfy the
    // detection claim without the history scan finding anything.
    rmSync(join(root, 'leak.key'));
    git('add', '-A');
    git('commit', '-q', '-m', 'remove key');

    const outDir = join(scratch, 'out', `run-p11-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'standard'], scratch);
    expect(run.status, run.stderr).toBe(0);
    expect(existsSync(marker), 'the textconv helper executed through a gitleaks git-mode child').toBe(false);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];
    const files = findingsFor(results, 'gitleaks/files') as GitleaksSecretFinding[];
    const history = findingsFor(results, 'gitleaks/history') as GitleaksSecretFinding[];
    // Fixture guard: leak.key exists only in history, so the current-files scan must hold no row
    // for it — if it does, the removal commit failed and this test would prove nothing.
    expect(files.some((finding) => (finding.location ?? '').startsWith('leak.key')), 'fixture invalid: leak.key is still in the worktree, so the files scan could satisfy the claim').toBe(false);
    // B-06 (p0_d_04): the history scan alone must find the history-only secret through the
    // hardened, helper-free scan.
    expect(history.some((finding) => (finding.location ?? '').startsWith('leak.key')), 'the history-only secret must be found by the hardened history scan').toBe(true);
    expect(JSON.stringify([...files, ...history])).not.toContain(secretJwt);
  }, 600_000);
});
