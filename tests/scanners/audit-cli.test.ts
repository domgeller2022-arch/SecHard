import { execFileSync, spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
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

    const repositorySecrets = findingsFor(audit.results, 'gitleaks/repository');
    expect(repositorySecrets.length).toBeGreaterThan(0);
    // One commit of history: every history finding duplicates the repository scan, so F-02 folds
    // it into the repository finding — one row per secret, with the history noted — rather than
    // reporting the same secret twice.
    expect(findingsFor(audit.results, 'gitleaks/history').length).toBe(0);
    expect(
      repositorySecrets.some((finding) => (finding.detail ?? '').includes('also present in committed history')),
      JSON.stringify(repositorySecrets),
    ).toBe(true);
    // F-02: classified, never `unknown`, with the category marker.
    expect(repositorySecrets.every((finding) => finding.severity !== 'unknown' && finding.category === 'secret')).toBe(true);
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
    // gitleaks honestly reports why it cannot run (no git worktree), never a pass.
    const gitleaks = audit.results.find((result) => result.check_id.includes('gitleaks/repository'));
    expect(gitleaks?.outcome).toBe('unsupported');
    expect(gitleaks?.diagnostic).toContain('git worktree');
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
    // The reference application has no committed secrets; the scan proves it, not an assumption.
    expect(audit.results.find((entry) => entry.check_id.includes('gitleaks/repository'))?.findings ?? []).toEqual([]);
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
    // Repository scan still runs at quick depth and still finds the committed secret.
    expect(findingsFor(quick.results, 'gitleaks/repository').length).toBeGreaterThan(0);
    // The report states what quick mode does not run.
    expect(quick.report).toContain('quick mode does not run the git-history secret scan');
  }, 600_000);

  it('deep mode states honestly that it adds nothing beyond standard in this build', () => {
    const app = fixtureApp('vite-supabase', true);
    const deep = auditApp(app, ['--depth', 'deep']);
    expect(deep.run.status, deep.run.stderr).toBe(0);
    expect(deep.report).toContain('same set as standard in this build');
    // Everything standard runs still ran: the history scan produced its real result — it examined
    // the tracked-file inventory (never an empty scope), and its findings are covered, folded into
    // the repository rows (single-commit fixture, F-02) or reported as their own.
    const history = deep.results.find((entry) => entry.check_id.includes('gitleaks/history')) as
      | { outcome?: string; scope?: { observed?: number } }
      | undefined;
    expect(history?.outcome).toBe('pass');
    expect(history?.scope?.observed ?? 0).toBeGreaterThan(0);
    expect(findingsFor(deep.results, 'gitleaks/repository').length).toBeGreaterThan(0);
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

describe('F-02: leaked secrets are classified, de-duplicated across repository and history, and readable', () => {
  // Synthetic, non-functional credentials composed at runtime (the repository's technique):
  // a structurally valid service-role JWT and a Stripe live-format key. None of these is issued
  // by any provider.
  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  const jwt = (role: string): string => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.${'a'.repeat(43)}`;
  const serviceRoleJwt = jwt('service_role');
  const anonJwt = jwt('anon');
  const stripeLive = `sk_live_${'51Hq8xYz3kT' + '4mLpQ9wRz' + '7vNsA2bC'}`;
  const envWithStripe = [
    `SUPABASE_SERVICE_ROLE_KEY=${serviceRoleJwt}`,
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${anonJwt}`,
    `STRIPE_SECRET_KEY=${stripeLive}`,
    '',
  ].join('\n');

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

  function makeApp(name: string): string {
    const root = join(scratch, 'apps', name);
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name, dependencies: { next: '14.0.0' } }, null, 2));
    writeFileSync(join(root, '.env'), envWithStripe);
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: root });
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'add configuration'], { cwd: root });
    return root;
  }

  function auditFindings(root: string): { repository: SecretFinding[]; history: SecretFinding[] } {
    const outDir = join(scratch, 'out', `run-f02-${randomUUID().slice(0, 8)}`);
    const run = cli(['audit', root, '--out', outDir, '--depth', 'standard'], scratch);
    expect(run.status, run.stderr).toBe(0);
    const results = JSON.parse(readFileSync(join(outDir, 'results.json'), 'utf8')) as AuditOutput['results'];
    return {
      repository: findingsFor(results, 'gitleaks/repository') as SecretFinding[],
      history: findingsFor(results, 'gitleaks/history') as SecretFinding[],
    };
  }

  it('classifies the service-role key and the Stripe live key critical, exactly one row each, with history folded in', () => {
    // The brief's scenario: the secrets were introduced in the newest commit, so both the
    // repository scan (the newest commit's changes) and the history scan report them, and the
    // duplicates must be folded into one row with the history noted.
    const { repository, history } = auditFindings(makeApp(`sechard-f02-fresh-${randomUUID().slice(0, 8)}`));

    const serviceRole = repository.find((finding) => (finding.title ?? '').includes('service-role'));
    expect(serviceRole, JSON.stringify(repository)).toBeDefined();
    expect(serviceRole?.severity).toBe('critical');
    expect(serviceRole?.category).toBe('secret');
    expect(serviceRole?.secret_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(serviceRole?.detail ?? '').toContain('also present in committed history');
    // The digest is recorded; the value itself appears nowhere on the finding.
    expect(JSON.stringify(repository)).not.toContain(serviceRoleJwt);
    expect(JSON.stringify(repository)).not.toContain(stripeLive);

    // Exactly one row for the service-role key and one for the Stripe key: the history copies are
    // folded, not repeated.
    expect(repository.filter((finding) => (finding.title ?? '').includes('service-role'))).toHaveLength(1);
    expect(repository.filter((finding) => finding.rule_id === 'stripe-access-token')).toHaveLength(1);
    expect(repository.find((finding) => finding.rule_id === 'stripe-access-token')?.severity).toBe('critical');
    expect(history, 'history duplicates must be folded').toHaveLength(0);

    // The anon key is informational, not a leak: low, same category, still visible.
    const anon = repository.find((finding) => (finding.title ?? '').includes('anon/publishable'));
    expect(anon?.severity).toBe('low');

    // Totality: no gitleaks finding is left unknown or uncategorized.
    for (const finding of repository) {
      expect(finding.severity, JSON.stringify(finding)).not.toBe('unknown');
      expect(finding.category).toBe('secret');
    }
  }, 600_000);

  it('finds and classifies a secret that only exists in history by reading its own commit', () => {
    // A second commit removes the Stripe key from the worktree. It must still be reported —
    // classified critical by reading the line from the commit that introduced it, not by
    // guessing from the rule id.
    const root = makeApp(`sechard-f02-removed-${randomUUID().slice(0, 8)}`);
    writeFileSync(join(root, '.env'), envWithStripe.split('\n').filter((line) => !line.startsWith('STRIPE_SECRET_KEY')).join('\n'));
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-q', '-m', 'remove stripe key'], { cwd: root });

    const { repository, history } = auditFindings(root);

    const stripe = history.find((finding) => finding.rule_id === 'stripe-access-token');
    expect(stripe, JSON.stringify(history)).toBeDefined();
    expect(stripe?.severity).toBe('critical');
    expect(stripe?.category).toBe('secret');
    expect(stripe?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect((stripe?.detail ?? '') + (stripe?.title ?? '')).not.toContain(stripeLive);
    // The service-role key survived to HEAD but is not part of the newest commit's change, so only
    // the history scan reports it — still critical, with its introducing commit recorded.
    const serviceRole = history.find((finding) => (finding.title ?? '').includes('service-role'));
    expect(serviceRole?.severity).toBe('critical');
    expect(serviceRole?.commit).toMatch(/^[0-9a-f]{40}$/);
    for (const finding of [...repository, ...history]) {
      expect(finding.severity, JSON.stringify(finding)).not.toBe('unknown');
      expect(finding.category).toBe('secret');
    }
  }, 600_000);
});
