import { execFileSync, spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
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

const findingsFor = (results: AuditOutput['results'], recipe: string): { rule_id: string }[] => {
  const result = results.find((entry) => entry.check_id.includes(recipe));
  expect(result, `no result for ${recipe}`).toBeDefined();
  return ((result?.findings ?? []) as { rule_id: string }[]);
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

    expect(findingsFor(audit.results, 'gitleaks/repository').length).toBeGreaterThan(0);
    expect(findingsFor(audit.results, 'gitleaks/history').length).toBeGreaterThan(0);
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
    // Everything standard runs still ran: the history scan produced its real result.
    const history = deep.results.find((entry) => entry.check_id.includes('gitleaks/history'));
    expect(history?.outcome).toBe('pass');
    expect((history?.findings ?? []).length).toBeGreaterThan(0);
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
