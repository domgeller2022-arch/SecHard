import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * W1 acceptance, through the CLI: every wired scanner must produce at least one real detection on
 * its vulnerable fixture. Adapter unit tests do not count — this runs `hardening plan` and
 * `hardening check` as separate processes, exactly as a consumer would.
 *
 * The scratch application is a real git repository so the gitleaks git-mode recipes have history to
 * scan, and it carries the vulnerable fixtures for all four tools.
 */
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');
const FIXTURE_RECORDS = join(REPO, 'tests', 'fixtures', 'consumer', '.hardening');
const SCANNER_FIXTURES = join(REPO, 'tests', 'fixtures', 'scanners');

const scratch = mkdtempSync(join(tmpdir(), 'hardening-recipes-'));
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
      maxBuffer: 32 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

describe('the wired recipes produce real detections through the CLI', () => {
  it('finds secrets, SAST issues, workflow problems, and advisories on the vulnerable scratch app', () => {
    // Build the scratch application with the vulnerable fixtures and one commit of history.
    mkdirSync(join(scratch, 'src'), { recursive: true });
    mkdirSync(join(scratch, '.github', 'workflows'), { recursive: true });
    cpSync(FIXTURE_RECORDS, join(scratch, '.hardening'), { recursive: true });
    cpSync(join(SCANNER_FIXTURES, 'secrets', 'vulnerable.ts'), join(scratch, 'src', 'leaky.ts'));
    cpSync(join(SCANNER_FIXTURES, 'sast', 'vulnerable.ts'), join(scratch, 'src', 'sast.ts'));
    cpSync(join(SCANNER_FIXTURES, 'workflows', 'vulnerable.yaml'), join(scratch, '.github', 'workflows', 'vulnerable.yaml'));
    cpSync(join(SCANNER_FIXTURES, 'dependencies', 'package-lock.json'), join(scratch, 'package-lock.json'));

    execFileSync('git', ['init', '-q'], { cwd: scratch });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: scratch });
    execFileSync('git', ['config', 'user.name', 'fixture'], { cwd: scratch });
    execFileSync('git', ['add', '-A'], { cwd: scratch });
    execFileSync('git', ['commit', '-q', '-m', 'vulnerable fixture'], { cwd: scratch });

    const runs = join(scratch, '.hardening', 'runs');
    const planned = cli(['plan', '--app', scratch, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', runs], scratch);
    expect(planned.status, planned.stderr).toBe(0);
    const runDir = join(runs, readdirSync(runs).filter((entry) => entry.startsWith('pr-')).sort().pop() as string);

    const checked = cli(['check', '--app', scratch, '--policy', REPO, '--plan', join(runDir, 'plan.json'), '--out', runDir], scratch);
    // Other required checks are not implemented yet, so `check` exits 1; that must not be an error.
    expect(checked.status, checked.stderr).toBe(1);

    const results = JSON.parse(readFileSync(join(runDir, 'results.json'), 'utf8')) as {
      check_id: string;
      outcome: string;
      findings?: { rule_id: string }[];
    }[];
    const findingsFor = (recipe: string): { rule_id: string; severity?: string; category?: string; detail?: string }[] => {
      const result = results.find((entry) => entry.check_id.includes(recipe));
      expect(result, `no result for ${recipe}`).toBeDefined();
      expect(result?.outcome, `${recipe} must produce an answer`).toBe('pass');
      return (result?.findings ?? []) as { rule_id: string; severity?: string; category?: string; detail?: string }[];
    };

    const filesSecrets = findingsFor('gitleaks/files');
    expect(filesSecrets.length, 'gitleaks/files').toBeGreaterThan(0);
    // One commit of history: every repository and history finding duplicates the current-files
    // scan, and the fold leaves one row per secret on the files scan — with the history and the
    // newest commit noted — instead of reporting the same secret three times.
    expect(findingsFor('gitleaks/repository').length, 'gitleaks/repository').toBe(0);
    expect(findingsFor('gitleaks/history').length, 'gitleaks/history').toBe(0);
    expect(
      filesSecrets.some((finding) => (finding.detail ?? '').includes('also present in committed history')),
      JSON.stringify(filesSecrets),
    ).toBe(true);
    expect(
      filesSecrets.every((finding) => (finding.detail ?? '').includes("also present in the newest commit's change set")),
      JSON.stringify(filesSecrets),
    ).toBe(true);
    // F-02: every secret finding is classified — never `unknown` — with the category marker set.
    expect(filesSecrets.every((finding) => finding.severity !== 'unknown' && finding.category === 'secret')).toBe(true);
    expect(findingsFor('opengrep/rules').length, 'opengrep/rules').toBeGreaterThan(0);
    expect(findingsFor('zizmor/workflows').length, 'zizmor/workflows').toBeGreaterThan(0);
    expect(findingsFor('osv/lockfile').length, 'osv/lockfile').toBeGreaterThan(0);

    // Raw reports are stored with digests, so evidence references exactly what was parsed.
    const withReport = results.find((entry) => entry.check_id.includes('gitleaks/repository')) as unknown as {
      report?: { path?: string; raw_digest?: string };
    };
    expect(withReport.report?.raw_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(withReport.report?.path).toMatch(/gitleaks-repository\.json$/);
    expect(() => readFileSync(join(runDir, 'raw', withReport.report?.path ?? ''), 'utf8')).not.toThrow();
  }, 600_000);

  it('reports an unsupported reason, not a pass, when a recipe does not apply', () => {
    // A bare application with no lockfile, no workflows, and no build output: the recipes that
    // apply to those artefacts must say why, and none of them may claim a pass.
    const bare = join(scratch, 'bare');
    mkdirSync(join(bare, '.hardening'), { recursive: true });
    cpSync(FIXTURE_RECORDS, join(bare, '.hardening'), { recursive: true });
    writeFileSync(join(bare, 'app.js'), 'console.log("no lockfile, no workflows");\n');
    // Its own repository, so the recipes resolve their scope here and not to the parent scratch
    // repository the previous test created.
    execFileSync('git', ['init', '-q'], { cwd: bare });

    const runs = join(bare, '.hardening', 'runs');
    expect(cli(['plan', '--app', bare, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', runs], bare).status).toBe(0);
    const runDir = join(runs, readdirSync(runs).filter((entry) => entry.startsWith('pr-')).sort().pop() as string);
    cli(['check', '--app', bare, '--policy', REPO, '--plan', join(runDir, 'plan.json'), '--out', runDir], bare);

    const results = JSON.parse(readFileSync(join(runDir, 'results.json'), 'utf8')) as {
      check_id: string;
      outcome: string;
      diagnostic?: string;
    }[];
    for (const recipe of ['osv/lockfile', 'zizmor/workflows']) {
      const result = results.find((entry) => entry.check_id.includes(recipe));
      expect(result?.outcome, recipe).toBe('unsupported');
      expect(result?.diagnostic?.length ?? 0, recipe).toBeGreaterThan(0);
    }
  }, 300_000);
});
