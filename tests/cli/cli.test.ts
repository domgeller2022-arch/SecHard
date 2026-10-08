import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildReport } from '../../src/commands/report.js';
import { redactSecrets, escapeMarkdown, containsSecretPattern } from '../../src/evidence/redaction.js';
import { evaluate } from '../../src/domain/evaluator.js';
import { buildPlan, planIdentity } from '../../src/domain/planner.js';
import { loadCatalogue, loadProfile } from '../../src/domain/definitions.js';
import type { ApplicabilityRule } from '../../src/domain/applicability.js';
import type { ManifestRecord } from '../../src/domain/types.js';
import { NOW, allPassing, manifest, planFor, policy } from '../helpers/fixtures.js';
import type { PlanInput } from '../../src/domain/planner.js';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = join(REPO, 'dist', 'cli.js');
const FIXTURE = join(REPO, 'tests', 'fixtures', 'consumer');
const COMMIT = 'a'.repeat(40);

interface RunResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** Runs the compiled CLI as a separate process, which is how the owner will use it. */
function cli(args: readonly string[], cwd = REPO): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return { status: failure.status ?? 2, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

const scratch = mkdtempSync(join(tmpdir(), 'hardening-cli-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function runDirectory(out: string): string {
  const entries = readdirSync(out).filter((entry) => entry.startsWith('pr-'));
  expect(entries.length).toBeGreaterThan(0);
  return join(out, entries.sort().pop() as string);
}

describe('the CLI runs from outside the repository', () => {
  it('prints help and exits 0', () => {
    const result = cli(['help']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('hardening plan');
    expect(result.stdout).toContain('Exit codes:');
  });

  it('prints the version and exits 0', () => {
    const result = cli(['version']);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('exits 2 on an unknown command', () => {
    const result = cli(['nonsense']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('unknown command');
  });

  it('exits 2 when a required option is missing', () => {
    const result = cli(['gate', '--app', FIXTURE]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('missing required option');
  });

  it('exits 2 on an unknown stage rather than planning nothing', () => {
    const result = cli(['plan', '--app', FIXTURE, '--policy', REPO, '--stage', 'nonsense', '--environment', 'local', '--out', scratch]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('unknown stage');
  });
});

describe('validate', () => {
  it('accepts the valid fixture and reports what it checked', () => {
    const result = cli(['validate', '--app', FIXTURE, '--policy', REPO]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('validate: OK');
    expect(result.stdout).toContain('35 controls');
  });

  it('rejects a manifest naming a profile that does not exist', () => {
    const dir = invalidConsumer('unknown-profile.yaml');
    const result = cli(['validate', '--app', dir, '--policy', REPO]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("unknown profile 'does-not-exist'");
  });

  it('rejects a manifest whose policy lock names a different commit', () => {
    const dir = invalidConsumer('forged-commit.yaml');
    const result = cli(['validate', '--app', dir, '--policy', REPO]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('policy lock');
    expect(result.stderr).toContain('000000000000');
  });

  it('rejects a duplicate YAML key rather than taking the last value', () => {
    const dir = invalidConsumer('duplicate-key.yaml');
    const result = cli(['validate', '--app', dir, '--policy', REPO]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('input.duplicate_key');
  });
});

describe('plan, check, gate, report end to end', () => {
  let runDir: string;

  beforeAll(() => {
    const out = join(scratch, 'demo');
    const planned = cli(['plan', '--app', FIXTURE, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', out]);
    expect(planned.status).toBe(0);
    runDir = runDirectory(out);
  });

  it('derives the expected work before anything runs and writes it', () => {
    const plan = JSON.parse(readFileSync(join(runDir, 'plan.json'), 'utf8')) as {
      expected_checks: { check_id: string; required: boolean }[];
      inputs: { source_commit: string; profiles: string[] };
    };
    expect(plan.expected_checks.length).toBeGreaterThan(0);
    expect(plan.inputs.source_commit).toMatch(/^[0-9a-f]{40}$/);
    expect(plan.inputs.profiles).toContain('nextjs-supabase');
  });

  it('records the run identity', () => {
    const record = JSON.parse(readFileSync(join(runDir, 'run.json'), 'utf8')) as {
      run_id: string;
      source_commit: string;
      node_version: string;
    };
    expect(record.run_id).toMatch(/^pr-/);
    expect(record.source_commit).toMatch(/^[0-9a-f]{40}$/);
    expect(record.node_version).toMatch(/^v\d+/);
  });

  it('runs the built-in recipe and reports a real pass for it', () => {
    const result = cli(['check', '--app', FIXTURE, '--policy', REPO, '--plan', join(runDir, 'plan.json'), '--out', runDir]);
    // Required checks that did not run make `check` exit 1. That is the fail-closed contract: a CI
    // job must not be green because the only implemented recipe passed.
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('produced');
    expect(result.stdout).toContain('required check(s) did not run');

    const results = JSON.parse(readFileSync(join(runDir, 'results.json'), 'utf8')) as {
      check_id: string;
      outcome: string;
      coverage: string;
      evidence_origin: string;
    }[];
    const builtIn = results.filter((item) => item.check_id.includes('policy/record-consistency'));
    expect(builtIn.length).toBeGreaterThan(0);
    expect(builtIn[0]?.outcome).toBe('pass');
    expect(builtIn[0]?.coverage).toBe('complete');
    expect(builtIn[0]?.evidence_origin).toBe('actual_tool');
  });

  // Recipes that belong to later batches must report unsupported, never a fabricated pass.
  it('reports unimplemented recipes as unsupported rather than passing them', () => {
    const results = JSON.parse(readFileSync(join(runDir, 'results.json'), 'utf8')) as {
      check_id: string;
      outcome: string;
      diagnostic?: string;
    }[];
    const unsupported = results.filter((item) => item.outcome === 'unsupported');
    expect(unsupported.length).toBeGreaterThan(0);
    for (const item of unsupported) {
      expect(item.diagnostic).toMatch(/not implemented/);
    }
    expect(results.some((item) => item.check_id.includes('gitleaks'))).toBe(true);
  });

  it('blocks the gate, because unimplemented coverage cannot satisfy a required check', () => {
    const result = cli(['gate', '--app', FIXTURE, '--policy', REPO, '--run', runDir]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('gate: blocked');
    expect(result.stdout).toContain('check.not_passed');
  });

  it('produces a readable report with the same decision as the gate', () => {
    const result = cli(['report', '--app', FIXTURE, '--policy', REPO, '--run', runDir]);
    expect(result.status).toBe(1);

    const evidence = JSON.parse(readFileSync(join(runDir, 'report.json'), 'utf8')) as {
      decision: { outcome: string; kit_readiness: string; application_production_readiness: string };
      expected_checks: { method?: string }[];
      results: unknown[];
      control_outcomes: { outcome: string }[];
    };
    expect(evidence.decision.outcome).toBe('blocked');
    // At a pull request the profile requires no manual evidence, so every expected check is an
    // executed one. Manual requirements appear at release, where they must be met by attestation.
    const executed = evidence.expected_checks.filter((check) => check.method !== 'manual_attestation');
    expect(evidence.results.length).toBe(executed.length);
    expect(evidence.expected_checks.some((check) => check.method === 'manual_attestation')).toBe(false);
    expect(evidence.decision.kit_readiness).toBe('pending');
    expect(evidence.decision.application_production_readiness).toBe('pending');

    const markdown = readFileSync(join(runDir, 'report.md'), 'utf8');
    expect(markdown).toContain('**Decision: blocked**');
    expect(markdown).toContain('Kit readiness:');
    expect(markdown).toContain('Application production readiness:');
  });

  it('does not let a report from one run satisfy a different plan', () => {
    const out = join(scratch, 'second');
    const planned = cli(['plan', '--app', FIXTURE, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', out]);
    expect(planned.status).toBe(0);
    const second = runDirectory(out);

    expect(second).not.toBe(runDir);
    expect(() => readFileSync(join(second, 'results.json'), 'utf8')).toThrow();

    // A gate run against the new plan finds no results at all, which blocks.
    const gated = cli(['gate', '--app', FIXTURE, '--policy', REPO, '--run', second]);
    expect(gated.status).toBe(1);
    expect(gated.stdout).toContain('check.missing');
  });
});

describe('exit codes distinguish the three outcomes', () => {
  it('exits 2 for invalid inputs', () => {
    const result = cli(['validate', '--app', invalidConsumer('unknown-profile.yaml'), '--policy', REPO]);
    expect(result.status).toBe(2);
  });

  it('exits 1 for a blocked decision', () => {
    const out = join(scratch, 'codes');
    cli(['plan', '--app', FIXTURE, '--policy', REPO, '--stage', 'pr', '--environment', 'local', '--out', out]);
    const run = runDirectory(out);
    cli(['check', '--app', FIXTURE, '--policy', REPO, '--plan', join(run, 'plan.json'), '--out', run]);
    expect(cli(['gate', '--app', FIXTURE, '--policy', REPO, '--run', run]).status).toBe(1);
  });

  it('exits 0 for validate on valid records', () => {
    expect(cli(['validate', '--app', FIXTURE, '--policy', REPO]).status).toBe(0);
  });
});

describe('a satisfied decision is reachable and exits 0', () => {
  it('reaches exit 0 with a core-only profile and complete evidence', () => {
    // Reaches the evaluator directly rather than through the CLI: satisfying the gate through the
    // CLI would require every profile recipe to exist, which is Batch B work.
    const controls = loadCatalogue().controls;
    const coreProfile = loadProfile('core');

    const demoManifest: ManifestRecord = {
      id: 'demo',
      features: {
        accounts: { state: 'enabled' },
        private_resources: { state: 'disabled' },
        roles: { state: 'disabled' },
        tenancy: { state: 'disabled' },
        recovery: { state: 'enabled' },
        payments: { state: 'disabled' },
        webhooks: { state: 'disabled' },
        uploads: { state: 'disabled' },
        outbound_requests: { state: 'disabled' },
        personal_data: { state: 'disabled' },
        runtime_ai: { state: 'disabled' },
        hosting: { state: 'enabled' },
        interfaces: { state: 'enabled' },
        environments: { state: 'enabled' },
        persistent_storage: { state: 'disabled' },
      },
      environments: [{ name: 'local', kind: 'local' }],
      profiles: ['core'],
      policy_lock: { repository: 'x/y', commit: COMMIT, policy_digest: '0'.repeat(64) },
    };

    const plan = buildPlan({
      stage: 'operations',
      environment: 'local',
      manifest: demoManifest,
      profiles: [coreProfile],
      controls: controls as unknown as PlanInput['controls'],
      policy,
      policyCommit: COMMIT,
      policyDigests: { controlCatalogue: 'c'.repeat(64), gatePolicy: 'd'.repeat(64), profiles: { core: 'e'.repeat(64) } },
      sourceCommit: COMMIT,
      sourceDirty: false,
      now: NOW,
      planId: 'plan-demo',
      runId: 'run-demo',
    });

    expect(plan.expected_checks.length).toBeGreaterThan(0);

    const results = plan.expected_checks.map((check) => ({
      schema_version: 'check-result/v1' as const,
      run_id: 'run',
      check_id: check.check_id,
      control_ids: check.control_ids,
      recipe: check.recipe,
      stage: check.stage,
      environment: check.environment,
      outcome: 'pass' as const,
      coverage: 'complete' as const,
      identity: { source_commit: COMMIT, policy_commit: COMMIT, run_id: 'run-demo', attempt: 1 },
      started_at: '2026-10-06T11:00:00Z',
      finished_at: '2026-10-06T11:00:10Z',
      scope: { expected: 1, observed: 10, files: ['a'], routes: ['/'] },
      evidence_origin: 'actual_tool' as const,
    }));

    const decision = evaluate({
      stage: 'operations',
      environment: 'local',
      manifest: demoManifest,
      controls: controls.map((control) => ({
        id: control.id,
        definition_version: control.definition_version,
        applicability: control.applicability as ApplicabilityRule,
      })),
      plan,
      results,
      manualEvidence: [],
      exceptions: [],
      policy,
      now: NOW,
      planIdentity: planIdentity(plan),
      excludedFeatures: coreProfile.excluded_features ?? [],
    });

    expect(decision.reasons).toEqual([]);
    expect(decision.satisfied).toBe(true);
  });
});

describe('redaction and Markdown escaping', () => {
  it('redacts synthetic secret material before it could be emitted', () => {
    // Composed at runtime, not committed as literals: this repository scans itself for secrets,
    // and a committed literal is indistinguishable from a real leak to that scan.
    const githubToken = ['ghp', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('_');
    const awsExample = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const jwt = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'abcdefghijklmnop'].join('');

    const synthetic = [
      `aws_access_key_id = ${awsExample}`,
      `token: ${githubToken}`,
      `url = https://x.supabase.co/rest/v1/?apikey=${jwt}`,
      '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----',
    ].join('\n');

    const redacted = redactSecrets(synthetic);
    expect(redacted).not.toContain(awsExample);
    expect(redacted).not.toContain(githubToken);
    expect(redacted).not.toContain(jwt);
    expect(redacted).toContain('[REDACTED]');
    expect(containsSecretPattern(synthetic)).toBe(true);
    expect(containsSecretPattern(redacted)).toBe(false);
  });

  it('escapes untrusted text so it cannot inject report structure', () => {
    const injected = '| fake | header |\n# not a heading\n- not a list';
    const escaped = escapeMarkdown(injected);
    expect(escaped).not.toContain('\n');
    expect(escaped).toContain('\\|');
  });

  it('does not write raw process environment into evidence', () => {
    const report = buildReport({
      decision: {
        satisfied: false,
        stage: 'pr',
        environment: 'local',
        reasons: [{ code: 'x', message: 'y' }],
        control_outcomes: [],
        coverage_gaps: [],
        unsupported_scope: [],
      },
      plan: {
        schema_version: 'execution-plan/v1',
        plan_id: 'p',
        run_id: 'r',
        attempt: 1,
        stage: 'pr',
        environment: 'local',
        created_at: '2026-10-06T00:00:00Z',
        policy_identity: {
          commit: 'a'.repeat(40),
          control_catalogue_digest: 'b'.repeat(64),
          gate_policy_digest: 'c'.repeat(64),
          profile_digests: {},
        },
        inputs: { app_id: 'a', source_commit: 'd'.repeat(40), profiles: ['core'] },
        expected_checks: [],
      },
      results: [],
      manualEvidence: [],
      exceptions: [],
      appId: 'a',
      sourceCommit: 'd'.repeat(40),
      sourceClean: false,
      policyRepository: 'x/y',
      policyCommit: 'a'.repeat(40),
      controlCatalogueDigest: 'b'.repeat(64),
      gatePolicyDigest: 'c'.repeat(64),
      generatedAt: new Date('2026-10-06T00:00:00Z'),
      runId: 'r',
    });

    const serialized = JSON.stringify(report.evidence);
    for (const name of Object.keys(process.env)) {
      if (name.length < 8) continue;
      if (process.env[name] !== undefined && (process.env[name] as string).length > 12) {
        expect(serialized).not.toContain(process.env[name] as string);
      }
    }
    expect(serialized).not.toContain('PATH=');
  });
});

describe('an application can never make its own recorded pass count', () => {
  it('ignores a stored status of pass when the actual result failed', () => {
    const plan = planFor('pr');
    const results = allPassing(plan).map((result, index) => (index === 0 ? { ...result, outcome: 'fail' as const } : result));

    const withClaim = evaluate({
      stage: 'pr',
      environment: 'local',
      manifest: manifest(),
      controls: loadCatalogue().controls.map((control) => ({
        id: control.id,
        definition_version: control.definition_version,
        applicability: control.applicability as ApplicabilityRule,
      })),
      plan,
      results,
      manualEvidence: [],
      exceptions: [],
      policy,
      now: NOW,
      planIdentity: planIdentity(plan),
      assessments: plan.expected_checks.map((check) => ({
        control: check.control_ids[0]!,
        definition_version: 1,
        applicability: 'applicable' as const,
        status: 'pass' as const,
        owner: 'maintainer',
        assessed_at: NOW.toISOString(),
      })),
    });

    expect(withClaim.satisfied).toBe(false);
    expect(withClaim.reasons.map((item) => item.code)).toContain('check.not_passed');
  });
});

/** Installs one of the deliberately invalid fixtures as a consumer's `app.yaml`. */
function invalidConsumer(file: string): string {
  const dir = mkdtempSync(join(scratch, 'invalid-'));
  mkdirSync(join(dir, '.hardening'), { recursive: true });
  cpSync(join(FIXTURE, 'invalid', file), join(dir, '.hardening', 'app.yaml'));
  writeFileSync(join(dir, '.hardening', 'exceptions.yaml'), 'exceptions: []\n', 'utf8');
  writeFileSync(join(dir, '.hardening', 'manual-evidence.yaml'), 'records: []\n', 'utf8');
  return dir;
}
