import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  checkDependencyPolicy,
  hasInstallException,
  isInstallHookApproved,
  isRegistryApproved,
  loadDependencyPolicy,
  type DependencyPolicy,
} from '../../src/execution/policy.js';
import { packageRoot } from '../../src/validation/schema.js';
import {
  executeProvisionPlan,
  installScriptDecision,
  validateProvisionPlan,
  type ProvisionPlan,
} from '../../src/execution/provision.js';

const NOW = new Date('2026-10-06T12:00:00Z');
const policyFile = join(packageRoot(), 'policy', 'dependency-policy.yaml');

const base = (): DependencyPolicy => ({
  schema: 'hardening/dependency-policy/v1',
  policy_version: 1,
  review_status: 'draft',
  minimum_release_age_minutes: 10080,
  registries: {
    allow_additional_registries: false,
    allowed: [{ id: 'npmjs', url: 'https://registry.npmjs.org/', reviewed_at: '2026-10-01T00:00:00Z' }],
  },
  install_scripts: { default: 'disabled', allowed_hooks: [] },
  install_exceptions: [],
  urgent_fix_route: { permitted: true, requires_exact_version: true, requires_expiry: true, requires_approval: true, max_exception_days: 30 },
  provisioning: { separate_from_checking: true, require_digest_for_execution: true, require_reviewed_registry: true, require_recorded_identity: true },
  application_execution: { requires_operator_approved_environment: true, isolation_is_operator_responsibility: true },
});

describe('the reviewed dependency policy', () => {
  it('loads and validates without issues', () => {
    const result = loadDependencyPolicy(policyFile, NOW);
    expect(result.issues).toEqual([]);
    expect(result.policy?.minimum_release_age_minutes).toBe(10080);
    expect(result.policy?.install_scripts.default).toBe('disabled');
    expect(result.policy?.install_scripts.allowed_hooks).toEqual([]);
    expect(result.policy?.install_exceptions).toEqual([]);
  });

  it('is clearly labelled draft', () => {
    const policy = loadDependencyPolicy(policyFile, NOW).policy as DependencyPolicy;
    expect(policy.review_status).toBe('draft');
  });

  it('does not claim a provisioning permission the owner has not granted', () => {
    const raw = readFileSync(policyFile, 'utf8');
    expect(raw).toMatch(/network_access_to_registries/);
    expect(raw).toMatch(/still unfilled|unfilled/);
  });

  it('reports a missing file rather than defaulting to permissive', () => {
    const result = loadDependencyPolicy(join(packageRoot(), 'policy', 'no-such-policy.yaml'), NOW);
    expect(result.issues[0]?.code).toBe('input.not_found');
    expect(result.policy).toBeUndefined();
  });
});

describe('policy validation rejects the shortcuts', () => {
  it('flags a release-age delay that is not the reviewed value', () => {
    const issues = checkDependencyPolicy({ ...base(), minimum_release_age_minutes: 0 }, NOW);
    expect(issues.some((item) => item.message.includes('10080'))).toBe(true);
  });

  it('flags a registry that is not HTTPS', () => {
    const policy = base();
    const issues = checkDependencyPolicy(
      { ...policy, registries: { ...policy.registries, allowed: [{ id: 'x', url: 'http://registry.example.invalid/', reviewed_at: '2026-10-01T00:00:00Z' }] } },
      NOW,
    );
    expect(issues.some((item) => item.message.includes('HTTPS'))).toBe(true);
  });

  it('flags an empty registry list', () => {
    const policy = base();
    const issues = checkDependencyPolicy({ ...policy, registries: { ...policy.registries, allowed: [] } }, NOW);
    expect(issues.some((item) => item.message.includes('no reviewed registry'))).toBe(true);
  });

  // A range or wildcard would be a permanent blanket exemption.
  it('flags an install exception that is not an exact version', () => {
    const policy = base();
    const issues = checkDependencyPolicy(
      {
        ...policy,
        install_exceptions: [
          { package: 'pkg', version: '^1.2.3', reason: 'urgent fix applied', approved_by: 'owner', approved_at: '2026-10-01T00:00:00Z', expires_at: '2026-11-01T00:00:00Z' },
        ],
      },
      NOW,
    );
    expect(issues.some((item) => item.code === 'semantic.invalid_exception_scope')).toBe(true);
  });

  it('flags an expired install exception', () => {
    const policy = base();
    const issues = checkDependencyPolicy(
      {
        ...policy,
        install_exceptions: [
          { package: 'pkg', version: '1.2.3', reason: 'urgent fix applied', approved_by: 'owner', approved_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z' },
        ],
      },
      NOW,
    );
    expect(issues.some((item) => item.code === 'semantic.invalid_interval')).toBe(true);
  });

  it('flags an exception that runs beyond the maximum duration', () => {
    const policy = base();
    const issues = checkDependencyPolicy(
      {
        ...policy,
        install_exceptions: [
          { package: 'pkg', version: '1.2.3', reason: 'urgent fix applied', approved_by: 'owner', approved_at: '2026-10-01T00:00:00Z', expires_at: '2027-10-01T00:00:00Z' },
        ],
      },
      NOW,
    );
    expect(issues.some((item) => item.message.includes('maximum'))).toBe(true);
  });

  it('flags an expired install-hook allowance', () => {
    const policy = base();
    const issues = checkDependencyPolicy(
      {
        ...policy,
        install_scripts: {
          default: 'disabled',
          allowed_hooks: [{ package: 'native-lib', hook: 'postinstall', reason: 'builds a native binding', approved_by: 'owner', approved_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z' }],
        },
      },
      NOW,
    );
    expect(issues.some((item) => item.code === 'semantic.invalid_interval')).toBe(true);
  });
});

describe('install scripts are disabled unless individually reviewed', () => {
  it('blocks an unapproved hook', () => {
    expect(installScriptDecision(base(), 'some-package', 'postinstall', NOW)).toBe('blocked');
  });

  it('allows only the reviewed hook, for its package, before expiry', () => {
    const policy = base();
    const withHook: DependencyPolicy = {
      ...policy,
      install_scripts: {
        default: 'disabled',
        allowed_hooks: [{ package: 'native-lib', hook: 'postinstall', reason: 'builds a native binding', approved_by: 'owner', approved_at: '2026-10-01T00:00:00Z', expires_at: '2026-12-01T00:00:00Z' }],
      },
    };
    expect(isInstallHookApproved(withHook, 'native-lib', 'postinstall', NOW)).toBe(true);
    expect(isInstallHookApproved(withHook, 'other-lib', 'postinstall', NOW)).toBe(false);
    expect(isInstallHookApproved(withHook, 'native-lib', 'preinstall', NOW)).toBe(false);
    expect(isInstallHookApproved(withHook, 'native-lib', 'postinstall', new Date('2027-01-01T00:00:00Z'))).toBe(false);
  });

  it('refuses to treat an enabling default as approval', () => {
    const enabled: DependencyPolicy = { ...base(), install_scripts: { default: 'enabled', allowed_hooks: [] } };
    expect(isInstallHookApproved(enabled, 'any-package', 'postinstall', NOW)).toBe(false);
  });
});

describe('provisioning is validated before anything runs', () => {
  const plan = (overrides: Partial<ProvisionPlan['steps'][number]> = {}): ProvisionPlan => ({
    steps: [{ kind: 'package', name: 'some-package', version: '1.2.3', registry: 'https://registry.npmjs.org/', manager: 'pnpm', ...overrides }],
  });

  it('blocks a version range', () => {
    const result = validateProvisionPlan(plan({ version: '^1.2.3' }), base(), { now: NOW });
    expect(result.ok).toBe(false);
    expect(result.blocks[0]?.reason).toBe('version_not_exact');
  });

  it('blocks an unreviewed registry', () => {
    const result = validateProvisionPlan(plan({ registry: 'https://evil.example.invalid/' }), base(), { now: NOW });
    expect(result.blocks.some((block) => block.reason === 'unreviewed_registry')).toBe(true);
  });

  // The machine's package-manager behaviour has not been verified, so the age policy cannot be
  // assumed to have applied.
  it('blocks a normal install while the release-age enforcement is unverified', () => {
    const result = validateProvisionPlan(plan(), base(), { now: NOW });
    expect(result.ok).toBe(false);
    expect(result.blocks.some((block) => block.reason === 'age_policy_unverified')).toBe(true);
  });

  it('permits the same install once the age behaviour has been verified', () => {
    const result = validateProvisionPlan(plan(), base(), { now: NOW, managerBehaviourVerified: true });
    expect(result.ok).toBe(true);
  });

  it('permits an exact, current install exception even without verified manager behaviour', () => {
    const policy = base();
    const withException: DependencyPolicy = {
      ...policy,
      install_exceptions: [{ package: 'some-package', version: '1.2.3', reason: 'urgent security fix reviewed', approved_by: 'owner', approved_at: '2026-10-05T00:00:00Z', expires_at: '2026-11-01T00:00:00Z' }],
    };
    expect(validateProvisionPlan(plan(), withException, { now: NOW }).ok).toBe(true);
    expect(hasInstallException(withException, 'some-package', '1.2.3', NOW)).toBe(true);
    expect(hasInstallException(withException, 'some-package', '1.2.4', NOW)).toBe(false);
  });

  it('rejects an expired exception and falls back to blocking', () => {
    const policy = base();
    const withExpired: DependencyPolicy = {
      ...policy,
      install_exceptions: [{ package: 'some-package', version: '1.2.3', reason: 'urgent security fix reviewed', approved_by: 'owner', approved_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z' }],
    };
    const result = validateProvisionPlan(plan(), withExpired, { now: NOW });
    expect(result.ok).toBe(false);
    expect(result.blocks.some((block) => block.reason === 'age_policy_unverified')).toBe(true);
  });

  it('blocks an unapproved install hook', () => {
    const result = validateProvisionPlan(plan({ installHooks: ['postinstall'] }), base(), { now: NOW, managerBehaviourVerified: true });
    expect(result.blocks.some((block) => block.reason === 'unapproved_install_hook')).toBe(true);
  });

  it('blocks a downloaded tool with no digest', () => {
    const result = validateProvisionPlan(
      { steps: [{ kind: 'download', name: 'tool', version: '1.0.0', url: 'https://registry.npmjs.org/tool.tgz' }] },
      base(),
      { now: NOW, managerBehaviourVerified: true },
    );
    expect(result.blocks.some((block) => block.reason === 'missing_digest')).toBe(true);
  });

  it('does not execute anything when validation fails', async () => {
    const result = await executeProvisionPlan(plan(), base(), {
      cwd: packageRoot(),
      managerExecutable: process.execPath,
      managerVersionArgs: ['--version'],
      now: NOW,
    });
    expect(result.executed).toBe(false);
    expect(result.outcomes).toEqual([]);
  });

  it('does not run a shell: the manager path must be absolute and real', async () => {
    const result = await executeProvisionPlan(plan(), base(), {
      cwd: packageRoot(),
      managerExecutable: 'pnpm',
      managerVersionArgs: ['--version'],
      now: NOW,
      managerBehaviourVerified: true,
    });
    // 'pnpm' is not absolute, so the process layer refuses rather than resolving it through PATH,
    // and the plan stops after that single refusal instead of continuing.
    expect(result.outcomes).toHaveLength(1);
    expect(result.outcomes[0]?.failure).toBe('spawn_error');
    expect(result.executed).toBe(false);
  });

  /**
   * P4.1: provisioning executes every step for real and reports per-step outcomes — a failed
   * package command, an unverified manager version, or a download that does not match its
   * recorded digest cannot yield a completion claim, and steps after a failure are recorded as
   * not run rather than implied complete.
   */
  describe('provisioning executes every step for real (P4.1)', () => {
    // Node as the fake manager: --version succeeds, and any package command exits nonzero, so a
    // failed install is exercisable without the network.
    const nodeManager = (extra: Partial<Parameters<typeof executeProvisionPlan>[2]> = {}): Parameters<typeof executeProvisionPlan>[2] => ({
      cwd: packageRoot(),
      managerExecutable: process.execPath,
      managerVersionArgs: ['--version'],
      now: NOW,
      managerBehaviourVerified: true,
      ...extra,
    });

    const packagePlan = (): ProvisionPlan => ({
      steps: [
        { kind: 'package', name: 'some-package', version: '1.2.3', registry: 'https://registry.npmjs.org/' },
        { kind: 'package', name: 'next-package', version: '2.0.0', registry: 'https://registry.npmjs.org/' },
      ],
    });

    it('a failed package command stops the plan, and the remaining steps are recorded as not run', async () => {
      const result = await executeProvisionPlan(packagePlan(), base(), nodeManager());
      expect(result.executed).toBe(false);
      expect(result.steps).toHaveLength(2);
      expect(result.steps[0]?.ok).toBe(false);
      expect(result.steps[0]?.process?.exitCode).not.toBe(0);
      expect(result.steps[1]?.notRun).toBe(true);
    });

    it('the approved registry is passed to the manager explicitly', async () => {
      const result = await executeProvisionPlan(packagePlan(), base(), nodeManager());
      expect(result.steps[0]?.args).toContain('--registry');
      expect(result.steps[0]?.args).toContain('https://registry.npmjs.org/');
    });

    it('a manager whose observed version does not match the reviewed exact version refuses before any step', async () => {
      const result = await executeProvisionPlan(packagePlan(), base(), nodeManager({ expectedManagerVersion: '99.99.99' }));
      expect(result.executed).toBe(false);
      expect(result.managerVersion).toMatchObject({ expected: '99.99.99', matched: false });
      expect(result.steps).toEqual([]);
    });

    it('a manager whose observed version matches the reviewed exact version proceeds to the steps', async () => {
      // Learn the observed version from a refusing probe, then require exactly it: the version
      // gate passes and the plan reaches its steps.
      const probe = await executeProvisionPlan(packagePlan(), base(), nodeManager({ expectedManagerVersion: '0.0.0-probe' }));
      const observed = probe.managerVersion?.observed;
      expect(observed).toBeDefined();
      const result = await executeProvisionPlan(packagePlan(), base(), nodeManager({ expectedManagerVersion: observed as string }));
      expect(result.managerVersion).toMatchObject({ expected: observed as string, matched: true });
      // The fake manager still fails the install itself; the version gate is what passed.
      expect(result.steps[0]?.ok).toBe(false);
    });

    it('a download step executes, verifies its digest, and writes the artifact', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'hardening-provision-'));
      const bytes = Buffer.from('verified artifact bytes');
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      const destination = join(dir, 'tool.bin');
      const downloadPlan: ProvisionPlan = {
        steps: [{ kind: 'download', name: 'tool', version: '1.0.0', url: 'https://registry.npmjs.org/tool.bin', expectedSha256: sha256, destination }],
      };
      const fetchImpl = (async () => new Response(bytes)) as typeof fetch;
      const result = await executeProvisionPlan(downloadPlan, base(), nodeManager({ fetchImpl }));
      expect(result.executed).toBe(true);
      expect(result.steps[0]?.ok).toBe(true);
      expect(readFileSync(destination)).toEqual(bytes);
      rmSync(dir, { recursive: true, force: true });
    });

    it('a download whose bytes do not match the recorded digest stops the plan', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'hardening-provision-'));
      const destination = join(dir, 'tool.bin');
      const sha256 = createHash('sha256').update(Buffer.from('expected bytes')).digest('hex');
      const downloadPlan: ProvisionPlan = {
        steps: [
          { kind: 'download', name: 'tool', version: '1.0.0', url: 'https://registry.npmjs.org/tool.bin', expectedSha256: sha256, destination },
          { kind: 'package', name: 'next-package', version: '2.0.0', registry: 'https://registry.npmjs.org/' },
        ],
      };
      const fetchImpl = (async () => new Response(Buffer.from('unexpected bytes'))) as typeof fetch;
      const result = await executeProvisionPlan(downloadPlan, base(), nodeManager({ fetchImpl }));
      expect(result.executed).toBe(false);
      expect(result.steps[0]?.download).toMatchObject({ ok: false, reason: 'digest_mismatch' });
      expect(existsSync(destination)).toBe(false);
      expect(result.steps[1]?.notRun).toBe(true);
      rmSync(dir, { recursive: true, force: true });
    });

    it('blocks a package step that names no registry while the policy requires a reviewed one', () => {
      // Built without the key: under exactOptionalPropertyTypes an explicit undefined is a type error.
      const step: ProvisionPlan['steps'][number] = { kind: 'package', name: 'some-package', version: '1.2.3', manager: 'pnpm' };
      const result = validateProvisionPlan({ steps: [step] }, base(), { now: NOW, managerBehaviourVerified: true });
      expect(result.ok).toBe(false);
      expect(result.blocks.some((block) => block.reason === 'missing_registry')).toBe(true);
    });

    it('blocks a download step with no URL and a download step with no destination', () => {
      const digest = createHash('sha256').update('x').digest('hex');
      const noUrl = validateProvisionPlan(
        { steps: [{ kind: 'download', name: 'tool', version: '1.0.0', expectedSha256: digest }] },
        base(),
        { now: NOW, managerBehaviourVerified: true },
      );
      expect(noUrl.blocks.some((block) => block.reason === 'missing_url')).toBe(true);

      const noDestination = validateProvisionPlan(
        { steps: [{ kind: 'download', name: 'tool', version: '1.0.0', url: 'https://registry.npmjs.org/tool.bin', expectedSha256: digest }] },
        base(),
        { now: NOW, managerBehaviourVerified: true },
      );
      expect(noDestination.blocks.some((block) => block.reason === 'missing_destination')).toBe(true);
    });
  });
});

describe('registry approval', () => {
  it('matches the exact reviewed registry and ignores a trailing slash', () => {
    const policy = base();
    expect(isRegistryApproved(policy, 'https://registry.npmjs.org/')).toBe(true);
    expect(isRegistryApproved(policy, 'https://registry.npmjs.org')).toBe(true);
    expect(isRegistryApproved(policy, 'https://registry.npmjs.org.evil.invalid/')).toBe(false);
  });
});
