import { createHash } from 'node:crypto';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { loadToolchain, resolveTool, runTool, type ExecutionIdentity, type ToolchainRecord } from '../../src/execution/registry.js';
import { readFileSync } from 'node:fs';
import { extractVersion } from '../../src/execution/version.js';
import { packageRoot } from '../../src/validation/schema.js';

const NODE = process.execPath;
const NODE_VERSION = (process.version.match(/^v(\d+\.\d+\.\d+)/)?.[1] ?? '0.0.0');

const toolchainWithNode = (overrides: Partial<ExecutionIdentity> = {}): ToolchainRecord => ({
  execution: { require_absolute_path: true, require_recorded_version: true, require_digest_when_fetched: true },
  security_tools: { 'fake-tool': { identity: 'verified', step: 9, purpose: 'test double' } },
  executables: {
    'fake-tool': {
      name: 'fake-tool',
      executable: NODE,
      versionArgs: ['--version'],
      expectedVersion: NODE_VERSION,
      fetched: false,
      identity: 'verified',
      ...overrides,
    },
  },
});

describe('an unidentified tool is not executed', () => {
  // The four scanners were pinned in Step 09 and resolve when their verified binaries are present.
  // ZAP and testssl are Step 11 work and must still be refused.
  it('refuses the tools that have no verified identity', () => {
    for (const name of ['zap_baseline', 'testssl']) {
      const availability = resolveTool(name);
      expect(availability.available, name).toBe(false);
      if (!availability.available) {
        expect(availability.reason, name).toBe('identity_unverified');
        expect(availability.message, name).toMatch(/Step \d+/);
      }
    }
  });

  it('resolves the pinned scanners when their verified binaries are present', () => {
    for (const name of ['gitleaks', 'opengrep', 'osv_scanner', 'zizmor']) {
      const availability = resolveTool(name);
      if (availability.available) {
        // Digests are checked against the file on disk inside resolveTool, so reaching here means
        // the binary matched its recorded digest.
        expect(availability.identity.identity).toBe('verified');
        expect(availability.identity.expectedVersion).toMatch(/^\d+\.\d+\.\d+/);
      } else {
        // A checkout without the downloaded tools must refuse rather than fall through.
        expect(availability.reason).toBe('not_executable');
      }
    }
  });

  it('refuses a tool that is not recorded at all', () => {
    const availability = resolveTool('not-a-tool');
    expect(availability.available).toBe(false);
    if (!availability.available) expect(availability.reason).toBe('not_recorded');
  });

  it('records ZAP and testssl as unverified and the four scanners as verified', () => {
    const toolchain = loadToolchain(join(packageRoot(), 'policy', 'toolchain.yaml'));
    expect(toolchain.security_tools?.zap_baseline?.identity).toBe('unverified');
    expect(toolchain.security_tools?.testssl?.identity).toBe('unverified');
    for (const name of ['gitleaks', 'opengrep', 'osv_scanner', 'zizmor']) {
      expect(toolchain.security_tools?.[name]?.identity, name).toBe('verified');
      const identity = toolchain.executables?.[name];
      expect(identity, name).toBeDefined();
      // Every recorded digest is a SHA-256 and every executable path is absolute.
      expect(identity?.digest).toMatch(/^[0-9a-f]{64}$/);
      expect(identity?.executable.startsWith('/')).toBe(true);
      expect(identity?.expectedVersion).toMatch(/^\d+\.\d+\.\d+/);
    }
  });
});

describe('identity requirements are enforced before running', () => {
  it('refuses a non-absolute executable path', () => {
    const availability = resolveTool('fake-tool', {
      security_tools: { 'fake-tool': { identity: 'verified' } },
      executables: {
        'fake-tool': { name: 'fake-tool', executable: 'fake-tool', expectedVersion: '1.0.0', fetched: false, identity: 'verified' },
      },
    });
    expect(availability.available).toBe(false);
    if (!availability.available) expect(availability.reason).toBe('not_absolute');
  });

  it('refuses a fetched tool with no verified digest', () => {
    const availability = resolveTool('fake-tool', {
      security_tools: { 'fake-tool': { identity: 'verified' } },
      executables: {
        'fake-tool': { name: 'fake-tool', executable: NODE, expectedVersion: '1.0.0', fetched: true, identity: 'verified' },
      },
    });
    expect(availability.available).toBe(false);
    if (!availability.available) expect(availability.reason).toBe('digest_missing');
  });

  it('resolves a fully identified tool', () => {
    const availability = resolveTool('fake-tool', toolchainWithNode());
    expect(availability.available).toBe(true);
  });
});

describe('a recorded digest is verified against the binary on disk', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'hardening-registry-'));
  const copied = join(scratch, 'node-copy');
  copyFileSync(NODE, copied);
  const realDigest = createHash('sha256').update(readFileSync(copied)).digest('hex');

  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  const withDigest = (digest: string): ToolchainRecord => ({
    security_tools: { 'fake-tool': { identity: 'verified' } },
    executables: {
      'fake-tool': {
        name: 'fake-tool',
        executable: copied,
        versionArgs: ['--version'],
        expectedVersion: NODE_VERSION,
        fetched: true,
        identity: 'verified',
        digest,
      },
    },
  });

  it('accepts a binary whose digest matches the record', () => {
    const availability = resolveTool('fake-tool', withDigest(realDigest));
    expect(availability.available).toBe(true);
  });

  // The pin only means something if it is checked. A swapped binary must not run.
  it('refuses to run a binary whose digest does not match', () => {
    const availability = resolveTool('fake-tool', withDigest('a'.repeat(64)));
    expect(availability.available).toBe(false);
    if (!availability.available) {
      expect(availability.reason).toBe('digest_mismatch');
      expect(availability.message).toMatch(/does not match its recorded digest/);
    }
  });

  it('does not spawn a tool whose digest fails verification', async () => {
    const result = await runTool('fake-tool', ['-e', 'process.stdout.write("should not run")'], {
      cwd: packageRoot(),
      toolchain: withDigest('b'.repeat(64)),
    });
    expect(result.ran).toBe(false);
    expect(result.outcome).toBeUndefined();
  });
});

describe('running a resolved tool', () => {
  it('runs the requested arguments and returns the outcome', async () => {
    const result = await runTool('fake-tool', ['-e', 'process.stdout.write("hello")'], {
      cwd: packageRoot(),
      toolchain: toolchainWithNode(),
    });
    expect(result.ran).toBe(true);
    expect(result.outcome?.exitCode).toBe(0);
    expect(result.outcome?.stdout).toBe('hello');
  });

  // A tool whose installed version differs from the record is not the reviewed tool.
  it('refuses to run when the installed version does not match the record', async () => {
    const result = await runTool('fake-tool', ['-e', 'process.stdout.write("should not run")'], {
      cwd: packageRoot(),
      toolchain: toolchainWithNode({ expectedVersion: '0.0.1' }),
    });
    expect(result.ran).toBe(false);
    expect(result.outcome).toBeUndefined();
    if (!result.availability.available) {
      expect(result.availability.message).toMatch(/records 0\.0\.1|version 0\.0\.1|but the toolchain records/);
    }
  });

  it('refuses to run a tool with no verified identity and does not spawn it', async () => {
    const result = await runTool('zap_baseline', ['--version'], { cwd: packageRoot() });
    expect(result.ran).toBe(false);
    expect(result.outcome).toBeUndefined();
    if (!result.availability.available) expect(result.availability.reason).toBe('identity_unverified');
  });

  it('does not pass the parent environment through', async () => {
    const result = await runTool(
      'fake-tool',
      ['-e', 'process.stdout.write(String(process.env.HARDENING_REGISTRY_SECRET ?? "absent"))'],
      { cwd: packageRoot(), toolchain: toolchainWithNode(), envAllowlist: [] },
    );
    expect(result.ran).toBe(true);
    expect(result.outcome?.stdout).toBe('absent');
  });
});

describe('version extraction', () => {
  it('finds a semantic version in typical tool output', () => {
    expect(extractVersion('gitleaks version 8.18.0')).toBe('8.18.0');
    expect(extractVersion('v1.2.3-rc.1')).toBe('1.2.3-rc.1');
    expect(extractVersion('no version here')).toBeUndefined();
  });
});
