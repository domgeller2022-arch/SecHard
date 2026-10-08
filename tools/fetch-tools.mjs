#!/usr/bin/env node
// Fetches and verifies the pinned scanner binaries for the current platform.
//
// This is a provisioning action, separate from checking, and it runs only when invoked explicitly.
// Everything it does uses the reviewed download path: an approved origin, an approved redirect
// host, a bounded size, and a SHA-256 that must match before anything is written.
//
// Order of trust (Batch R, R1):
//   1. If policy/toolchain.yaml pins the requested platform, the downloaded archive must match its
//      `archiveSha256`. The hosting API's digest is not consulted in that case; a reviewed pin wins.
//   2. Otherwise the release asset digest from the hosting API is used and the printed record is
//      labelled PROPOSED, to be reviewed and pasted into policy/toolchain.yaml before it is trusted.
// A `GITHUB_TOKEN` in the environment is sent when present so CI is not rate-limited.
//
// The executable digest is computed after extraction: an extracted binary does not share the
// archive's hash, and the executable digest is the pin checked before every run.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { downloadVerified } from '../dist/execution/download.js';
import { loadDependencyPolicy } from '../dist/execution/policy.js';
import { platformKey } from '../dist/execution/registry.js';
import { runProcess } from '../dist/execution/process.js';
import { extractVersion } from '../dist/execution/version.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const binDir = join(root, 'tools', 'bin');

const platformArgIndex = process.argv.indexOf('--platform');
const platform = platformArgIndex === -1 ? platformKey() : process.argv[platformArgIndex + 1];
if (typeof platform !== 'string' || !/^[a-z0-9]+-[a-z0-9]+$/.test(platform)) {
  console.error(`unsupported_platform: '${platform}' is not a <os>-<arch> key`);
  process.exit(2);
}

// The reviewed asset names. A platform missing from this table is refused, not guessed.
const TOOLS = [
  {
    name: 'gitleaks',
    repo: 'gitleaks/gitleaks',
    tag: 'v8.30.1',
    version: '8.30.1',
    binary: 'gitleaks',
    versionArgs: ['version'],
    assets: {
      'darwin-x64': { asset: 'gitleaks_8.30.1_darwin_x64.tar.gz', archive: 'tar.gz' },
      'darwin-arm64': { asset: 'gitleaks_8.30.1_darwin_arm64.tar.gz', archive: 'tar.gz' },
      'linux-x64': { asset: 'gitleaks_8.30.1_linux_x64.tar.gz', archive: 'tar.gz' },
      'linux-arm64': { asset: 'gitleaks_8.30.1_linux_arm64.tar.gz', archive: 'tar.gz' },
    },
  },
  {
    name: 'osv_scanner',
    repo: 'google/osv-scanner',
    tag: 'v2.6.0',
    version: '2.6.0',
    binary: 'osv-scanner',
    versionArgs: ['--version'],
    assets: {
      'darwin-x64': { asset: 'osv-scanner_darwin_amd64', archive: 'none' },
      'darwin-arm64': { asset: 'osv-scanner_darwin_arm64', archive: 'none' },
      'linux-x64': { asset: 'osv-scanner_linux_amd64', archive: 'none' },
      'linux-arm64': { asset: 'osv-scanner_linux_arm64', archive: 'none' },
    },
  },
  {
    name: 'opengrep',
    repo: 'opengrep/opengrep',
    tag: 'v1.30.0',
    version: '1.30.0',
    binary: 'opengrep',
    versionArgs: ['--version'],
    assets: {
      'darwin-x64': { asset: 'opengrep_osx_x86', archive: 'none' },
      'darwin-arm64': { asset: 'opengrep_osx_arm64', archive: 'none' },
      'linux-x64': { asset: 'opengrep_manylinux_x86', archive: 'none' },
      'linux-arm64': { asset: 'opengrep_manylinux_aarch64', archive: 'none' },
    },
  },
  {
    name: 'zizmor',
    repo: 'zizmorcore/zizmor',
    tag: 'v1.30.1',
    version: '1.30.1',
    binary: 'zizmor',
    versionArgs: ['--version'],
    assets: {
      'darwin-x64': { asset: 'zizmor-x86_64-apple-darwin.tar.gz', archive: 'tar.gz' },
      'darwin-arm64': { asset: 'zizmor-aarch64-apple-darwin.tar.gz', archive: 'tar.gz' },
      'linux-x64': { asset: 'zizmor-x86_64-unknown-linux-gnu.tar.gz', archive: 'tar.gz' },
      'linux-arm64': { asset: 'zizmor-aarch64-unknown-linux-gnu.tar.gz', archive: 'tar.gz' },
    },
  },
];

function reviewedRecord(name) {
  try {
    const toolchain = parseYaml(readFileSync(join(root, 'policy', 'toolchain.yaml'), 'utf8'));
    return toolchain.executables?.[name];
  } catch {
    return undefined;
  }
}

async function api(url) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'hardening-provisioning' };
  if (typeof process.env.GITHUB_TOKEN === 'string' && process.env.GITHUB_TOKEN.length > 0) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`GitHub API ${response.status} for ${url}`);
  return response.json();
}

async function main() {
  const policyResult = loadDependencyPolicy(join(root, 'policy', 'dependency-policy.yaml'));
  if (policyResult.policy === undefined || policyResult.issues.length > 0) {
    console.error('dependency policy is invalid; refusing to provision');
    for (const issue of policyResult.issues) console.error(' ', issue.code, issue.message);
    process.exit(2);
  }
  const policy = policyResult.policy;
  const approvedOrigins = policy.tool_downloads?.allowed_origins.map((entry) => entry.origin) ?? [];
  const redirectHosts = policy.tool_downloads?.allowed_redirect_hosts ?? [];
  const maxRedirects = policy.tool_downloads?.max_redirects ?? 3;

  if (approvedOrigins.length === 0) {
    console.error('no approved tool download origins; refusing to provision');
    process.exit(2);
  }

  console.log(`# Platform: ${platform}`);

  let failures = 0;
  let unsupported = 0;
  const records = [];

  for (const tool of TOOLS) {
    const assetForPlatform = tool.assets[platform];
    if (assetForPlatform === undefined) {
      console.error(`unsupported_platform: ${tool.name} has no reviewed asset for ${platform}; not guessing one`);
      unsupported += 1;
      continue;
    }

    const record = reviewedRecord(tool.name);
    const reviewedPlatform = record?.platforms?.[platform];
    let expectedSha256 = reviewedPlatform?.archiveSha256;
    let digestSource = 'reviewed toolchain pin';

    if (expectedSha256 === undefined) {
      const release = await api(`https://api.github.com/repos/${tool.repo}/releases/tags/${tool.tag}`);
      const asset = release.assets.find((entry) => entry.name === assetForPlatform.asset);
      if (asset === undefined) {
        console.error(`${tool.name}: asset ${assetForPlatform.asset} not found in release ${tool.tag}`);
        failures += 1;
        continue;
      }
      expectedSha256 = String(asset.digest ?? '').replace(/^sha256:/, '');
      digestSource = 'release asset digest (PROPOSED, not yet reviewed)';
    }
    if (!/^[0-9a-f]{64}$/.test(expectedSha256 ?? '')) {
      console.error(`${tool.name}: no usable digest for ${assetForPlatform.asset}; refusing`);
      failures += 1;
      continue;
    }

    const dir = join(binDir, tool.name, String(tool.version), platform);
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });

    const downloaded = join(dir, assetForPlatform.asset);
    const result = await downloadVerified({
      url: `https://github.com/${tool.repo}/releases/download/${tool.tag}/${assetForPlatform.asset}`,
      expectedSha256,
      destination: downloaded,
      policy,
      maxBytes: 300 * 1024 * 1024,
      approvedOrigins,
      allowedHosts: redirectHosts,
      followRedirects: true,
      maxRedirects,
    });

    if (!result.ok) {
      console.error(`${tool.name}: download failed: ${result.reason}: ${result.message}`);
      failures += 1;
      continue;
    }

    const binary = join(dir, tool.binary);
    if (assetForPlatform.archive === 'tar.gz') {
      execFileSync('tar', ['-xzf', downloaded, '-C', dir], { timeout: 120_000 });
      rmSync(downloaded, { force: true });
      chmodSync(binary, 0o755);
    } else {
      execFileSync('mv', [downloaded, binary], { timeout: 30_000 });
      chmodSync(binary, 0o755);
    }

    let observed;
    if (platform === platformKey()) {
      const versionOutcome = await runProcess({
        executable: binary,
        args: tool.versionArgs,
        cwd: dir,
        timeoutMs: 60_000,
        maxOutputBytes: 256 * 1024,
      });
      observed = extractVersion(`${versionOutcome.stdout}\n${versionOutcome.stderr}`);
      if (observed === undefined || observed !== tool.version) {
        console.error(`${tool.name}: the binary reports '${observed ?? 'unknown'}', expected ${tool.version}; refusing to record it`);
        failures += 1;
        continue;
      }
    }

    const executableDigest = createHash('sha256').update(readFileSync(binary)).digest('hex');
    records.push({
      tool,
      platform,
      asset: assetForPlatform,
      archiveSha256: expectedSha256,
      digestSource,
      digest: executableDigest,
      observed,
    });
  }

  if (records.length > 0) {
    console.log('\n# Generated by tools/fetch-tools.mjs. Paste under `executables:`.');
    for (const entry of records) {
      console.log(`      ${entry.platform}:  # ${entry.tool.name}`);
      console.log(`        asset: ${entry.asset.asset}`);
      console.log(`        binary: ${entry.tool.binary}`);
      console.log(`        archive: ${entry.asset.archive}`);
      console.log(`        archiveSha256: "${entry.archiveSha256}"`);
      console.log(`        digest: "${entry.digest}"`);
      console.log(`        expectedVersion: "${entry.tool.version}"`);
      console.log(`        versionProvenance: "${entry.observed === undefined ? 'release tag; runTool verifies it on first run on this platform' : `observed by running the binary on ${entry.platform}`}"`);
      console.log(`        provenance: "${entry.digestSource}"`);
    }
  }

  console.log(`\n# ${records.length} tool(s) verified on ${platform}; ${failures} failure(s); ${unsupported} unsupported.`);
  if (unsupported === TOOLS.length) process.exit(2);
  if (failures > 0 || unsupported > 0) process.exit(1);
}

await main();
