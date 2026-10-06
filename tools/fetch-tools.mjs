#!/usr/bin/env node
// Fetches and verifies the pinned scanner binaries.
//
// This is a provisioning action, separate from checking, and it runs only when invoked explicitly.
// Everything it does uses the reviewed download path: an approved origin, an approved redirect
// host, a bounded size, and a SHA-256 that must match before anything is written.
//
// Digests come from the hosting API's release-asset digest, cross-checked against a
// publisher-published checksums file where one exists. Where no checksums file exists that weaker
// provenance is printed, not hidden.
//
// It prints the identity records to place in policy/toolchain.yaml. It does not rewrite that file:
// the toolchain record is reviewed policy and is edited deliberately.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { downloadVerified } from '../dist/execution/download.js';
import { loadDependencyPolicy } from '../dist/execution/policy.js';
import { runProcess } from '../dist/execution/process.js';
import { extractVersion } from '../dist/execution/version.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const binDir = join(root, 'tools', 'bin');

const TOOLS = [
  {
    name: 'gitleaks',
    repo: 'gitleaks/gitleaks',
    tag: 'v8.30.1',
    asset: 'gitleaks_8.30.1_darwin_x64.tar.gz',
    checksums: 'gitleaks_8.30.1_checksums.txt',
    archive: 'tar.gz',
    binary: 'gitleaks',
    versionArgs: ['version'],
    purpose: 'Repository and history secret detection',
  },
  {
    name: 'osv_scanner',
    repo: 'google/osv-scanner',
    tag: 'v2.6.0',
    asset: 'osv-scanner_darwin_amd64',
    checksums: 'osv-scanner_SHA256SUMS',
    archive: 'none',
    binary: 'osv-scanner',
    versionArgs: ['--version'],
    purpose: 'Dependency advisories',
  },
  {
    name: 'opengrep',
    repo: 'opengrep/opengrep',
    tag: 'v1.30.0',
    asset: 'opengrep_osx_x86',
    checksums: null,
    archive: 'none',
    binary: 'opengrep',
    versionArgs: ['--version'],
    purpose: 'Static analysis for the reference stack',
  },
  {
    name: 'zizmor',
    repo: 'zizmorcore/zizmor',
    tag: 'v1.30.1',
    asset: 'zizmor-x86_64-apple-darwin.tar.gz',
    checksums: null,
    archive: 'tar.gz',
    binary: 'zizmor',
    versionArgs: ['--version'],
    purpose: 'GitHub workflow analysis',
  },
];

async function api(url) {
  const response = await fetch(url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'hardening-provisioning' } });
  if (!response.ok) throw new Error(`GitHub API ${response.status} for ${url}`);
  return response.json();
}

async function publisherChecksum(tool, assetDigest) {
  if (tool.checksums === null) return { source: 'none', agrees: null };
  const url = `https://github.com/${tool.repo}/releases/download/${tool.tag}/${tool.checksums}`;
  const response = await fetch(url, { headers: { 'user-agent': 'hardening-provisioning' } });
  if (!response.ok) return { source: 'unavailable', agrees: null };
  const text = await response.text();
  const line = text.split('\n').find((entry) => entry.includes(tool.asset));
  if (line === undefined) return { source: 'no-entry', agrees: null };
  const digest = line.trim().split(/\s+/)[0];
  return { source: 'publisher_checksums_file', agrees: digest === assetDigest, digest };
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

  const identities = [];

  for (const tool of TOOLS) {
    const release = await api(`https://api.github.com/repos/${tool.repo}/releases/tags/${tool.tag}`);
    const asset = release.assets.find((entry) => entry.name === tool.asset);
    if (asset === undefined) {
      console.error(`${tool.name}: asset ${tool.asset} not found in release ${tool.tag}`);
      process.exit(1);
    }
    const assetDigest = String(asset.digest ?? '').replace(/^sha256:/, '');
    if (!/^[0-9a-f]{64}$/.test(assetDigest)) {
      console.error(`${tool.name}: release asset has no usable digest; refusing to use it`);
      process.exit(1);
    }

    const cross = await publisherChecksum(tool, assetDigest);
    if (cross.agrees === false) {
      console.error(`${tool.name}: publisher checksum file disagrees with the release asset digest; refusing`);
      process.exit(1);
    }

    const dir = join(binDir, tool.name, tool.tag);
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });

    const downloaded = join(dir, tool.asset);
    const result = await downloadVerified({
      url: `https://github.com/${tool.repo}/releases/download/${tool.tag}/${tool.asset}`,
      expectedSha256: assetDigest,
      destination: downloaded,
      policy,
      maxBytes: 200 * 1024 * 1024,
      approvedOrigins,
      allowedHosts: redirectHosts,
      followRedirects: true,
      maxRedirects,
    });

    if (!result.ok) {
      console.error(`${tool.name}: download failed: ${result.reason}: ${result.message}`);
      process.exit(1);
    }

    const binary = join(dir, tool.binary);
    if (tool.archive === 'tar.gz') {
      execFileSync('tar', ['-xzf', downloaded, '-C', dir], { timeout: 120_000 });
      chmodSync(binary, 0o755);
    } else {
      execFileSync('mv', [downloaded, binary], { timeout: 30_000 });
      chmodSync(binary, 0o755);
    }

    const versionOutcome = await runProcess({
      executable: binary,
      args: tool.versionArgs,
      cwd: dir,
      timeoutMs: 60_000,
      maxOutputBytes: 256 * 1024,
    });
    const observed = extractVersion(`${versionOutcome.stdout}\n${versionOutcome.stderr}`);

    // The registry verifies the digest of the file it executes. For an archive that is NOT the
    // digest of the download, so both are recorded: the archive digest as provenance of the
    // verified download, and the executable digest as the pin that is checked before every run.
    const executableDigest = createHash('sha256').update(readFileSync(binary)).digest('hex');

    identities.push({
      tool,
      path: binary,
      digest: executableDigest,
      archiveSha256: result.sha256,
      observed,
      provenance: cross.source === 'publisher_checksums_file' ? 'publisher checksums file cross-checked with the release asset digest' : 'release asset digest only (no publisher checksums file)',
      crossChecked: cross.agrees === true,
      versionExit: versionOutcome.exitCode,
    });
  }

  console.log('\n# ---------------------------------------------------------------------------');
  console.log('# Generated by tools/fetch-tools.mjs on ' + new Date().toISOString());
  console.log('# Place under `executables:` in policy/toolchain.yaml, and set the matching');
  console.log('# security_tools entry to identity: verified.');
  console.log('# ---------------------------------------------------------------------------');
  for (const entry of identities) {
    console.log(`  ${entry.tool.name}:`);
    console.log(`    name: ${entry.tool.name}`);
    console.log(`    executable: "${entry.path}"`);
    console.log(`    versionArgs: [${entry.tool.versionArgs.map((a) => `"${a}"`).join(', ')}]`);
    console.log(`    expectedVersion: "${entry.observed ?? 'UNKNOWN'}"`);
    if (entry.tool.archive === 'tar.gz') console.log(`    archiveSha256: "${entry.archiveSha256}"`);
    console.log(`    digest: "${entry.digest}"`);
    console.log(`    fetched: true`);
    console.log(`    identity: verified`);
    console.log(`    source: "https://github.com/${entry.tool.repo}/releases/tag/${entry.tool.tag}"`);
    console.log(`    provenance: "${entry.provenance}"`);
  }
  console.log('\n# Observed versions:');
  for (const entry of identities) {
    console.log(`#   ${entry.tool.name} -> ${entry.observed ?? 'could not be determined'} (exit ${entry.versionExit})`);
  }
  console.log('\n# Provenance summary:');
  for (const entry of identities) {
    console.log(`#   ${entry.tool.name}: ${entry.provenance}`);
  }
}

await main();
