import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '../domain/types.js';

/**
 * QUAL-11 (repository hygiene) and QUAL-12 (dependency health): SecHard-owned checks over the
 * repository's own artifacts. Presence checks cannot prove the CI is green or the README truthful
 * — the findings say "present or missing", and the report states the boundary. The registry
 * health route (P4.3) adds bounded reviewed queries whose failures are unknown, never healthy.
 */

export interface HygieneResult {
  readonly findings: Finding[];
  readonly checks: number;
}

function hygieneFinding(ruleId: string, severity: Finding['severity'], what: string, fix: string): Finding {
  return {
    id: `quality:repo-hygiene:${ruleId}`,
    tool: 'quality-repo-hygiene',
    rule_id: ruleId,
    severity,
    title: what,
    detail: fix,
    location: '.',
    control_ids: ['QUAL-11'],
    triage: 'unresolved',
  };
}

export function analyzeRepoHygiene(root: string, expectedLockfiles: readonly string[]): HygieneResult {
  const findings: Finding[] = [];
  let checks = 0;

  const hasLockfile = expectedLockfiles.some((name) => existsSync(join(root, name)));
  checks += 1;
  if (!hasLockfile) {
    findings.push(hygieneFinding('no-lockfile', 'medium',
      'no supported lockfile is committed',
      `Commit a lockfile (${expectedLockfiles.slice(0, 4).join(', ')}, …) so installs are reproducible and advisory scans have a full graph to cover.`));
  }

  checks += 1;
  if (!existsSync(join(root, '.gitignore'))) {
    findings.push(hygieneFinding('no-gitignore', 'medium',
      'no .gitignore file; nothing keeps secrets and build output out of commits',
      'Add a .gitignore that at minimum excludes dependency directories (.gitignore patterns for node_modules, venv), build output, and environment files (.env*).'));
  } else {
    const gitignore = readFileSync(join(root, '.gitignore'), 'utf8').toLowerCase();
    if (!gitignore.includes('node_modules') && !gitignore.includes('venv') && !gitignore.includes('/vendor')) {
      checks += 1;
      findings.push(hygieneFinding('gitignore-missing-dependencies', 'low',
        '.gitignore does not exclude dependency directories',
        'Add the dependency directory (node_modules, venv, vendor) to .gitignore; committed dependencies make every diff meaningless.'));
    }
    if (!gitignore.includes('.env')) {
      checks += 1;
      findings.push(hygieneFinding('gitignore-missing-env', 'low',
        '.gitignore does not exclude environment files',
        'Add .env* to .gitignore; environment files are where credentials live and they must never be committable by accident.'));
    }
  }

  checks += 1;
  if (!existsSync(join(root, 'README.md'))) {
    findings.push(hygieneFinding('no-readme', 'low',
      'no README; a newcomer (or you, in six months) has no entry point',
      'Add a README that states what the project is, how to run it, and what "done" means.'));
  }

  checks += 1;
  if (!existsSync(join(root, 'CHANGELOG.md'))) {
    findings.push(hygieneFinding('no-changelog', 'low',
      'no CHANGELOG; changes are invisible between releases',
      'Add a CHANGELOG (Keep a Changelog format works) so a release can say what actually changed.'));
  }

  const workflows = join(root, '.github', 'workflows');
  const hasWorkflows = existsSync(workflows) && readdirSync(workflows).some((name) => name.endsWith('.yml') || name.endsWith('.yaml'));
  checks += 1;
  if (!hasWorkflows && !existsSync(join(root, '.gitlab-ci.yml')) && !existsSync(join(root, '.circleci', 'config.yml'))) {
    findings.push(hygieneFinding('no-ci', 'medium',
      'no CI configuration; nothing checks commits automatically',
      'Add a CI workflow that builds, tests, and runs the security checks on every pull request.'));
  }

  checks += 1;
  if (!existsSync(join(root, 'LICENSE')) && !existsSync(join(root, 'LICENSE.md')) && !existsSync(join(root, 'LICENSE.txt'))) {
    findings.push(hygieneFinding('no-licence', 'low',
      'no LICENSE file. If the absence is deliberate (private, undistributed), that decision must be recorded alongside it — an unrecorded absence is indistinguishable from an oversight',
      'Choose a licence, or record the deliberate decision (owner decisions, README) so the absence is a documented choice rather than a gap.'));
  }


  // P4.3: generated build artifacts must not be committed — they drift from their sources and
  // bloat every clone. A directory named in .gitignore is not committed; the bounded pattern
  // read keeps this static and honest about its own limits.
  const gitignoreText = existsSync(join(root, '.gitignore')) ? readFileSync(join(root, '.gitignore'), 'utf8') : '';
  for (const dir of ['dist', '.next', 'build', 'out']) {
    const full = join(root, dir);
    if (!existsSync(full) || !statSync(full).isDirectory()) continue;
    if (readdirSync(full).length === 0) continue;
    if (new RegExp(`(?:^|/)${dir.replace('.', '\\.')}(?:$|/)`, 'm').test(gitignoreText)) continue;
    checks += 1;
    findings.push(hygieneFinding('generated-artifacts-committed', 'low',
      `the generated '${dir}/' directory appears to be committed`,
      `Add ${dir}/ to .gitignore and remove it from version control; generated output drifts from its sources and bloats every clone.`));
  }

  // P4.3: licence-description accuracy — a README claiming an open-source licence without a
  // committed LICENSE file misdescribes the repository's status. An owner's private/no-licence
  // choice is described accurately and never relabelled as public open-source readiness.
  const readmePath = join(root, 'README.md');
  const claimsOpenLicence = existsSync(readmePath)
    && /\b(MIT|Apache|GPL|BSD|ISC)\s+Licen[cs]e\b|\bopen[- ]source\b/i.test(readFileSync(readmePath, 'utf8'));
  const hasLicenceFile = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE'].some((name) => existsSync(join(root, name)));
  if (claimsOpenLicence && !hasLicenceFile) {
    checks += 1;
    findings.push(hygieneFinding('licence-description-mismatch', 'low',
      'the README describes an open-source licence but no LICENSE file is committed',
      'Recipients have no enforceable terms. Add the licence file, or describe the private/no-licence status accurately instead of claiming open-source readiness.'));
  }

  const readmeScripts = advertisedReadmeScripts(root);
  if (readmeScripts.phantom.length > 0) {
    const readmeFinding = hygieneFinding('readme-phantom-scripts', 'medium',
      `the README advertises ${readmeScripts.phantom.map((name) => `"${name}"`).join(', ')}, which ${readmeScripts.phantom.length === 1 ? 'is' : 'are'} not in package.json scripts`,
      'Remove the commands from the README or add the scripts to package.json. A documented command that fails on first use is how trust in the documentation dies.');
    findings.push({ ...readmeFinding, location: 'README.md' });
  }

  return { findings, checks };
}

// --- QUAL-12: dependency health ---------------------------------------------------------

export interface DependencyHealthResult {
  readonly findings: Finding[];
  readonly packagesExamined: number;
}

interface LockfilePackages {
  readonly names: readonly string[];
  readonly source: string;
}

function readLockfilePackageNames(root: string, expectedLockfiles: readonly string[]): LockfilePackages | undefined {
  for (const name of expectedLockfiles) {
    const file = join(root, name);
    if (!existsSync(file)) continue;
    try {
      if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as { packages?: Record<string, unknown> };
        const names = Object.keys(parsed.packages ?? {})
          .filter((key) => key.startsWith('node_modules/') && !key.includes('node_modules/') || key.split('node_modules/').length === 2)
          .map((key) => key.split('node_modules/').pop() ?? '')
          .filter((pkg) => pkg.length > 0);
        return { names, source: name };
      }
      if (name === 'yarn.lock') {
        const text = readFileSync(file, 'utf8');
        const names = [...text.matchAll(/^"?([^@"\s]+)@[^"]*"?:$/gm)].map((match) => match[1]?.replace(/^@?\w+\//, (m) => m) ?? '');
        const scoped = names.map((entry) => entry.replace(/^.*:/, ''));
        return { names: scoped.filter((entry) => entry.length > 0), source: name };
      }
      if (name === 'pnpm-lock.yaml') {
        const text = readFileSync(file, 'utf8');
        const names = [...text.matchAll(/^\s{2}'?([@a-z0-9/.-]+)@/gm)].map((match) => match[1] ?? '');
        return { names: [...new Set(names)], source: name };
      }
      if (name === 'requirements.txt') {
        const names = readFileSync(file, 'utf8').split(/\r?\n/)
          .map((line) => line.trim().split('==')[0]?.split('>=')[0]?.split('~=')[0]?.split('<')[0]?.split('>')[0]?.split('[')[0]?.trim() ?? '')
          .filter((entry) => entry.length > 0 && !entry.startsWith('#') && !entry.startsWith('-'));
        return { names, source: name };
      }
      if (name === 'go.mod') {
        const names = [...readFileSync(file, 'utf8').matchAll(/^\s*(?:require\s+)?([\w./-]+)\s+v[\w.-]+/gm)].map((match) => match[1] ?? '');
        return { names: [...new Set(names)].filter((entry) => !entry.startsWith('github.com/golang')), source: name };
      }
      if (name === 'Cargo.lock') {
        const text = readFileSync(file, 'utf8');
        const names = [...text.matchAll(/^name = "([^"]+)"/gm)].map((match) => match[1] ?? '');
        return { names, source: name };
      }
      if (name === 'composer.lock') {
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as { packages?: { name?: string }[] };
        return { names: (parsed.packages ?? []).map((entry) => entry.name ?? '').filter((entry) => entry.length > 0), source: name };
      }
    } catch {
      // An unreadable lockfile is reported by the advisory recipe; this analyser skips it.
      return undefined;
    }
  }
  return undefined;
}

export function analyzeDependencyHealth(root: string, expectedLockfiles: readonly string[], equivalentRoles: readonly { role: string; packages: readonly string[] }[]): DependencyHealthResult {
  const lockfile = readLockfilePackageNames(root, expectedLockfiles);
  if (lockfile === undefined) {
    // F-07: the no-lockfile variant. The role check still runs against package.json's declared
    // dependencies — an app that declares moment and dayjs has the problem whether or not a
    // lockfile was committed. The source is recorded honestly as package.json.
    const declared = readPackageJsonDependencies(root);
    if (declared.size === 0) return { findings: [], packagesExamined: 0 };
    const findings: Finding[] = [];
    for (const role of equivalentRoles) {
      const members = role.packages.filter((pkg) => declared.has(pkg.toLowerCase()));
      if (members.length >= 2) {
        findings.push({
          id: `quality:dependency-health:duplicate-role:${role.role}:package-json`,
          tool: 'quality-dependency-health',
          rule_id: 'duplicate-role',
          severity: 'medium',
          title: `two or more libraries for one job: ${members.join(', ')} all provide "${role.role}"`,
          location: 'package.json',
          detail: 'Pick one and remove the rest. Every extra library is another advisory surface, another install hook, and two ways to do the same thing for every future reader.',
          control_ids: ['QUAL-12'],
          triage: 'unresolved',
        });
      }
    }
    return { findings, packagesExamined: declared.size };
  }

  const present = new Set(lockfile.names.map((name) => name.toLowerCase().replace(/^@types\//, '').replace(/^@[^/]+\//, (match) => match)));
  const presentFull = new Set(lockfile.names.map((name) => name.toLowerCase()));
  const findings: Finding[] = [];

  for (const role of equivalentRoles) {
    const members: string[] = [];
    for (const pkg of role.packages) {
      if (presentFull.has(pkg.toLowerCase()) || present.has(pkg.toLowerCase().replace(/^@[^/]+\//, ''))) {
        members.push(pkg);
      }
    }
    if (members.length >= 2) {
      findings.push({
        id: `quality:dependency-health:duplicate-role:${role.role}`,
        tool: 'quality-dependency-health',
        rule_id: 'duplicate-role',
        severity: 'medium',
        title: `two or more libraries for one job: ${members.join(', ')} all provide "${role.role}"`,
        location: lockfile.source,
        detail: 'Pick one and remove the rest. Every extra library is another advisory surface, another install hook, and two ways to do the same thing for every future reader.',
        control_ids: ['QUAL-12'],
        triage: 'unresolved',
      });
    }
  }

  return { findings, packagesExamined: lockfile.names.length };
}

/** Scripts a README advertises through npm/pnpm/yarn run spans (F-07). */
function advertisedReadmeScripts(root: string): { readonly phantom: readonly string[] } {
  let text: string | undefined;
  for (const name of ['README.md', 'readme.md', 'Readme.md']) {
    try {
      const candidate = join(root, name);
      if (existsSync(candidate)) {
        text = readFileSync(candidate, 'utf8').slice(0, 256 * 1024);
        break;
      }
    } catch {
      continue;
    }
  }
  if (text === undefined) return { phantom: [] };
  let scripts: ReadonlySet<string> = new Set();
  try {
    const raw = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { scripts?: Record<string, string> };
    scripts = new Set(Object.keys(raw.scripts ?? {}));
  } catch {
    return { phantom: [] };
  }
  const advertised = new Set<string>();
  const runPattern = /(?:npm|pnpm|yarn)\s+(?:run\s+)?([a-z0-9:@_\/-]+)/gi;
  for (const match of text.matchAll(runPattern)) {
    const name = match[1]?.trim();
    if (name === undefined || name === '') continue;
    // Lifecycle commands exist without a scripts entry.
    if (['install', 'test', 'start', 'dev', 'build', 'ci'].includes(name)) continue;
    if (name.includes('install') || name.includes('add') || name.includes('publish')) continue;
    advertised.add(name);
  }
  const phantom = [...advertised].filter((name) => !scripts.has(name)).sort();
  return { phantom };
}

/** Declared dependencies from package.json, lowercased (F-07 no-lockfile role check). */
function readPackageJsonDependencies(root: string): ReadonlySet<string> {
  try {
    const raw = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return new Set([...Object.keys(raw.dependencies ?? {}), ...Object.keys(raw.devDependencies ?? {})].map((name) => name.toLowerCase()));
  } catch {
    return new Set();
  }
}

// --- QUAL-12: registry health (P4.3) ---------------------------------------------------

export interface RegistryHealthResult {
  readonly findings: Finding[];
  readonly queries: number;
  readonly unknown: readonly string[];
}

interface RegistryDoc {
  readonly 'dist-tags'?: { readonly latest?: string };
  readonly versions?: Record<string, { readonly deprecated?: string }>;
  readonly time?: Record<string, string>;
}

const REGISTRY_QUERY_BOUND = 60;
const REGISTRY_STALE_DAYS = 730;

function readDeclaredRanges(root: string): Map<string, string> {
  try {
    const raw = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const ranges = new Map<string, string>();
    for (const [name, range] of [...Object.entries(raw.dependencies ?? {}), ...Object.entries(raw.devDependencies ?? {})]) {
      if (range !== undefined) ranges.set(name.toLowerCase(), range);
    }
    return ranges;
  } catch {
    return new Map();
  }
}

/**
 * QUAL-12 (P4.3): registry health from bounded reviewed queries against the approved registry —
 * existence, deprecation, major drift and staleness. Offline or failed queries are recorded as
 * unknown, never as evidence that a package is healthy, and this never replaces OSV advisory
 * scanning. The query bound keeps an audit's egress to a reviewed maximum; packages beyond it
 * are recorded as unknown.
 */
export async function analyzeRegistryHealth(root: string, expectedLockfiles: readonly string[], fetchImpl: typeof fetch = fetch): Promise<RegistryHealthResult> {
  const lockfile = readLockfilePackageNames(root, expectedLockfiles);
  if (lockfile === undefined) return { findings: [], queries: 0, unknown: ['no supported lockfile — registry health is unknown'] };
  const npmEcosystem = lockfile.source === 'package-lock.json' || lockfile.source === 'pnpm-lock.yaml' || lockfile.source === 'yarn.lock';
  if (!npmEcosystem) {
    return { findings: [], queries: 0, unknown: [`${lockfile.source}: the registry health route covers npm packages; this ecosystem's registry route is a recorded gap`] };
  }
  const declared = readDeclaredRanges(root);
  const findings: Finding[] = [];
  const unknown: string[] = [];
  let queries = 0;
  for (const name of lockfile.names.slice(0, REGISTRY_QUERY_BOUND)) {
    queries += 1;
    try {
      const response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) {
        unknown.push(`${name}: the registry responded ${String(response.status)}`);
        continue;
      }
      const doc = JSON.parse(await response.text()) as RegistryDoc;
      const latest = doc['dist-tags']?.latest;
      const latestEntry = latest === undefined ? undefined : doc.versions?.[latest];
      if (latestEntry?.deprecated !== undefined) {
        findings.push({
          id: `quality:dependency-health:registry-deprecated:${name}`,
          tool: 'quality-dependency-health',
          rule_id: 'registry-deprecated',
          severity: 'medium',
          title: `The latest release of ${name} is deprecated.`,
          detail: `The registry marks ${name}@${latest ?? '?'} deprecated: ${latestEntry.deprecated} — plan the migration the deprecation message names.`,
          location: lockfile.source,
          control_ids: ['QUAL-12'],
          triage: 'unresolved',
        });
      }
      const range = declared.get(name);
      const declaredMajor = range === undefined ? undefined : /^\^?(\d+)/.exec(range)?.[1];
      const latestMajor = latest === undefined ? undefined : /^(\d+)/.exec(latest)?.[1];
      if (declaredMajor !== undefined && latestMajor !== undefined && Number(latestMajor) - Number(declaredMajor) >= 2) {
        findings.push({
          id: `quality:dependency-health:registry-major-drift:${name}`,
          tool: 'quality-dependency-health',
          rule_id: 'registry-major-drift',
          severity: 'low',
          title: `${name} is ${String(Number(latestMajor) - Number(declaredMajor))} major versions behind the latest published release.`,
          detail: `The declared range (${range}) resolves to major ${declaredMajor}; the registry's latest is ${latest}. Major drift compounds — schedule the upgrade before the gap grows.`,
          location: 'package.json',
          control_ids: ['QUAL-12'],
          triage: 'unresolved',
        });
      }
      const publishedAt = latest === undefined ? undefined : doc.time?.[latest];
      const publishedTime = publishedAt === undefined ? undefined : Date.parse(publishedAt);
      if (publishedTime !== undefined && Date.now() - publishedTime > REGISTRY_STALE_DAYS * 24 * 60 * 60 * 1000) {
        findings.push({
          id: `quality:dependency-health:registry-stale:${name}`,
          tool: 'quality-dependency-health',
          rule_id: 'registry-stale',
          severity: 'low',
          title: `${name}'s latest release is more than ${String(Math.floor(REGISTRY_STALE_DAYS / 30))} months old.`,
          detail: `The latest published release (${latest ?? '?'}, ${publishedAt ?? '?'}) is stale by the reviewed threshold; unmaintained dependencies stop receiving fixes. Verify the project is actually abandoned before acting.`,
          location: lockfile.source,
          control_ids: ['QUAL-12'],
          triage: 'unresolved',
        });
      }
    } catch (error) {
      unknown.push(`${name}: the registry query failed (${error instanceof Error ? error.message : 'unknown error'})`);
    }
  }
  if (lockfile.names.length > REGISTRY_QUERY_BOUND) {
    unknown.push(`${String(lockfile.names.length - REGISTRY_QUERY_BOUND)} package(s) beyond the query bound were not checked`);
  }
  return { findings, queries, unknown };
}
