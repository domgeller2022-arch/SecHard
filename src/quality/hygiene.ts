import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '../domain/types.js';

/**
 * QUAL-11 (repository hygiene) and QUAL-12 (dependency health): SecHard-owned checks over the
 * repository's own artifacts. Presence checks cannot prove the CI is green or the README truthful
 * — the findings say "present or missing", and the report states the boundary.
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
    return { findings: [], packagesExamined: 0 };
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
