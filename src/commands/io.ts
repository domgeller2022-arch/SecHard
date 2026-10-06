import { readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { ValidationError, type ValidationIssue } from '../validation/errors.js';
import { loadDocument } from '../validation/loader.js';
import { confineToRoot, type ConfinedPath } from '../validation/paths.js';
import { validateAgainstSchema } from '../validation/schema.js';
import { checkDuplicateIds, checkReference } from '../validation/semantic.js';
import { loadCatalogue, type ControlDefinition, type Profile } from '../domain/definitions.js';
import { sha256Hex } from '../evidence/digest.js';
import type { ExceptionRecord, GatePolicy, ManualEvidence } from '../domain/types.js';
import type { ManifestRecord } from '../domain/types.js';

export interface Paths {
  readonly appRoot: string;
  readonly policyRoot: string;
  readonly runDir?: string;
  readonly planPath?: string;
}

export interface LoadedPolicy {
  readonly policy: GatePolicy;
  readonly gatePolicyDigest: string;
  readonly controlCatalogueDigest: string;
  readonly profiles: readonly Profile[];
  readonly profileDigests: Readonly<Record<string, string>>;
  readonly controls: readonly ControlDefinition[];
  readonly policyCommit: string;
}

export interface LoadedConsumer {
  readonly manifest?: ManifestRecord;
  readonly manifestDigest?: string;
  readonly exceptions: readonly ExceptionRecord[];
  readonly manualEvidence: readonly ManualEvidence[];
}

export interface LoadOutcome<T> {
  readonly value?: T;
  readonly issues: readonly ValidationIssue[];
}

const CONSUMER_FILES = {
  manifest: '.hardening/app.yaml',
  assessments: '.hardening/assessments.yaml',
  exceptions: '.hardening/exceptions.yaml',
  manualEvidence: '.hardening/manual-evidence.yaml',
  policyLock: '.hardening/policy-lock.json',
} as const;

/**
 * Loads the repository's own policy inputs. These are authoritative: a failure here is a defect in
 * this repository, and reporting it as an application error would be misleading.
 */
export function loadPolicy(paths: Paths): LoadOutcome<LoadedPolicy> {
  const issues: ValidationIssue[] = [];
  const policyRoot = paths.policyRoot;

  const gatePolicyPath = join(policyRoot, 'policy', 'gate-policy.yaml');
  const gate = loadDocument<GatePolicy>(gatePolicyPath);
  issues.push(...gate.issues);
  if (gate.data === undefined) return { issues };

  const controls: ControlDefinition[] = [...loadCatalogue().controls];
  const controlFile = join(policyRoot, 'controls', 'controls.yaml');
  const rawControls = loadDocument(controlFile);
  issues.push(...rawControls.issues);
  if (rawControls.data !== undefined) {
    const schemaResult = validateAgainstSchema('control-catalogue', rawControls.data, controlFile);
    issues.push(...schemaResult.issues);
    if (schemaResult.valid) {
      issues.push(...checkDuplicateIds((rawControls.data as { controls: { id: string }[] }).controls.map((c) => c.id), controlFile));
    }
  }

  const profiles: Profile[] = [];
  const profileDigests: Record<string, string> = {};
  for (const id of ['core', 'nextjs-supabase']) {
    const file = join(policyRoot, 'profiles', `${id}.yaml`);
    const loaded = loadDocument<Profile>(file);
    issues.push(...loaded.issues);
    if (loaded.data === undefined) continue;
    const result = validateAgainstSchema('profile', loaded.data, file);
    issues.push(...result.issues);
    profiles.push(loaded.data);
    profileDigests[id] = loaded.rawDigest;
  }

  const controlCatalogueDigest = sha256Hex(
    controls.map((control) => `${control.id}@${control.definition_version}:${control.review_status}`).join('\n'),
  );

  const knownControls = new Set(controls.map((control) => control.id));
  for (const profile of profiles) {
    for (const entry of profile.controls) {
      issues.push(...checkReference(entry.control, { known: knownControls, kind: 'control', file: `profiles/${profile.id}.yaml` }));
    }
    const governed = new Set(profile.permitted_exceptions.map((entry) => entry.control));
    for (const entry of profile.controls) {
      if (!governed.has(entry.control)) {
        issues.push({
          code: 'semantic.unknown_reference',
          message: `profile ${profile.id} selects ${entry.control} but declares no exception policy for it`,
          file: `profiles/${profile.id}.yaml`,
        });
      }
    }
  }

  return {
    value: {
      policy: gate.data,
      gatePolicyDigest: gate.rawDigest,
      controlCatalogueDigest,
      profiles,
      profileDigests,
      controls,
      policyCommit: resolvePolicyCommit(policyRoot),
    },
    issues,
  };
}

export function loadConsumer(paths: Paths, selectedProfiles: readonly string[]): LoadOutcome<LoadedConsumer> {
  const issues: ValidationIssue[] = [];
  let manifest: ManifestRecord | undefined;
  let manifestDigest: string | undefined;

  const manifestFile = join(paths.appRoot, CONSUMER_FILES.manifest);
  const loadedManifest = loadDocument(manifestFile);
  if (loadedManifest.issues.length > 0) {
    // A missing or unparsable manifest is reported on its own. Continuing would produce a wall of
    // derived complaints that all trace back to this one missing record.
    if (loadedManifest.issues[0]?.code === 'input.not_found') {
      return { issues: loadedManifest.issues, value: { exceptions: [], manualEvidence: [] } };
    }
    issues.push(...loadedManifest.issues);
  } else if (loadedManifest.data !== undefined) {
    const result = validateAgainstSchema('app', loadedManifest.data, manifestFile);
    issues.push(...result.issues);
    if (result.valid) {
      manifest = loadedManifest.data as unknown as ManifestRecord;
      manifestDigest = loadedManifest.rawDigest;
      for (const profileId of manifest.profiles) {
        issues.push(...checkReference(profileId, { known: new Set(selectedProfiles), kind: 'profile', file: manifestFile }));
      }
    }
  }

  const exceptions: ExceptionRecord[] = [];
  const exceptionsFile = join(paths.appRoot, CONSUMER_FILES.exceptions);
  const loadedExceptions = loadDocument<{ exceptions?: ExceptionRecord[] }>(exceptionsFile);
  if (loadedExceptions.issues.length === 0 && loadedExceptions.data?.exceptions !== undefined) {
    for (const record of loadedExceptions.data.exceptions) {
      const result = validateAgainstSchema('exception', record, exceptionsFile);
      issues.push(...result.issues);
      if (result.valid) exceptions.push(record);
    }
    issues.push(...checkDuplicateIds(loadedExceptions.data.exceptions.map((record) => record.id), exceptionsFile));
  }

  const manualEvidence: ManualEvidence[] = [];
  const manualFile = join(paths.appRoot, CONSUMER_FILES.manualEvidence);
  const loadedManual = loadDocument<{ records?: ManualEvidence[] }>(manualFile);
  if (loadedManual.issues.length === 0 && loadedManual.data?.records !== undefined) {
    for (const record of loadedManual.data.records) {
      const result = validateAgainstSchema('manual-evidence', record, manualFile);
      issues.push(...result.issues);
      if (result.valid) manualEvidence.push(record);
    }
    issues.push(...checkDuplicateIds(loadedManual.data.records.map((record) => record.id), manualFile));
  }

  return { value: { ...(manifest === undefined ? {} : { manifest }), ...(manifestDigest === undefined ? {} : { manifestDigest }), exceptions, manualEvidence }, issues };
}

export interface SourceIdentity {
  readonly commit: string;
  readonly dirty: boolean;
}

export function resolveSourceIdentity(appRoot: string): SourceIdentity {
  const result = runGit(appRoot, ['rev-parse', 'HEAD']);
  if (result === undefined) {
    return { commit: '0'.repeat(40), dirty: true };
  }
  const status = runGit(appRoot, ['status', '--porcelain']);
  return { commit: result, dirty: status !== undefined && status.length > 0 };
}

function resolvePolicyCommit(policyRoot: string): string {
  return runGit(policyRoot, ['rev-parse', 'HEAD']) ?? '0'.repeat(40);
}

/**
 * Runs git with an argument array and no shell. Output is bounded because it comes from the
 * environment rather than from this repository's code.
 */
function runGit(cwd: string, args: readonly string[]): string | undefined {
  try {
    const stdout = execFileSync('git', [...args], {
      cwd,
      encoding: 'utf8',
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { PATH: process.env['PATH'] ?? '' },
    });
    const trimmed = stdout.trim();
    return trimmed.length === 0 ? undefined : trimmed;
  } catch {
    return undefined;
  }
}

/** Resolves a run-relative path and refuses anything outside the run directory. */
export function confineToRun(runDir: string, candidate: string): ConfinedPath {
  const result = confineToRoot(runDir, candidate, { mustExist: true });
  if ('code' in result) throw new ValidationError([result]);
  return result;
}

export function readRunRecord<T>(runDir: string): T {
  const file = join(runDir, 'run.json');
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

export function displayPath(root: string, file: string): string {
  return relative(root, file).split(sep).join('/');
}

export { writeFileSync };
