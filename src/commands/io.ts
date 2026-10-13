import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { ValidationIssue } from '../validation/errors.js';
import { loadDocument } from '../validation/loader.js';
import { confineReference, isRemoteReference } from '../validation/paths.js';
import { validateAgainstSchema } from '../validation/schema.js';
import { checkDuplicateIds, checkReference } from '../validation/semantic.js';
import { loadCatalogue, type ControlDefinition, type Profile } from '../domain/definitions.js';
import { gitHardeningArgs } from '../execution/git-hardening.js';
import { loadToolchain, platformKey } from '../execution/registry.js';
import { sha256Hex } from '../evidence/digest.js';
import type { ApprovalRecord } from '../domain/approval.js';
import type { AssessmentRecord, ExceptionRecord, GatePolicy, ManualEvidence, TriageRecord } from '../domain/types.js';
import type { ManifestRecord } from '../domain/types.js';

export interface Paths {
  readonly appRoot: string;
  readonly policyRoot: string;
  readonly runDir?: string;
  readonly planPath?: string;
  /**
   * Where consumer records (`.hardening/`) are read from. Defaults to the application root, which is
   * the gate-mode contract. Audit mode sets it to its ephemeral records directory so the audited
   * tree is never written to and never supplies its own manifest.
   */
  readonly recordsRoot?: string;
}

export const recordsRootFor = (paths: Paths): string => paths.recordsRoot ?? paths.appRoot;

export interface LoadedPolicy {
  readonly policy: GatePolicy;
  readonly gatePolicyDigest: string;
  readonly controlCatalogueDigest: string;
  readonly profiles: readonly Profile[];
  readonly profileDigests: Readonly<Record<string, string>>;
  readonly controls: readonly ControlDefinition[];
  /** Owner approvals. Empty until the owner records real ones. */
  readonly approvals: readonly ApprovalRecord[];
  readonly policyCommit: string;
}

export interface LoadedConsumer {
  readonly manifest?: ManifestRecord;
  readonly manifestDigest?: string;
  readonly assessments: readonly AssessmentRecord[];
  readonly exceptions: readonly ExceptionRecord[];
  readonly manualEvidence: readonly ManualEvidence[];
  /** Reviewed false-positive records; the only triage that clears a finding. */
  readonly triages: readonly TriageRecord[];
}

/** Issues that should be visible to the owner but do not make a record unusable. */
export interface LoadOutcome<T> {
  readonly value?: T;
  readonly issues: readonly ValidationIssue[];
  readonly warnings?: readonly string[];
}

const CONSUMER_FILES = {
  manifest: '.hardening/app.yaml',
  assessments: '.hardening/assessments.yaml',
  exceptions: '.hardening/exceptions.yaml',
  manualEvidence: '.hardening/manual-evidence.yaml',
  triage: '.hardening/triage.yaml',
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
  // Every reviewed profile file in `profiles/` is loaded: a shipped-but-unloaded profile would be
  // dead policy. Sorted for deterministic digest ordering.
  let profileFiles: string[] = [];
  try {
    profileFiles = readdirSync(join(policyRoot, 'profiles')).filter((name) => name.endsWith('.yaml') || name.endsWith('.yml')).sort();
  } catch {
    profileFiles = [];
  }
  for (const name of profileFiles) {
    const id = name.replace(/\.ya?ml$/, '');
    const file = join(policyRoot, 'profiles', name);
    const loaded = loadDocument<Profile>(file);
    issues.push(...loaded.issues);
    if (loaded.data === undefined) continue;
    const result = validateAgainstSchema('profile', loaded.data, file);
    issues.push(...result.issues);
    if (!result.valid) continue;
    profiles.push(loaded.data);
    profileDigests[id] = loaded.rawDigest;
  }

  const approvals: ApprovalRecord[] = [];
  const approvalsFile = join(policyRoot, 'controls', 'approvals.yaml');
  const loadedApprovals = loadDocument<{ approvals?: ApprovalRecord[] }>(approvalsFile);
  if (loadedApprovals.issues.length === 0 && loadedApprovals.data?.approvals !== undefined) {
    for (const record of loadedApprovals.data.approvals) {
      const result = validateAgainstSchema('control-approvals', { schema_version: 'control-approvals/v1', approvals: [record] }, approvalsFile);
      issues.push(...result.issues);
      if (result.valid) approvals.push(record);
    }
  } else {
    // A missing approvals file is not an error: it means nothing has been approved, which is the
    // honest state for an unreviewed catalogue. A malformed one is an error.
    issues.push(...loadedApprovals.issues.filter((item) => item.code !== 'input.not_found'));
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
      approvals,
      policyCommit: resolvePolicyCommit(policyRoot),
    },
    issues,
  };
}

export function loadConsumer(paths: Paths, selectedProfiles: readonly string[]): LoadOutcome<LoadedConsumer> {
  const issues: ValidationIssue[] = [];
  let manifest: ManifestRecord | undefined;
  let manifestDigest: string | undefined;

  const recordsRoot = recordsRootFor(paths);
  const manifestFile = join(recordsRoot, CONSUMER_FILES.manifest);
  const loadedManifest = loadDocument(manifestFile);
  if (loadedManifest.issues.length > 0) {
    // A missing or unparsable manifest is reported on its own. Continuing would produce a wall of
    // derived complaints that all trace back to this one missing record.
    if (loadedManifest.issues[0]?.code === 'input.not_found') {
      return { issues: loadedManifest.issues, value: { assessments: [], exceptions: [], manualEvidence: [], triages: [] } };
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
  const exceptionsFile = join(recordsRoot, CONSUMER_FILES.exceptions);
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
  const manualFile = join(recordsRoot, CONSUMER_FILES.manualEvidence);
  const loadedManual = loadDocument<{ records?: ManualEvidence[] }>(manualFile);
  if (loadedManual.issues.length === 0 && loadedManual.data?.records !== undefined) {
    for (const record of loadedManual.data.records) {
      const result = validateAgainstSchema('manual-evidence', record, manualFile);
      issues.push(...result.issues);
      if (result.valid) manualEvidence.push(record);
    }
    issues.push(...checkDuplicateIds(loadedManual.data.records.map((record) => record.id), manualFile));
  }

  // Reviewed false-positive records (F-02/A-4): the only triage that clears a finding. A missing
  // file is normal; a malformed record is an issue, never silently ignored.
  const triages: TriageRecord[] = [];
  const triageFile = join(recordsRoot, CONSUMER_FILES.triage);
  const loadedTriages = loadDocument<{ triages?: TriageRecord[] }>(triageFile);
  if (loadedTriages.issues.length === 0 && loadedTriages.data?.triages !== undefined) {
    for (const record of loadedTriages.data.triages) {
      const result = validateAgainstSchema('triage', record, triageFile);
      issues.push(...result.issues);
      if (result.valid) triages.push(record);
    }
    issues.push(...checkDuplicateIds(loadedTriages.data.triages.map((record) => record.id), triageFile));
  }

  const assessments: AssessmentRecord[] = [];
  const warnings: string[] = [];
  const assessmentsFile = join(recordsRoot, CONSUMER_FILES.assessments);
  const loadedAssessments = loadDocument<{ assessments?: AssessmentRecord[] }>(assessmentsFile);
  if (loadedAssessments.issues.length > 0) {
    issues.push(...loadedAssessments.issues.filter((item) => item.code !== 'input.not_found'));
  } else if (loadedAssessments.data?.assessments !== undefined) {
    const records = loadedAssessments.data.assessments;
    for (const record of records) {
      const result = validateAgainstSchema('assessment', record, assessmentsFile);
      issues.push(...result.issues);
      if (result.valid) assessments.push(record);
    }
    issues.push(...checkDuplicateIds(records.map((record) => record.control), assessmentsFile));
  }

  // Record freshness: an interval that ends before it starts is malformed and unusable. A record
  // that has simply expired is a warning here; the gate is what blocks on it, so an expired record
  // still lets a plan be derived and the finding shown.
  const now = new Date();
  for (const record of assessments) {
    if (record.applicability === 'not_applicable' && (record.applicability_reason ?? '').trim().length < 10) {
      issues.push({
        code: 'semantic.missing_field',
        message: `assessment for ${record.control} is not_applicable without a reason tied to the manifest`,
        file: assessmentsFile,
      });
    }
  }
  for (const record of manualEvidence) {
    const expired = Date.parse(record.expires_at) <= now.getTime();
    const malformed = Date.parse(record.expires_at) <= Date.parse(record.observed_at);
    if (malformed) {
      issues.push({
        code: 'semantic.invalid_interval',
        message: `manual evidence ${record.id} expires at or before it was observed`,
        file: manualFile,
      });
    } else if (expired) {
      warnings.push(`manual evidence ${record.id} for ${record.control} expired at ${record.expires_at}`);
    }
  }
  for (const exception of exceptions) {
    const malformed = Date.parse(exception.expires_at) <= Date.parse(exception.created_at ?? exception.expires_at);
    if (exception.created_at !== undefined && malformed) {
      issues.push({
        code: 'semantic.invalid_interval',
        message: `exception ${exception.id} expires at or before it was created`,
        file: exceptionsFile,
      });
    } else if (Date.parse(exception.expires_at) <= now.getTime() && exception.status === 'active') {
      warnings.push(`exception ${exception.id} is active but expired at ${exception.expires_at}`);
    }
  }

  // References must stay inside the application root. A remote URL is a reference only and is never
  // fetched; a local reference may point at evidence that does not exist yet.
  for (const [file, refs] of [
    [assessmentsFile, assessments.flatMap((record) => [...(record.implementation_refs ?? []), ...(record.evidence_refs ?? [])])],
    [manualFile, manualEvidence.flatMap((record) => [...(record.supporting_refs ?? [])])],
  ] as const) {
    for (const ref of refs) {
      if (isRemoteReference(ref)) continue;
      const confined = confineReference(paths.appRoot, ref);
      if (typeof confined !== 'string') issues.push({ ...confined, file });
    }
  }

  return {
    value: {
      ...(manifest === undefined ? {} : { manifest }),
      ...(manifestDigest === undefined ? {} : { manifestDigest }),
      assessments,
      exceptions,
      manualEvidence,
      triages,
    },
    issues,
    warnings,
  };
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
 * The git to use, from the reviewed toolchain record.
 *
 * Resolved to an absolute path rather than looked up through PATH: Step 06's execution rule forbids
 * PATH lookups, and a caller-influenced PATH could otherwise redirect the command that establishes
 * source identity.
 */
function gitExecutable(): string | undefined {
  const identity = loadToolchain().executables?.git;
  const candidates = [
    ...(identity?.candidates?.[platformKey()] ?? []),
    identity?.executable,
    identity?.fallbackExecutable,
    '/usr/bin/git',
  ].filter((candidate): candidate is string => typeof candidate === 'string');
  return candidates.find((candidate) => existsSync(candidate));
}

/**
 * Runs git with an argument array and no shell. Output is bounded because it comes from the
 * environment rather than from this repository's code.
 */
function runGit(cwd: string, args: readonly string[]): string | undefined {
  const executable = gitExecutable();
  if (executable === undefined) return undefined;
  try {
    // A-01: the audited tree's own .git/config can execute code (core.fsmonitor); harden every call.
    const stdout = execFileSync(executable, [...gitHardeningArgs(), ...args], {
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
