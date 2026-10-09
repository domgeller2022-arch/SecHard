import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { packageRoot } from '../validation/schema.js';

export interface ControlDefinition {
  readonly id: string;
  readonly schema_version: string;
  readonly definition_version: number;
  readonly review_status: 'draft' | 'owner_reviewed';
  readonly reviewed_by?: string;
  readonly reviewed_at?: string;
  readonly title: string;
  readonly purpose: string;
  readonly applicability: ApplicabilityShape;
  readonly acceptance: readonly string[];
  readonly verification: readonly VerificationMethod[];
  readonly evidence_requirements: readonly EvidenceRequirement[];
  readonly limitations: readonly string[];
  readonly owner_role: string;
  readonly reassessment_triggers: readonly string[];
  readonly standards?: readonly StandardMapping[];
}

export interface ApplicabilityShape {
  readonly rule: string;
  readonly features?: readonly string[];
  readonly environments?: readonly string[];
}

export interface VerificationMethod {
  readonly method: string;
  readonly recipe?: string;
  readonly coverage: 'automated' | 'mixed' | 'manual_only';
  readonly recipe_version?: string;
  readonly notes?: string;
}

export interface EvidenceRequirement {
  readonly kind: string;
  readonly required_origin?: 'actual_tool' | 'manual_attestation';
  readonly max_age_days?: number;
  readonly notes?: string;
}

export interface StandardMapping {
  readonly framework: string;
  readonly edition?: string;
  readonly requirement?: string;
  readonly relationship: 'related_risk' | 'verified_coverage' | 'unverified_reference';
  readonly verified_by?: string;
  readonly verified_at?: string;
  readonly notes?: string;
}

export interface Profile {
  readonly id: string;
  readonly schema_version: string;
  readonly definition_version: number;
  readonly review_status: 'draft' | 'owner_reviewed';
  readonly title: string;
  readonly description?: string;
  readonly extends?: readonly string[];
  readonly controls: readonly { readonly control: string; readonly required?: boolean }[];
  readonly excluded_features?: readonly string[];
  readonly stage_requirements: Readonly<Record<string, {
    readonly required_methods?: readonly string[];
    readonly require_clean_source?: boolean;
    readonly require_actual_tool_origin?: boolean;
    readonly required_recipes?: readonly string[];
  }>>;
  readonly support_constraints?: {
    readonly platforms?: readonly string[];
    readonly runtime?: Readonly<Record<string, string>>;
    readonly notes?: string;
  };
  readonly permitted_exceptions: readonly {
    readonly control: string;
    readonly policy: 'permitted' | 'never';
    readonly max_duration_days?: number;
    readonly requires_independent_approval?: boolean;
    readonly note?: string;
  }[];
}

export interface Mappings {
  readonly mappings_version: number;
  readonly reviewed: boolean;
  readonly review_note?: string;
  readonly editions: Readonly<Record<string, { edition: string; status: string; source: string; source_id?: string }>>;
  /** Standards recorded as sources but deliberately not mapped to any control, with a reason. */
  readonly not_referenced?: readonly { readonly source_id: string; readonly reason: string }[];
  readonly controls: Readonly<Record<string, readonly StandardMapping[]>>;
}

const root = packageRoot();

/**
 * Loads the repository's own reviewed definitions. These files are authored here, not supplied by a
 * consumer, so a parse failure is a repository defect rather than untrusted input. It still throws
 * rather than degrading to an empty catalogue: a runner with no controls must not report a pass.
 */
function loadOwn<T>(relativePath: string): T {
  return parse(readFileSync(join(root, relativePath), 'utf8')) as T;
}

export function loadCatalogue(): {
  readonly catalogue_version: number;
  readonly migration?: { readonly changed_in: number; readonly reason: string; readonly added?: readonly string[]; readonly removed?: readonly string[] };
  readonly controls: readonly ControlDefinition[];
} {
  const data = loadOwn<{
    catalogue_version: number;
    migration?: { changed_in: number; reason: string; added?: string[]; removed?: string[] };
    controls: ControlDefinition[];
  }>('controls/controls.yaml');
  return { catalogue_version: data.catalogue_version, ...(data.migration === undefined ? {} : { migration: data.migration }), controls: data.controls };
}

export function loadProfile(id: string): Profile {
  return loadOwn<Profile>(`profiles/${id}.yaml`);
}

export interface Pattern {
  readonly id: string;
  readonly schema_version: string;
  readonly review_status: 'draft' | 'reviewed';
  readonly reviewed_by?: string;
  readonly reviewed_at?: string;
  readonly title: string;
  readonly related_control_ids: readonly string[];
  readonly applicability: ApplicabilityShape;
  readonly rationale: string;
  readonly limitations: readonly string[];
  readonly vulnerable_example: { readonly language: string; readonly code: string; readonly explanation: string };
  readonly permitted_example: { readonly language: string; readonly code: string; readonly explanation: string };
  readonly verification: readonly {
    readonly method: string;
    readonly description: string;
    readonly recipe?: string;
    readonly implemented?: boolean;
  }[];
  readonly provenance: {
    readonly source_id: string;
    readonly source_file?: string;
    readonly source_digest?: string;
    readonly reviewed_at: string;
    readonly corrections?: readonly string[];
  };
}

export interface SourceRecord {
  readonly schema_version: string;
  readonly id: string;
  readonly canonical_url: string;
  readonly component: string;
  readonly licence: string;
  readonly use_type: 'linking' | 'invoking' | 'copying' | 'adapting' | 'redistributing';
  readonly attribution?: string;
  readonly notice_file?: string;
  readonly reviewed_release: { readonly kind: string; readonly value?: string; readonly verified_at?: string; readonly integrity_method?: string };
  readonly support_status: 'planned' | 'verified' | 'deprecated' | 'unsupported' | 'blocked';
  readonly update_policy?: string;
  readonly last_reviewed: string;
  readonly notes?: string;
}

export function loadPatterns(): { readonly catalogue_version: number; readonly patterns: readonly Pattern[] } {
  return loadOwn<{ catalogue_version: number; patterns: Pattern[] }>('controls/patterns/patterns.yaml');
}

export function loadSources(): { readonly sources: readonly SourceRecord[] } {
  return loadOwn<{ sources: SourceRecord[] }>('upstream/sources.yaml');
}

export function loadMappings(): Mappings {
  return loadOwn<Mappings>('controls/mappings/standards.yaml');
}
