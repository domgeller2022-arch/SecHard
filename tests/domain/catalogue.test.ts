import { describe, expect, it } from 'vitest';
import { loadCatalogue, loadMappings, loadProfile, type ControlDefinition } from '../../src/domain/definitions.js';
import { coverageGap, evaluateApplicability, type ManifestLike } from '../../src/domain/applicability.js';
import { generateMatrix } from '../../src/domain/matrix.js';
import { loadDocument } from '../../src/validation/loader.js';
import { validateAgainstSchema } from '../../src/validation/schema.js';
import { checkDuplicateIds, checkIntervals, checkReference } from '../../src/validation/semantic.js';
import { resolveApprovals } from '../../src/domain/approval.js';
import { loadPolicy } from '../../src/commands/io.js';
import { packageRoot } from '../../src/validation/schema.js';
import { join } from 'node:path';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const catalogue = loadCatalogue();
const controls = catalogue.controls;
const BLUEPRINT_IDS = [
  'CTX-01', 'GOV-01', 'GOV-02', 'AGT-01', 'AGT-02', 'AGT-03', 'DEP-01', 'DEP-02', 'DEP-03',
  'SEC-01', 'SEC-02', 'SEC-03', 'CI-01', 'CI-02', 'CI-03', 'CODE-01', 'QUAL-01', 'AUTH-01',
  'AUTH-02', 'AUTHZ-01', 'AUTHZ-02', 'AUTHZ-03', 'DATA-01', 'WEB-01', 'WEB-02', 'ABUSE-01',
  'BIZ-01', 'DEPLOY-01', 'OPS-01', 'OPS-02', 'OPS-03', 'PRIV-01', 'REL-01', 'REL-02', 'EXC-01',
] as const;
// D3's catalogue-versioning story: a new ID set never changes silently. Catalogue v2 added the
// quality controls; v3 added AUTH-03 (Batch S, RFC 9700). These lists are the deliberate record,
// and the test asserts the migration note names exactly the latest change plus the full history.
const CATALOGUE_V2_ADDITIONS = [
  'QUAL-02', 'QUAL-03', 'QUAL-04', 'QUAL-05', 'QUAL-06', 'QUAL-07', 'QUAL-08', 'QUAL-09',
  'QUAL-10', 'QUAL-11', 'QUAL-12', 'QUAL-13',
] as const;
const CATALOGUE_V3_ADDITIONS = ['AUTH-03'] as const;

describe('control catalogue', () => {
  it('contains exactly the v1 blueprint IDs plus the v2 and v3 additions, with no duplicates', () => {
    const ids = controls.map((control) => control.id);
    expect(ids).toHaveLength(BLUEPRINT_IDS.length + CATALOGUE_V2_ADDITIONS.length + CATALOGUE_V3_ADDITIONS.length);
    expect([...ids].sort()).toEqual([...BLUEPRINT_IDS, ...CATALOGUE_V2_ADDITIONS, ...CATALOGUE_V3_ADDITIONS].sort());
    expect(checkDuplicateIds(ids)).toEqual([]);
  });

  it('carries a migration note that names exactly what the latest catalogue version added, with the full history', () => {
    // A catalogue whose size changed without a migration note is a silent release change; D3
    // exists to make that impossible.
    expect(catalogue.catalogue_version).toBe(3);
    expect(catalogue.migration?.changed_in).toBe(3);
    expect([...(catalogue.migration?.added ?? [])].sort()).toEqual([...CATALOGUE_V3_ADDITIONS].sort());
    expect(catalogue.migration?.removed ?? []).toEqual([]);
    expect((catalogue.migration?.reason ?? '').length).toBeGreaterThan(40);
  });

  it('keeps every v2 and v3 addition a draft that the owner has not yet approved', () => {
    const additions = controls.filter((control) => ([...CATALOGUE_V2_ADDITIONS, ...CATALOGUE_V3_ADDITIONS] as readonly string[]).includes(control.id));
    expect(additions).toHaveLength(CATALOGUE_V2_ADDITIONS.length + CATALOGUE_V3_ADDITIONS.length);
    for (const control of additions) {
      expect(control.review_status, control.id).toBe('draft');
      expect(control.reviewed_by, control.id).toBeUndefined();
    }
  });

  it('validates against its schema', () => {
    const file = join(packageRoot(), 'controls', 'controls.yaml');
    const loaded = loadDocument(file);
    expect(loaded.issues).toEqual([]);
    const result = validateAgainstSchema('control-catalogue', loaded.data, file);
    expect(result.issues).toEqual([]);
    expect(result.valid).toBe(true);
  });

  // The owner approved all 35 v1 definitions on 2026-10-07. The definition's own review_status is an
  // assertion; what makes it real is a resolving approval record, which the next test checks. The
  // v2 quality additions are drafts and are covered by their own test above.
  it('records the owner review on every v1 definition', () => {
    const reviewed = controls.filter((control) => control.review_status === 'owner_reviewed');
    expect(reviewed).toHaveLength(35);
    expect(reviewed.every((control) => typeof control.reviewed_by === 'string' && control.reviewed_at !== undefined)).toBe(true);
    // And the agent must not have claimed independent review.
    expect(reviewed.every((control) => control.reviewed_by === 'owner')).toBe(true);
  });

  it('approvals are on record and every control could not have been approved by an agent alone', () => {
    const policy = loadPolicy({ appRoot: packageRoot(), policyRoot: packageRoot() });
    expect(policy.value?.approvals).toHaveLength(35);
    const states = resolveApprovals(controls, policy.value?.approvals ?? [], new Date());
    // Definition edits invalidate approvals by design: the digest is over the definition as
    // reviewed, so content that changed since approval stops resolving. Three batches did that
    // deliberately: Batch W changed SEC-01 (mixed coverage), Batch Q and Batch S added the
    // quality controls and AUTH-03, and Batch S added WSTG citations and cheat-sheet references
    // to fourteen v1 definitions (AUTH-01/02, AUTHZ-01..03, DATA-01, WEB-01, ABUSE-01, BIZ-01,
    // AGT-03, DEP-02, REL-02, EXC-01, QUAL-01) - a citation is reviewable content. Release
    // evaluation must block on all of them until the owner approves them; Batch D re-approves the
    // whole sheet once the remediation batches stop changing definitions.
    const WSTG_INVALIDATED = [
      'AGT-03', 'AUTH-01', 'AUTH-02', 'AUTHZ-01', 'AUTHZ-02', 'AUTHZ-03', 'BIZ-01', 'DATA-01',
      'DEP-02', 'EXC-01', 'QUAL-01', 'REL-02', 'WEB-01', 'ABUSE-01',
    ] as const;
    const unresolved = states.filter((state) => !state.approved);
    expect([...unresolved.map((state) => state.control)].sort()).toEqual(
      ['SEC-01', ...WSTG_INVALIDATED, ...CATALOGUE_V2_ADDITIONS, ...CATALOGUE_V3_ADDITIONS].sort(),
    );
    expect(states.filter((state) => state.approved)).toHaveLength(20);
    // Self-review, not independent assurance. The unresolved SEC-01 has no valid approval to label.
    expect(states.filter((state) => state.approved).every((state) => state.self_review)).toBe(true);
  });

  it('gives every control at least one real method or an explicit manual recipe', () => {
    for (const control of controls) {
      expect(control.verification.length, control.id).toBeGreaterThan(0);
      for (const entry of control.verification) {
        expect(entry.method, control.id).toBeTruthy();
        expect(['automated', 'mixed', 'manual_only']).toContain(entry.coverage);
        if (entry.coverage !== 'manual_only') {
          expect(entry.recipe, `${control.id} declares an automated method without a recipe`).toBeTruthy();
        }
      }
    }
  });

  it('gives every control evidence requirements, limitations, an owner role, and triggers', () => {
    for (const control of controls) {
      expect(control.evidence_requirements.length, control.id).toBeGreaterThan(0);
      expect(control.limitations.length, control.id).toBeGreaterThan(0);
      expect(control.acceptance.length, control.id).toBeGreaterThan(0);
      expect(control.owner_role, control.id).toBeTruthy();
      expect(control.reassessment_triggers.length, control.id).toBeGreaterThan(0);
    }
  });

  it('never claims verified standards coverage that was not reviewed', () => {
    const mappings = loadMappings();
    expect(mappings.reviewed).toBe(false);
    for (const entries of Object.values(mappings.controls)) {
      for (const mapping of entries) {
        expect(mapping.relationship, `${mapping.framework} must not claim verified coverage yet`).not.toBe('verified_coverage');
        expect(mapping.verified_by).toBeUndefined();
      }
    }
  });
});

describe('profiles', () => {
  const core = loadProfile('core');
  const reference = loadProfile('nextjs-supabase');
  const known = new Set(controls.map((control) => control.id));

  it('validate against the profile schema', () => {
    for (const [name, profile] of [['core', core], ['nextjs-supabase', reference]] as const) {
      const result = validateAgainstSchema('profile', profile);
      expect(result.issues, name).toEqual([]);
    }
  });

  it('select only controls that exist in the catalogue', () => {
    for (const profile of [core, reference]) {
      const ids = profile.controls.map((entry) => entry.control);
      expect(checkReference(ids[0] as string, { known, kind: 'control', file: profile.id })).toEqual([]);
      for (const id of ids) {
        expect(known.has(id), `${profile.id} selects unknown control ${id}`).toBe(true);
      }
    }
  });

  it('are drafts until the owner reviews them; profiles are still unreviewed', () => {
    // Controls were approved; the profiles were not, and this test would catch a claim otherwise.
    expect(core.review_status).toBe('draft');
    expect(reference.review_status).toBe('draft');
  });

  it('define requirements for every stage', () => {
    for (const profile of [core, reference]) {
      for (const stage of ['pr', 'release', 'operations']) {
        expect(profile.stage_requirements[stage], `${profile.id}/${stage}`).toBeDefined();
      }
    }
  });

  it('require a clean source only for release', () => {
    expect(reference.stage_requirements.release?.require_clean_source).toBe(true);
    expect(reference.stage_requirements.pr?.require_clean_source).toBe(false);
  });

  it('do not let a production-only obligation block an ordinary local PR check', () => {
    const pr = reference.stage_requirements.pr;
    expect(pr?.required_methods ?? []).not.toContain('tls_check');
    expect(reference.stage_requirements.release?.required_methods ?? []).toContain('tls_check');
  });

  // Scoped to controls the profile actually selects: the core profile does not select the stack
  // authorization controls, so demanding an exception policy for them there would be wrong.
  it('never permit an exception for gate, policy, or authorization-boundary controls', () => {
    const nonExceptable = ['GOV-02', 'CI-03', 'AUTHZ-01', 'AUTHZ-02', 'AUTHZ-03', 'REL-01', 'EXC-01'];
    for (const profile of [core, reference]) {
      const selected = new Set(profile.controls.map((entry) => entry.control));
      const never = new Set(
        profile.permitted_exceptions.filter((entry) => entry.policy === 'never').map((entry) => entry.control),
      );
      for (const controlId of nonExceptable.filter((id) => selected.has(id))) {
        expect(never.has(controlId), `${profile.id} must not permit an exception for ${controlId}`).toBe(true);
      }
    }
  });

  it('states every profile control\'s exception policy', () => {
    for (const profile of [core, reference]) {
      const governed = new Set(profile.permitted_exceptions.map((entry) => entry.control));
      for (const entry of profile.controls) {
        expect(governed.has(entry.control), `${profile.id} has no exception policy for ${entry.control}`).toBe(true);
      }
    }
  });

  it('explicitly exclude payments, uploads, tenancy, roles, and runtime AI from the reference stack', () => {
    const excluded = reference.excluded_features ?? [];
    for (const feature of ['payments', 'uploads', 'tenancy', 'runtime_ai']) {
      expect(excluded, feature).toContain(feature);
    }
  });
});

describe('excluded features produce coverage gaps rather than silent passes', () => {
  const reference = loadProfile('nextjs-supabase');

  const manifestWith = (features: Record<string, { state: 'enabled' | 'disabled' }>): ManifestLike => ({
    features,
    environments: [{ kind: 'production' }],
  });

  it('reports a gap when payments are enabled', () => {
    const gaps = coverageGap(manifestWith({ payments: { state: 'enabled' } }), reference.excluded_features ?? []);
    expect(gaps.some((gap) => gap.includes('payments'))).toBe(true);
  });

  it('brings in BIZ-01 when payments or webhooks are enabled', () => {
    const byId = (id: string): ControlDefinition | undefined => controls.find((control) => control.id === id);

    const biz = byId('BIZ-01');
    expect(biz).toBeDefined();
    expect(evaluateApplicability(biz!.applicability as never, manifestWith({ payments: { state: 'enabled' } }), 'production')).toBe('applicable');
    // Nothing declared is unknown, not a clean not_applicable: absence of information is not absence of the feature.
    expect(evaluateApplicability(biz!.applicability as never, manifestWith({}), 'production')).toBe('unknown');
    expect(
      evaluateApplicability(
        biz!.applicability as never,
        manifestWith({ payments: { state: 'disabled' }, webhooks: { state: 'disabled' } }),
        'production',
      ),
    ).toBe('not_applicable');
    expect(reference.controls.some((entry) => entry.control === 'BIZ-01')).toBe(true);
  });

  it('cannot silently drop tenancy requirements when tenancy is undeclared', () => {
    const authz02 = controls.find((control) => control.id === 'AUTHZ-02');
    expect(authz02).toBeDefined();
    expect(evaluateApplicability(authz02!.applicability as never, manifestWith({ accounts: { state: 'enabled' } }), 'production')).toBe('unknown');
  });

  it('cannot silently drop roles requirements when roles are undeclared', () => {
    // AUTHZ-02 applies to either roles or tenancy. With tenancy enabled it is applicable outright;
    // with neither declared it must be unknown rather than silently absent.
    const authz02 = controls.find((control) => control.id === 'AUTHZ-02');
    expect(evaluateApplicability(authz02!.applicability as never, manifestWith({ tenancy: { state: 'enabled' } }), 'production')).toBe('applicable');
    expect(evaluateApplicability(authz02!.applicability as never, manifestWith({}), 'production')).toBe('unknown');
  });

  it('reports no gap for a feature that is not enabled', () => {
    expect(coverageGap(manifestWith({ payments: { state: 'disabled' } }), reference.excluded_features ?? [])).toEqual([]);
  });
});

describe('matrix generation', () => {
  it('is repeatable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hardening-matrix-'));
    try {
      const first = {
        matrixPath: join(dir, 'a', 'matrix.md'),
        reviewSheetPath: join(dir, 'a', 'sheet.md'),
      };
      const second = {
        matrixPath: join(dir, 'b', 'matrix.md'),
        reviewSheetPath: join(dir, 'b', 'sheet.md'),
      };
      generateMatrix(first);
      generateMatrix(second);

      expect(readFileSync(first.matrixPath, 'utf8')).toBe(readFileSync(second.matrixPath, 'utf8'));
      expect(readFileSync(first.reviewSheetPath, 'utf8')).toBe(readFileSync(second.reviewSheetPath, 'utf8'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('includes every control with its review status', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hardening-matrix-'));
    try {
      const matrixPath = join(dir, 'matrix.md');
      generateMatrix({ matrixPath, reviewSheetPath: join(dir, 'sheet.md') });
      const matrix = readFileSync(matrixPath, 'utf8');
      for (const control of controls) {
        expect(matrix).toContain(`**${control.id}**`);
      }
      expect(matrix).toContain(`- Controls: ${controls.length}`);
      expect(matrix).toContain('All definitions draft: false');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('distinguishes automation from manual and unsupported scope', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hardening-matrix-'));
    try {
      const matrixPath = join(dir, 'matrix.md');
      generateMatrix({ matrixPath, reviewSheetPath: join(dir, 'sheet.md') });
      const matrix = readFileSync(matrixPath, 'utf8');
      expect(matrix).toContain('| automated |');
      expect(matrix).toContain('| mixed |');
      expect(matrix).toContain('| manual_only |');
      expect(matrix).toContain('Unsupported and excluded scope');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('classifies an all-mixed control as mixed, never manual_only', () => {
    // Batch W made SEC-01's two gitleaks recipes `mixed` (tool evidence judged against
    // required_coverage). The matrix classifier still dropped an all-mixed control into
    // `manual_only` — whose own definition says a scan result can never satisfy it — so the
    // regenerated matrix contradicted the control. Found and fixed in Batch U.
    const sec01 = controls.find((control) => control.id === 'SEC-01');
    expect(sec01).toBeDefined();
    expect(sec01?.verification.every((method) => method.coverage === 'mixed')).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), 'hardening-matrix-mixed-'));
    try {
      const matrixPath = join(dir, 'matrix.md');
      generateMatrix({ matrixPath, reviewSheetPath: join(dir, 'sheet.md') });
      const matrix = readFileSync(matrixPath, 'utf8');
      expect(matrix).toMatch(/\*\*SEC-01\*\* \| [^|]+\| [^|]+\| [^|]+\| mixed \|/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('semantic validation helpers', () => {
  const now = new Date('2026-10-06T00:00:00Z');

  it('rejects a repeated id', () => {
    expect(checkDuplicateIds(['a', 'b', 'a'])).toHaveLength(1);
    expect(checkDuplicateIds(['a', 'b'])).toEqual([]);
  });

  it('rejects an unknown reference', () => {
    expect(checkReference('MISSING-1', { known: new Set(['A-1']), kind: 'control' })).toHaveLength(1);
    expect(checkReference('A-1', { known: new Set(['A-1']), kind: 'control' })).toEqual([]);
  });

  it('rejects an expiry at or before the observation', () => {
    const issues = checkIntervals(
      [{ id: 'ME-1', observedAt: '2026-10-06T00:00:00Z', expiresAt: '2026-10-06T00:00:00Z' }],
      now,
    );
    expect(issues[0]?.code).toBe('semantic.invalid_interval');
  });

  it('rejects an already-expired record', () => {
    const issues = checkIntervals(
      [{ id: 'ME-1', observedAt: '2026-01-01T00:00:00Z', expiresAt: '2026-06-01T00:00:00Z' }],
      now,
    );
    expect(issues[0]?.message).toMatch(/expired/);
  });

  it('accepts a current record', () => {
    expect(
      checkIntervals([{ id: 'ME-1', observedAt: '2026-09-01T00:00:00Z', expiresAt: '2026-12-01T00:00:00Z' }], now),
    ).toEqual([]);
  });
});
