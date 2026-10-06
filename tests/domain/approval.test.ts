import { describe, expect, it } from 'vitest';
import {
  definitionContentDigest,
  resolveApprovals,
  approvalsRequiredForRelease,
  type ApprovalRecord,
} from '../../src/domain/approval.js';
import type { ControlDefinition } from '../../src/domain/definitions.js';
import { loadCatalogue } from '../../src/domain/definitions.js';
import { validateAgainstSchema } from '../../src/validation/schema.js';
import { checkDuplicateIds, checkReference } from '../../src/validation/semantic.js';

const NOW = new Date('2026-10-06T12:00:00Z');
const controls = loadCatalogue().controls;

const control = (id: string): ControlDefinition => {
  const found = controls.find((entry) => entry.id === id);
  if (found === undefined) throw new Error(`no such control ${id}`);
  return found;
};

/** A definition edited without bumping its version: the case an approval must not survive. */
const withAcceptance = (base: ControlDefinition, extra: string): ControlDefinition =>
  ({ ...base, acceptance: [...base.acceptance, extra] }) as ControlDefinition;

const approvalFor = (id: string, overrides: Partial<ApprovalRecord> = {}): ApprovalRecord => ({
  control: id,
  definition_version: control(id).definition_version,
  content_digest: definitionContentDigest(control(id)),
  reviewer: 'owner',
  reviewed_at: '2026-10-05T00:00:00Z',
  kind: 'owner',
  ...overrides,
});

describe('reviewed-content digest', () => {
  it('is stable for an unchanged definition', () => {
    expect(definitionContentDigest(control('AUTHZ-01'))).toBe(definitionContentDigest(control('AUTHZ-01')));
  });

  it('changes when acceptance criteria change', () => {
    const base = control('AUTHZ-01');
    expect(definitionContentDigest(withAcceptance(base, 'A new criterion that was not reviewed'))).not.toBe(
      definitionContentDigest(base),
    );
  });

  it('changes when limitations change', () => {
    const base = control('AUTHZ-01');
    expect(definitionContentDigest({ ...base, limitations: [] } as ControlDefinition)).not.toBe(
      definitionContentDigest(base),
    );
  });

  it('does not change when only approval metadata is recorded', () => {
    const draft = control('AUTHZ-01');
    const reviewed: ControlDefinition = {
      ...draft,
      review_status: 'owner_reviewed',
      reviewed_by: 'owner',
      reviewed_at: '2026-10-05T00:00:00Z',
    };
    expect(definitionContentDigest(reviewed)).toBe(definitionContentDigest(draft));
  });

  it('produces a different digest for every distinct definition', () => {
    const digests = new Set(controls.map((entry) => definitionContentDigest(entry)));
    expect(digests.size).toBe(controls.length);
  });
});

describe('resolving approvals', () => {
  it('reports an unapproved draft definition as not approved', () => {
    const states = resolveApprovals([control('AUTHZ-01')], [], NOW);
    expect(states[0]?.approved).toBe(false);
    expect(states[0]?.problem).toBe('not_approved');
  });

  it('accepts a correctly approved unchanged definition', () => {
    const states = resolveApprovals([control('AUTHZ-01')], [approvalFor('AUTHZ-01')], NOW);
    expect(states[0]?.approved).toBe(true);
    expect(states[0]?.approval?.reviewer).toBe('owner');
  });

  // This is the case the review called out: a content edit with no version bump.
  it('invalidates an approval when the content changed even if the version did not', () => {
    const edited = withAcceptance(control('AUTHZ-01'), 'Added after approval and never reviewed');
    const states = resolveApprovals([edited], [approvalFor('AUTHZ-01')], NOW);
    expect(states[0]?.approved).toBe(false);
    expect(states[0]?.problem).toBe('content_changed');
  });

  it('invalidates an approval whose version no longer matches', () => {
    const states = resolveApprovals(
      [control('AUTHZ-01')],
      [approvalFor('AUTHZ-01', { definition_version: 99 })],
      NOW,
    );
    expect(states[0]?.approved).toBe(false);
    expect(states[0]?.problem).toBe('version_changed');
  });

  it('rejects an approval with no reviewer', () => {
    const states = resolveApprovals([control('AUTHZ-01')], [approvalFor('AUTHZ-01', { reviewer: '  ' })], NOW);
    expect(states[0]?.approved).toBe(false);
    expect(states[0]?.problem).toBe('missing_reviewer');
  });

  it('ignores an approval dated in the future', () => {
    const states = resolveApprovals([control('AUTHZ-01')], [approvalFor('AUTHZ-01', { reviewed_at: '2027-01-01T00:00:00Z' })], NOW);
    expect(states[0]?.approved).toBe(false);
  });

  it('keeps unchanged definitions approved when another definition changes', () => {
    const changed = { ...control('AUTHZ-01'), limitations: ['completely rewritten'] } as ControlDefinition;
    const states = resolveApprovals(
      [changed, control('DATA-01')],
      [approvalFor('AUTHZ-01'), approvalFor('DATA-01')],
      NOW,
    );
    expect(states.find((state) => state.control === 'AUTHZ-01')?.approved).toBe(false);
    expect(states.find((state) => state.control === 'DATA-01')?.approved).toBe(true);
  });

  it('records owner acceptance as self-review rather than independent review', () => {
    const byOwner = resolveApprovals([control('AUTHZ-01')], [approvalFor('AUTHZ-01', { kind: 'owner' })], NOW);
    const independent = resolveApprovals([control('AUTHZ-01')], [approvalFor('AUTHZ-01', { kind: 'independent' })], NOW);
    expect(byOwner[0]?.self_review).toBe(true);
    expect(independent[0]?.self_review).toBe(false);
  });

  it('treats an approval older than the stated interval as unusable', () => {
    const old: ApprovalRecord = { ...approvalFor('AUTHZ-01'), reviewed_at: '2025-01-01T00:00:00Z' };
    expect(resolveApprovals([control('AUTHZ-01')], [old], NOW, { staleAfterDays: 30 })[0]?.approved).toBe(false);
    expect(resolveApprovals([control('AUTHZ-01')], [old], NOW, { staleAfterDays: 3650 })[0]?.approved).toBe(true);
  });

  it('does not confuse a control id that matches nothing', () => {
    const states = resolveApprovals([control('AUTHZ-01')], [approvalFor('DATA-01')], NOW);
    expect(states[0]?.approved).toBe(false);
  });
});

describe('release scoping', () => {
  it('only requires approval for applicable controls', () => {
    const states = resolveApprovals(controls, [], NOW);
    expect(approvalsRequiredForRelease(states, new Set(['AUTHZ-01', 'DATA-01']))).toHaveLength(2);
    expect(approvalsRequiredForRelease(states, new Set())).toHaveLength(0);
  });
});

describe('approval record structure', () => {
  const record = {
    schema_version: 'control-approvals/v1',
    approvals: [approvalFor('AUTHZ-01')],
  };

  it('validates against its schema', () => {
    expect(validateAgainstSchema('control-approvals', record).issues).toEqual([]);
  });

  it('rejects a malformed digest', () => {
    const result = validateAgainstSchema('control-approvals', {
      schema_version: 'control-approvals/v1',
      approvals: [approvalFor('AUTHZ-01', { content_digest: 'short' })],
    });
    expect(result.valid).toBe(false);
  });

  it('rejects an unknown kind', () => {
    const result = validateAgainstSchema('control-approvals', {
      schema_version: 'control-approvals/v1',
      approvals: [approvalFor('AUTHZ-01', { kind: 'agent_written' as never })],
    });
    expect(result.valid).toBe(false);
  });

  it('rejects duplicate approvals for one control', () => {
    const ids = [approvalFor('AUTHZ-01'), approvalFor('AUTHZ-01')];
    expect(checkDuplicateIds(ids.map((entry) => entry.control))).toHaveLength(1);
  });

  it('rejects an approval for an unknown control', () => {
    const issues = checkReference('NOPE-99', {
      known: new Set(controls.map((entry) => entry.id)),
      kind: 'control',
    });
    expect(issues).toHaveLength(1);
  });
});

describe('the approved state is not self-granting', () => {
  // Marking a definition owner_reviewed in the source is an assertion the evaluator cannot verify.
  // It is reported as a status, and the approval record is what the gate reads.
  it('reports a definition that claims owner_reviewed without an approval record as not approved', () => {
    const claiming = {
      ...control('AUTHZ-01'),
      review_status: 'owner_reviewed',
      reviewed_by: 'someone',
      reviewed_at: '2026-10-01T00:00:00Z',
    } as ControlDefinition;
    const states = resolveApprovals([claiming], [], NOW);
    expect(claiming.review_status).toBe('owner_reviewed');
    expect(states[0]?.approved).toBe(false);
    expect(states[0]?.problem).toBe('not_approved');
  });
});
