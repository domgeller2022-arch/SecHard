import { canonicalDigest } from '../evidence/digest.js';

/**
 * Fields that record *who reviewed* rather than *what was reviewed*.
 *
 * They are excluded from the reviewed-content digest so that recording an approval does not itself
 * invalidate the approval it is recording.
 */
const APPROVAL_METADATA = new Set(['review_status', 'reviewed_by', 'reviewed_at']);

export type ApprovalKind = 'owner' | 'independent';

/** The fields of a control definition this module reads. */
export interface DefinitionLike {
  readonly id: string;
  readonly definition_version: number;
  readonly review_status: 'draft' | 'owner_reviewed';
}

export interface ApprovalRecord {
  readonly control: string;
  readonly definition_version: number;
  readonly content_digest: string;
  readonly reviewer: string;
  readonly reviewed_at: string;
  readonly kind: ApprovalKind;
  readonly notes?: string;
}

export interface ApprovalState {
  readonly control: string;
  readonly definition_version: number;
  readonly required: boolean;
  readonly review_status: 'draft' | 'owner_reviewed';
  readonly approved: boolean;
  readonly approval?: ApprovalRecord;
  /** Why the approval does not currently apply. Absent when `approved` is true. */
  readonly problem?: 'not_approved' | 'content_changed' | 'version_changed' | 'different_control' | 'missing_reviewer';
  readonly self_review: boolean;
}

/**
 * Digest of the definition's substantive content: everything except who reviewed it and when.
 *
 * A definition whose acceptance criteria or limitations change produces a different digest, so the
 * previous approval no longer applies even when whoever edited it forgot to increment
 * `definition_version`. That is the whole point of digesting content rather than trusting a number.
 */
export function definitionContentDigest(control: DefinitionLike): string {
  const record = control as unknown as Record<string, unknown>;
  const content: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    if (APPROVAL_METADATA.has(key)) continue;
    content[key] = record[key];
  }
  return canonicalDigest(content);
}

/**
 * Resolves whether each control currently holds a valid owner approval.
 *
 * An approval applies only when it names the same control, the same definition version, and the same
 * reviewed content digest, with a recorded reviewer. Anything else is an invalid approval, not an
 * absent one: the difference matters, because an invalid approval must not read as "reviewed".
 */
export function resolveApprovals(
  controls: readonly DefinitionLike[],
  approvals: readonly ApprovalRecord[],
  now: Date,
  options: { readonly staleAfterDays?: number } = {},
): readonly ApprovalState[] {
  const byControl = new Map<string, ApprovalRecord[]>();
  for (const approval of approvals) {
    const list = byControl.get(approval.control);
    if (list === undefined) byControl.set(approval.control, [approval]);
    else list.push(approval);
  }

  return controls.map((control) => {
    const candidates = byControl.get(control.id) ?? [];
    const digest = definitionContentDigest(control);

    const usable = candidates.find(
      (approval) =>
        approval.content_digest === digest &&
        approval.definition_version === control.definition_version &&
        approval.reviewer.trim().length > 0 &&
        Date.parse(approval.reviewed_at) <= now.getTime() &&
        (options.staleAfterDays === undefined ||
          (now.getTime() - Date.parse(approval.reviewed_at)) / 86_400_000 <= options.staleAfterDays),
    );

    if (usable !== undefined) {
      return {
        control: control.id,
        definition_version: control.definition_version,
        required: true,
        review_status: 'owner_reviewed',
        approved: true,
        approval: usable,
        self_review: usable.kind === 'owner',
      };
    }

    let problem: ApprovalState['problem'] = 'not_approved';
    if (candidates.length > 0) {
      const nearest = candidates.reduce((best, current) =>
        Date.parse(current.reviewed_at) > Date.parse(best.reviewed_at) ? current : best,
      );
      problem =
        nearest.reviewer.trim().length === 0
          ? 'missing_reviewer'
          : nearest.control !== control.id
            ? 'different_control'
            : nearest.definition_version !== control.definition_version
              ? 'version_changed'
              : 'content_changed';
    }

    return {
      control: control.id,
      definition_version: control.definition_version,
      required: true,
      review_status: control.review_status,
      approved: false,
      problem,
      self_review: false,
    };
  });
}

/** Controls among `applicable` that a release gate would require a valid approval for. */
export function approvalsRequiredForRelease(
  states: readonly ApprovalState[],
  applicable: ReadonlySet<string>,
): readonly ApprovalState[] {
  return states.filter((state) => applicable.has(state.control) && !state.approved);
}
