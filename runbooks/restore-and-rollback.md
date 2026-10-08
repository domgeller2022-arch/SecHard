# Runbook: restore and rollback

**Controls:** OPS-02 (backup and restoration, 90-day interval), REL-02 (safe rollback, 90-day interval).

## Exercised locally

`examples/nextjs-supabase/tests/operations/restore-exercise.sh` backs up the notes table, destroys it,
restores it, and verifies the row count, the per-owner distribution, and a marker row that exists only
in that run. It fails if the reset did not actually remove the data, because a "restore" that proved
nothing is worse than no exercise.

**A real defect was found by running it.** The first version loaded a data-only dump without replacing
the target's rows and failed with a duplicate key: a data-only dump appended to existing data is an
append, not a restore. The corrected procedure truncates first. Schema, grants, and policies are
deliberately *not* in the backup — they come from versioned migrations, so a restore cannot silently
reintroduce a drifted schema.

## Operator steps for the hosted environment

1. Confirm hosted backup coverage: what is included (database, object storage, configuration), the
   retention window, and where it is stored.
2. Confirm access to the encryption material. A backup nobody can decrypt is not a backup.
3. Restore into a **separate** environment and measure recovery time and the data-loss window against
   the stated targets.
4. Verify integrity: row counts, per-tenant distribution, and a known record.
5. Reconcile deletion and retention obligations after recovery: data that was deleted before the
   backup existed comes back, and that must be handled deliberately.
6. Rollback compatibility: confirm the previous application version can read the current schema, and
   that migrations are reversible or that a forward fix is documented.

## Evidence to record

A manual-evidence record for OPS-02 and one for REL-02, with operator identity, time, the
environment, a configuration fingerprint, supporting references, and an expiry. **The local exercise
is not evidence for the hosted environment**, and the record stays `pending` until a person performs
the steps above.
