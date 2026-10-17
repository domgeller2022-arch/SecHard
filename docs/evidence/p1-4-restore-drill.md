# P1.4 evidence — live restore drill (observed 2026-10-15)

**Result: PASS — exit 0.** `SECHARD_DRILL_STANDALONE=1 bash tests/operations/restore-exercise.sh`
(escape to a private log):

1. Target positively identified: container `supabase_db_nextjs-supabase`, image
   `public.ecr.aws/supabase/postgres:17.6.1.171`, compose working directory inside the example.
2. Marker row written; backup dumped and verified (1020 bytes, marker present) before anything
   destructive.
3. Verification restore into a separate disposable database (`sechard_drill_verify_<ts>_<pid>`,
   created only after an existence check) with a minimal auth stub, loaded from a schema+data
   dump — reproduced the data exactly.
4. Destructive reset (standalone mode: schema rebuilt from the repository's own migrations —
   `supabase start`'s full stack cannot sustain its health checks on this machine, recorded
   honestly); marker=0 after reset, proving real data loss.
5. Restore from the verified backup: total=1, marker=1, per-owner distribution identical;
   recovery measured at **1s**; PASS; cleanup after verified recovery only.

Safety events during bring-up (each failed safely, backup preserved, no destructive step run):
the FK violation (no parent auth user), two auth.users column-shape mismatches, and the missing
auth stub in the verification database — each fixed in the drill script and re-run. The
standalone reset mode is recorded in the script with its reason.

Operator evidence still outstanding (unchanged): hosted backup coverage/retention, encryption
material access, measured recovery vs stated targets, deletion/retention reconciliation.
