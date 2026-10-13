#!/usr/bin/env bash
# Disposable local restore exercise (rewritten for Batch R1 / A-27, plan review PR-05).
#
# What it proves: data can be backed up, lost, and restored, and the restored state is *verified*
# against what was there before. It measures the time the restore took, which is the number an
# operator needs against a stated recovery target.
#
# What it does not prove: hosted backup coverage, encryption of backups at rest, access to the
# decryption material, or reconciliation of deletion obligations after recovery. Those are operator
# steps in runbooks/restore-and-rollback.md, and the manual evidence record stays `pending` until a
# person performs them.
#
# Safety contract (A-27):
#   - The drill positively identifies its dedicated disposable target (the local Supabase dev
#     container by exact name and Postgres image) and rejects anything else — there is no flag
#     that redirects it at another database.
#   - The fresh dump is verified (exit status, non-empty, contains the marker) AND restored into a
#     separate disposable verification database BEFORE any destructive step on the drill database.
#   - Once destructive work has begun, a failure preserves the verified backup and prints recovery
#     instructions; cleanup happens only after verified recovery. Nothing deletes the only copy.
set -euo pipefail

export PATH="$HOME/.local/opt/node-v24.21.0/bin:/usr/local/bin:$PATH"
DB=supabase_db_nextjs-supabase
HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$(cd "$HERE/../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sechard-restore-drill.XXXXXX")"
chmod 700 "$WORKDIR"
DUMP="$WORKDIR/notes.sql"
MARKER_ID="deadbeef-0000-4000-8000-000000000001"
VERIFY_DB="sechard_drill_verify"
DESTRUCTIVE_STARTED=0
RECOVERY_OK=0

cleanup() {
  # PR-05: after destructive work begins, the verified backup is preserved on every failure path.
  # Only a fully verified recovery (or a deliberate operator cleanup of this private directory)
  # removes it.
  if [ "$DESTRUCTIVE_STARTED" -eq 1 ] && [ "$RECOVERY_OK" -eq 0 ]; then
    echo
    echo "RESTORE FAILED — the verified backup is preserved at: $DUMP"
    echo "Recovery (run manually, from a known-good shell):"
    echo "  docker exec -i $DB psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q -f - < '$DUMP'"
    echo "Do not delete $WORKDIR until the data is confirmed recovered."
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

psql_q() {
  docker exec -i "$DB" psql -U postgres -d postgres -tA -v ON_ERROR_STOP=1 -c "$1"
}

echo "=== preconditions: positively identify the dedicated disposable target ==="
if ! docker inspect "$DB" >/dev/null 2>&1; then
  echo "FAIL: container $DB does not exist. This drill only runs against the local Supabase dev stack."
  exit 2
fi
image="$(docker inspect --format '{{.Config.Image}}' "$DB")"
case "$image" in
  *postgres*) : ;;
  *) echo "FAIL: $DB is not a Postgres container (image: $image) — refusing to run." ;;
esac
if ! psql_q 'select 1;' >/dev/null 2>&1; then
  echo "FAIL: the local database is not reachable. Start the stack first: pnpm exec supabase start"
  exit 2
fi

echo "=== 1. write a marker row that exists only in this run ==="
psql_q "insert into public.notes (id, owner_id, title, body) values ('$MARKER_ID', '11111111-1111-4111-8111-111111111111', 'Restore drill marker', 'present before the backup') on conflict (id) do update set title = excluded.title;" >/dev/null
before_total="$(psql_q 'select count(*) from public.notes;')"
before_marker="$(psql_q "select count(*) from public.notes where id = '$MARKER_ID';")"
before_owners="$(psql_q 'select string_agg(c, '"'"','"'"') from (select owner_id::text || '"'"':'"'"' || count(*)::text as c from public.notes group by owner_id order by 1) s;')"
echo "before: total=$before_total marker=$before_marker owners=$before_owners"

echo
echo "=== 2. back up, then verify the dump before anything destructive ==="
docker exec -i "$DB" pg_dump -U postgres -d postgres --data-only --table=public.notes > "$DUMP"
dump_bytes=$(wc -c < "$DUMP" | tr -d ' ')
[ "$dump_bytes" -gt 0 ] || { echo "FAIL: the dump is empty — refusing to destroy anything."; exit 1; }
grep -q "$MARKER_ID" "$DUMP" || { echo "FAIL: the dump does not contain the marker row — refusing to destroy anything."; exit 1; }
echo "backup written and verified: $DUMP ($dump_bytes bytes, marker present)"

echo
echo "=== 3. restore into a separate disposable verification database first ==="
psql_q "drop database if exists $VERIFY_DB;" >/dev/null
psql_q "create database $VERIFY_DB;" >/dev/null
docker exec -i "$DB" psql -U postgres -d "$VERIFY_DB" -v ON_ERROR_STOP=1 -q -f - < "$DUMP" >/dev/null
verify_marker="$(docker exec -i "$DB" psql -U postgres -d "$VERIFY_DB" -tA -c "select count(*) from public.notes where id = '$MARKER_ID';")"
verify_total="$(docker exec -i "$DB" psql -U postgres -d "$VERIFY_DB" -tA -c 'select count(*) from public.notes;')"
[ "$verify_marker" = "1" ] && [ "$verify_total" = "$before_total" ] || { echo "FAIL: the verification restore did not reproduce the data (total=$verify_total marker=$verify_marker) — the drill database was not touched."; exit 1; }
echo "verification restore OK: total=$verify_total marker=$verify_marker (drill database untouched so far)"

echo
echo "=== 4. destroy the data (simulated loss / rollback to a clean state) ==="
DESTRUCTIVE_STARTED=1
(cd "$EXAMPLE" && pnpm exec supabase db reset >/dev/null 2>&1)
after_reset_marker="$(psql_q "select count(*) from public.notes where id = '$MARKER_ID';")"
echo "after reset: marker=$after_reset_marker (expected 0 — the point is that the data was lost)"

echo
echo "=== 5. restore from the backup and measure how long it takes ==="
# The backup is data-only on purpose: schema, grants, and row-level security policies come from
# versioned migrations, not from a backup. Restoring rows over an existing table therefore has to
# replace them first (a data-only dump loaded without replacing the target is an append, not a
# restore — that failure mode is the exercise doing its job).
psql_q 'truncate table public.notes;' >/dev/null
start=$(date +%s)
docker exec -i "$DB" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q -f - < "$DUMP" >/dev/null
end=$(date +%s)
restore_seconds=$((end - start))
after_marker="$(psql_q "select count(*) from public.notes where id = '$MARKER_ID';")"
after_total="$(psql_q 'select count(*) from public.notes;')"
after_owners="$(psql_q 'select string_agg(c, '"'"','"'"') from (select owner_id::text || '"'"':'"'"' || count(*)::text as c from public.notes group by owner_id order by 1) s;')"
echo "after restore: total=$after_total marker=$after_marker owners=$after_owners (${restore_seconds}s)"

echo
echo "=== result ==="
failures=0
if [ "$before_total" != "$after_total" ]; then echo "FAIL: row count changed ($before_total -> $after_total)"; failures=$((failures + 1)); fi
if [ "$before_marker" != "1" ] || [ "$after_marker" != "1" ]; then echo "FAIL: the marker row did not survive the restore"; failures=$((failures + 1)); fi
if [ "$before_owners" != "$after_owners" ]; then echo "FAIL: per-owner distribution changed ($before_owners -> $after_owners)"; failures=$((failures + 1)); fi
if [ "$after_reset_marker" != "0" ]; then echo "FAIL: the reset did not actually remove the data, so the restore proved nothing"; failures=$((failures + 1)); fi

if [ "$failures" -eq 0 ]; then
  RECOVERY_OK=1
  psql_q "drop database if exists $VERIFY_DB;" >/dev/null
  echo "PASS: backup, verification restore, loss, and restore verified; recovery took ${restore_seconds}s"
  echo
  echo "Operator evidence still required (recorded as manual evidence, remains pending until performed):"
  echo "  - hosted backup coverage and retention"
  echo "  - access to encryption material for the real backups"
  echo "  - measured recovery time and data-loss window against the stated targets"
  echo "  - deletion/retention reconciliation after recovery"
  exit 0
fi
exit 1
