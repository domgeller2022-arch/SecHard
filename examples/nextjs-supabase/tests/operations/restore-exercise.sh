#!/usr/bin/env bash
# Disposable local restore exercise.
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
# It operates only on the local development stack. Production is never touched.
set -uo pipefail

export PATH="$HOME/.local/opt/node-v24.21.0/bin:/usr/local/bin:$PATH"
DB=supabase_db_nextjs-supabase
HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$(cd "$HERE/../.." && pwd)"
WORKDIR="${TMPDIR:-/tmp}/hardening-restore-exercise"
mkdir -p "$WORKDIR"
DUMP="$WORKDIR/notes.sql"
MARKER_ID="deadbeef-0000-4000-8000-000000000001"

psql_q() {
  docker exec -i "$DB" psql -U postgres -d postgres -tA -v ON_ERROR_STOP=1 -c "$1"
}

echo "=== preconditions ==="
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
echo "=== 2. back up ==="
docker exec -i "$DB" pg_dump -U postgres -d postgres --data-only --table=public.notes > "$DUMP"
dump_bytes=$(wc -c < "$DUMP" | tr -d ' ')
echo "backup written: $DUMP ($dump_bytes bytes)"

echo
echo "=== 3. destroy the data (simulated loss / rollback to a clean state) ==="
(cd "$EXAMPLE" && pnpm exec supabase db reset >/dev/null 2>&1)
after_reset_marker="$(psql_q "select count(*) from public.notes where id = '$MARKER_ID';")"
echo "after reset: marker=$after_reset_marker (expected 0 — the point is that the data was lost)"

echo
echo "=== 4. restore from the backup and measure how long it takes ==="
# The backup is data-only on purpose: the schema, grants, and row-level security policies come from
# versioned migrations, not from a backup. Restoring rows over an existing table therefore has to
# replace them first. The first version of this script skipped that step and failed with a duplicate
# key — which is the exercise doing its job: a data-only dump loaded without replacing the target is
# an append, not a restore, and an operator following that procedure would corrupt the database.
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
  echo "PASS: backup, loss, and restore verified; recovery took ${restore_seconds}s"
  echo
  echo "Operator evidence still required (recorded as manual evidence, remains pending until performed):"
  echo "  - hosted backup coverage and retention"
  echo "  - access to encryption material for the real backups"
  echo "  - measured recovery time and data-loss window against the stated targets"
  echo "  - deletion/retention reconciliation after recovery"
  exit 0
fi
export_path_hint="$DUMP"
echo "backup retained for inspection: $export_path_hint"
exit 1
