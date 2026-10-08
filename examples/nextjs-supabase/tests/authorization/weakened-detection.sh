#!/usr/bin/env bash
# Proves the authorization matrix detects a weakened policy.
#
# A test suite that only ever passes proves nothing about its own sensitivity. This script makes the
# boundary genuinely weaker — one extra permissive SELECT policy, the exact mistake that makes one
# user's private rows readable by every authenticated user — runs the same assertions, and requires
# them to FAIL. It then restores the real migrations and requires them to pass again.
#
# The weakened policy is applied to the local development database only, from this script, and the
# database is reset at the end. Production code is never touched.
set -euo pipefail

export PATH="$HOME/.local/opt/node-v24.21.0/bin:/usr/local/bin:$PATH"
DB=supabase_db_nextjs-supabase
HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$(cd "$HERE/../.." && pwd)"

weaken() {
  docker exec -i "$DB" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
create policy notes_read_all on public.notes
  for select to authenticated using (true);
SQL
  echo "weakened: added a permissive SELECT policy for every authenticated user"
}

restore() {
  (cd "$EXAMPLE" && pnpm exec supabase db reset >/dev/null 2>&1)
  echo "restored: migrations and seed re-applied"
}

run_matrix() {
  (cd "$EXAMPLE" && node tests/authorization/run-authorization.mjs 2>&1) || true
}

echo "=== 1. weakened policy ==="
weaken

echo
echo "=== 2. the same matrix must detect the change ==="
weakened_output="$(run_matrix)"
echo "$weakened_output"
if echo "$weakened_output" | grep -q "0 failed"; then
  echo
  echo "RESULT: FAIL — the matrix did not detect a permissive policy. The assertions are too weak."
  restore
  exit 1
fi
echo
echo "detected: the matrix reported failures under the weakened policy"

echo
echo "=== 3. restore the real policy ==="
restore

echo
echo "=== 4. the same matrix must pass again ==="
restored_output="$(run_matrix)"
echo "$restored_output"
if ! echo "$restored_output" | grep -q "0 failed"; then
  echo
  echo "RESULT: FAIL — the matrix does not pass against the correct policy."
  exit 1
fi

echo
echo "RESULT: PASS — detection proven on the weakened variant, correctness proven on the fixed one."
