-- Notes: schema, constraints, grants, and row-level security.
--
-- Policy and grants live in a migration so they are reviewed like any other code and cannot drift
-- from the schema by being applied by hand.
--
-- The two properties this migration exists to establish:
--   1. A note belongs to exactly one user, and that owner is set from the authenticated session,
--      not from client-supplied data.
--   2. Ownership cannot be reassigned by a client. The policy's WITH CHECK makes the proposed row
--      subject to the same rule as the existing one, so setting owner_id to somebody else fails
--      rather than transferring the note.

create extension if not exists "pgcrypto";

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  body text not null default '' check (char_length(body) <= 20000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.notes is
  'Private notes. owner_id defaults to the authenticated user and is enforced by the policy below.';

create index notes_owner_id_idx on public.notes (owner_id);

alter table public.notes enable row level security;
-- Belt and braces: RLS is the control, but a table owner can bypass it, so force it for the table
-- owner too. This stops a migration or a privileged session from accidentally reading every row
-- without meaning to.
alter table public.notes force row level security;

-- One owner-scoped policy for every operation. USING governs which existing rows are visible and
-- WITH CHECK governs proposed rows; stating both makes the intent explicit rather than relying on
-- PostgreSQL's implicit behaviour.
create policy notes_owner_all on public.notes
  for all
  to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- Grants are separate from policies: a policy cannot grant access that was never granted, and a
-- grant without a policy would expose the table. Both are required, so both are stated.
revoke all on public.notes from anon, public;
grant select, insert, update, delete on public.notes to authenticated;

-- Anonymous users get nothing at all. Stated explicitly so that a future default-privilege change
-- in the database does not quietly open the table.
revoke all on public.notes from anon;
