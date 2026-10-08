# Reference application: nextjs-supabase

A small private-notes application used to exercise the hardening controls against a real stack. It
is deliberately minimal: two normal users, private notes, no payments, uploads, roles, tenancy, or
runtime AI. What makes it useful is not its features but that it is **real** — a real Postgres, real
row-level security, and real unprivileged clients.

## Prerequisites

- Node 24.21.0 and pnpm 12.9.1 (the repository root pins both).
- A container runtime. This machine uses colima; see `policy/toolchain.yaml`.

## Security note before you start the stack

The Supabase CLI binds its services to `0.0.0.0` **inside the container VM**, and colima forwards
those ports to the host on **all interfaces**. On this machine that was observed directly: a request
to the machine's LAN address on port 54321 returned 200. The CLI itself warns about this, along
with the fact that the local keys and JWT secret are shared defaults.

Until that is contained, the local stack is reachable by anything on the same network. The
recommended containment is the macOS application firewall, which needs an administrator:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp /usr/local/opt/lima/bin/limactl
```

`limactl` is the process that listens on the forwarded ports. Verify with `lsof -nP -iTCP -sTCP:LISTEN
| grep 5432` (it will still show a listener, but other machines should no longer reach it) or by
requesting the LAN address from another device.

Two alternatives, both weaker: run the stack only while actively developing and stop it afterwards
(this repository's build did exactly that), or accept that the development machine's network is part
of the trust boundary. The second is not a control; it is a decision, and it should be recorded as
one.

## Commands

```bash
# Start the local stack (Postgres on 54322, data API on 54321).
pnpm exec supabase start

# Apply migrations and seed data to a clean database.
pnpm exec supabase db reset

# Stop the stack. Do this when you are not using it.
pnpm exec supabase stop
```

`realtime` and `analytics` are disabled in `supabase/config.toml`: this application does not use
them, and on the reference machine they came up unhealthy and caused `supabase start` to tear the
whole stack down. Re-enabling one means investigating its health first, not just flipping the flag.

## What is here

- `supabase/config.toml` — local stack configuration.
- `supabase/migrations/` — schema, grants, row-level security policies, and seed data. Policy and
  grant changes belong in migrations so they can be reviewed like any other code.
- `.hardening/` — this application's manifest, assessments, and exceptions. These are the
  application's own records; the controls live in the hardening repository.
