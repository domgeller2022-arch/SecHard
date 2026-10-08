# Status

> Generated from `docs/implementation-progress.md` (source SHA-256 `c03e434bcc86c285a982962da39a1f7b41e13025cd0605cee3c299f8a8182213`) by
> `node tools/generate-status.mjs`. Do not edit by hand: edit the progress record and regenerate.
> A section appears here only when the record states its state; "verified" means the record's
> stated acceptance checks ran, nothing more.

| Section | State |
| --- | --- |
| Step 00 — Establish the build decisions | `verified` |
| Step 01 — Create the minimal repository | `verified` |
| Step 02 — Schemas and safe input loading | `verified` |
| Step 03 — Author the 35 controls and two profiles | `verified` |
| Step 04 — Planning and the decision engine | `verified` |
| Step 05 — First working CLI and report | `verified` |
| Step 06 — Control dependency and tool execution | `verified` |
| Step 07 — reference application built and verified end to end (2026-10-07) | `verified` |
| Step 08 — authorization matrix verified, with detection proven (2026-10-07) | `verified` |
| Step 09 — Implement the four scanner adapters | `verified` |
| Step 10 — Build verification and the client secret boundary (2026-10-07) | `verified` |
| Step 11 — Guarded live application recipes (2026-10-08) | `verified` |
| Step 12 — Generate and protect agent guidance | `verified` |
| Step 13 — GitHub workflows and the trusted final gate (local half) | `awaiting_external_verification` |
| Step 14 — Manual evidence and operational recipes (2026-10-08) | `verified` |
| Batch R — Repair (remediation plan, 2026-10-08) | `verified` |

## Open findings and blockers

These are not generated: the authoritative list is in `docs/implementation-progress.md` and
`CHANGELOG.md`. The short version, as of Batch R:

- no scanner, build, or live recipe is wired into `check` yet (audit C1; Batch W);
- a pull request still supplies its own `.hardening/` records (audit H4; Batch W3);
- the local development stack is reachable from the LAN (open finding; no batch owns it yet);
- AUTH-02 recovery isolation and genuine session expiry are untested;
- no `LICENSE` and no security contact **by owner decision**: private, sole-maintainer, and
  undistributed; OPS-03 stays unmet and release evaluation blocks, which is correct while no release
  is planned;
- platform verification (Step 13) awaits the owner's throwaway GitHub account;
- audit-mode isolation for executing untrusted application code is undefined (Batch U).

