# Batch U checkpoint

Batch U of `docs/audit/2026-10-08-remediation-plan.md` (the plan's audit-mode batch, renamed U by
the gap analysis), worked after Batch W on the owner's instruction to continue with the next phase.
Scope: A1–A4 plus the before-A gap items D1, D2, D5, D6, D8, D9.

## Status

- **U1 — the audit command: verified.** `hardening audit PATH` with depths, `--url`, `--allow-local`,
  and the never-writes contract enforced by a tree-digest test. The ephemeral manifest validates
  like any consumer manifest, and the audit runs through the real plan/check/gate machinery.
- **U2 — detection: verified.** Bounded read-only walk, per-detection evidence, `unknown` (never
  `disabled`) for undetectable features, gap banners for unsupported stacks.
- **U3 — the report: verified.** Four formats from one evaluation; prioritised plain-English
  findings with prompts; SARIF validated against the vendored 2.1.0 schema with no snippets and no
  absolute local URIs.
- **U4 — composable profiles: verified, with recorded omissions.** Six new profiles composed from
  detection; `nextjs-supabase` kept rather than replaced; the `quality` profile deferred to Batch Q;
  firebase/uploads/runtime-ai/multi-tenant have nothing to select yet and are reported as detection
  gaps.

## What now works

One command, no setup, on any folder — `hardening audit PATH --out SOMEWHERE_ELSE` produces
`report.md`, `report.html`, `report.json`, and `report.sarif` with real findings from every wired
scanner, a prioritised fix list, and an honest list of everything it could not check. The audited
folder is byte-identical afterwards.

## Checks actually run

| Command | Outcome |
| --- | --- |
| `pnpm test` | 510 passed, 31 files (34 new audit unit tests, 2 regression tests) |
| `pnpm run test:scanners` | 27 passed (9 new audit CLI acceptance tests; real scanner runs) |
| `pnpm run test:integration` / `test:example` | 8 / 5 passed |
| `pnpm run typecheck` / `typecheck:tools` / `lint` | clean |
| Audit, Vite+Supabase fixture | gitleaks repository+history, opengrep, zizmor, osv findings; tree digest unchanged |
| Audit, Python FastAPI fixture | PYSEC advisories for the pinned `requests==2.19.1` and `fastapi==0.95.2`; gitleaks reports why it cannot run |
| Audit, Expo fixture | unsupported-stack banner + real lockfile advisories (a gap banner, not a clean report) |
| Audit, the reference application | stack nextjs, profiles core + nextjs + supabase, zero committed secrets |
| `--url https://127.0.0.1:<port> --allow-local` against a self-signed local server | the production live-check path runs end to end and reports the honest `tls-invalid` critical finding |
| `--url http://169.254.169.254/` etc. | refused, exit 2, no request made |

## Defects found in this batch (all fixed, all with regression tests)

1. The control-matrix classifier dropped all-`mixed` controls into `manual_only`, mislabelling
   eight controls and contradicting that word's definition. Batch W had also edited SEC-01 to v2
   without regenerating the matrix, hiding the drift until this batch regenerated it.
2. The live HTTP adapter read only the outer "fetch failed" message and classified unverified-TLS
   connections as generic unreachable routes (Node nests the real error in `error.cause`).
3. A test-harness defect: the first live acceptance test hosted its HTTPS server in the vitest
   process while the CLI helper blocked that event loop; the resulting timeout looked like an
   unreachable route. The server is now a separate child process.

## Deviations from the plan

1. **"Replace the two fixed profiles" became "extend".** `nextjs-supabase` is kept so the example's
   records keep resolving; the composable set is additive. The plan's `quality` profile is deferred
   to Batch Q, when QUAL-02+ controls exist to select.
2. **The Git-URL goal is dropped, not implemented** (the plan allowed either): the trust rules for
   cloning untrusted repositories are their own batch of work, and faking the claim was the worse
   option.
3. **`--url` live checks only run the transport path for `https` origins** because the catalogue
   itself scopes WEB-02/DEPLOY-01 to staging/production; a plain-HTTP local target is recorded and
   honestly runs no transport check. The plan's "generated inventory" is validated by the recipe's
   own loader.
4. The plan's acceptance ("a Vite + Supabase app, a Python FastAPI app") is met with fixtures under
   `tests/fixtures/audit/` rather than full scaffolded applications: the fixtures carry the real
   detection evidence and the real vulnerable scanner inputs, which is what the acceptance asserts.

## Blockers and owner actions needed

1. **Batch authorisation** for the next batch — Batch Q (quality) or S (standards); the plan's
   order proposes Q next, with S able to run in parallel.
2. **SARIF schema licence review before any distribution** (owner action, recorded in
   `upstream/sources.yaml`): the schema is OASIS material under the OASIS IPR policy; it is vendored
   for validating SecHard's own output in a private, undistributed repository.
3. Unchanged: a real pull request to exercise the PR workflow's platform half; LAN binding and
   AUTH-02 recovery/session remain unowned by any batch.

## Owner review list

- `docs/audit-mode.md` — the full audit contract: never-writes, depths, the `--url` guard, honest
  boundaries.
- `src/audit/detect.ts` and `src/audit/url-guard.ts` — what detection claims, and what the guard
  refuses (with the cloud-metadata case).
- `profiles/{nextjs,react-spa,node-api,python-web,supabase,payments}.yaml` — the composed control
  selections, method sets, and exception policies (all `draft`; never-wins unions preserve the
  reference behaviour).
- `src/audit/report.ts` — scores, ordering, redaction/escaping, SARIF safety rules.
- `tests/scanners/audit-cli.test.ts` — the acceptance, including the tree-digest proof.

## Known limitations and risks

- Local folder only; `deep` equals `standard` pending the isolation model; Python static analysis
  not run (rule pack is JS/TS only); the audit live path is proven against `--allow-local` https
  targets, not a real deployed origin.
- The FastAPI acceptance audit costs ~5 minutes (osv resolves Python dependencies online); recorded
  as the price of a real-advisory acceptance.
- An audit's security score covers only the checks that ran; the report states the coverage caveat
  beside every score, and a score must never be read without the "could not check" list.
- Most catalogue recipes remain unimplemented, so audits report many honest `unsupported` results;
  a clean application still cannot pass the gate, which is correct.

## Proposed next batch

**Batch Q — quality**: QUAL-02…QUAL-13 controls, SecHard-owned analysis configuration, the
"vibe-coded tells" analyser, the calibration corpus, and applying quality findings to the reference
app (gap A2). Batch S (standards) can run in parallel per the plan. Owner preparation: authorise
the batch and review this checkpoint.
