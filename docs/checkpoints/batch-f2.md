# Checkpoint — Batch F2: detection depth (fix brief F-04..F-09)

**State: `in_progress` — the majority of the batch is implemented and verified; three sub-items
are recorded below as the batch's remaining work, each with the plan's own design.** This batch is
unlike F1: it is the largest batch in the brief, and the checkpoint is produced at the point the
owner asked for ("stop at the F2 checkpoint, push to the branch, watch CI").

## Commands actually run

- Full local battery through the compiled CLI: unit **561/561**, typecheck (both configs) and
  lint clean; the scanners, integration, and example suites run in this checkpoint's push.
- The Appendix A calibration corpus (`tests/corpus/independent-nextjs/`, 18 files) audited
  through `hardening audit` at standard depth on a composed copy (secret shapes composed at
  runtime in the shell, per the corpus discipline), with the resulting `results.json` measured
  against the brief's seed list.
- Every new opengrep rule verified against the pinned binary (opengrep 1.30.0) — including the
  negative cases (a literal-valued `dangerouslySetInnerHTML` stays silent; an unverified webhook
  is reported, a `constructEvent` handler is not).

## What landed

1. **Exposure tiers extended (owner decision with the F2 authorisation).** Tracked files keep the
   classifier's grade; untracked-and-gitignored files grade medium; untracked files that are NOT
   gitignored grade high ("a plain git add will commit this file"). The fold restores committed
   severity/title for both tiers; non-git targets are never graded down. Pinned by one CLI test
   (three cases in one app) and two unit tests.
2. **F-04 taint-mode rule pack** (`ci/configs/opengrep-rules/detection-depth.yaml`, 20 rules):
   request-data taint sources into SQL injection (JS + Python), XSS, SSRF (replacing the
   regex-only rule per the brief), path traversal, open redirect, and command injection (JS +
   Python); the non-literal-HTML rule (medium minimum, per the brief); the F-05 pattern rules
   (weak password hashing, JWT none/hardcoded secret, insecure cookies, CORS wildcard+credentials,
   weak randomness, logging secret values, client-side AI SDK, dangerous Next.js config); and the
   F-09 unverified-Stripe-webhook rule, pinned **critical** through a reviewed
   `hardening_severity` metadata convention in the adapter. The `opengrep/rules` recipe now runs
   both packs and merges findings.
3. **F-06 static half — the Supabase migration rules** (`src/security/migrations.ts`, wired as
   `data/migration-inventory`, a recipe DATA-01 declared before it existed — no definition
   change): tables without RLS (state tracked across the migration sequence), `using (true)` /
   `with check (true)` policies, `grant all`/write verbs to anon/public, `security definer`
   without `search_path`, public storage buckets, and views without `security_invoker`. No SQL
   parser dependency, per the plan.
4. **F-07 internal rules** in the existing quality machinery (no new recipes, no definition
   churn): swallowed Supabase errors and mock/demo data in production paths (vibe-tells, comment
   lines and the rule's own definition exempted after the self-audit caught the false positives);
   README commands that do not exist in package.json scripts (repo-hygiene); duplicate-role
   libraries read from package.json when there is no lockfile (dependency-health).
5. **F-09 detection fixes**: payments enabled by dependency (stripe, @stripe/stripe-js, paddle,
   lemonsqueezy) or payment-event handling in source; the webhook event-type detection feeding
   both payments and webhooks; a detection-exclusion list (tests, fixtures, examples, corpora are
   not the app's own stack — SecHard no longer detects itself as its fixtures); and the verbatim
   runtime-AI gap banner when `runtime_ai` is detected with no runtime-ai profile composed.
6. **Zizmor excessive-permissions investigation (F-05's last item): found and fixed.** The audit
   is **persona-gated** in zizmor 1.30.1 — the default persona suppresses it. The recipe now runs
   `--persona=auditor`, and the corpus workflow's `permissions: write-all` surfaces. The
   documented trade-off: the auditor persona also adds anonymous-definition, concurrency-limits,
   and secrets-outside-env findings — more noise, deliberately accepted for an audit tool, and
   zizmor's inline ignores are still respected by the adapter.

## Measured on the Appendix A corpus (before: security 7/33, quality 17/30 at f3c9727)

- **Security seeds: 26/26 fire** — every statically checkable security seed in the brief's list,
  including the variable-assignment SSRF shape, both SQL injection shapes, the stored-XSS and
  non-literal HTML sinks, the unverified Stripe webhook (critical), the migration rules, and the
  secret classifier's rows.
- **Quality seeds: 12/22 fire as reported rows.** The remaining misses split into two recorded
  causes: the quality analysers' per-file reporting caps (the detection exists; rows beyond the
  cap are listed as covered-but-capped in the analyser's own counting, not silently dropped from
  the scope record), and the four F-07 analysers below. The corpus manifest as a permanent test
  (measuring recall per seed through the CLI) is part of the remaining work; the numbers above
  were measured from the audit's results.json in this checkpoint's verification.
- Profiles on the corpus: core + quality + nextjs + supabase + **payments** (was not detected
  before F-09), with the runtime-AI banner present (the corpus depends on `openai`).

## Remaining work in this batch (recorded, not deferred silently)

1. **F-07's four staged analysers** (jscpd, Lizard, Knip, dependency-cruiser). The remediation
   plan's A-2 decision stands: an isolated `tools/quality/` package with a committed lockfile as
   the pin, `--frozen-lockfile`, no install scripts, invoked from its own `.bin`; Lizard as a
   SHA-256-pinned wheel in a fetch-created venv. The A-1 execution-safety work (Knip's config
   plugins execute audited code via jiti — disabled plugins with SecHard's own config; the marker
   fixture proving nothing executes) is designed in the plan and is the reason this is its own
   chunk of work rather than an afternoon wiring.
2. **F-06's second and third steps** (the plan's sequence): `supabase/splinter` — licence verdict
   first, recorded before any code — and the read-only live anon-key probe from the remediation
   plan's X1. The static rules above are valuable on their own, which is why they landed first.
3. **F-08 narration recall** (synonym restatement, density signal, helper headers; acceptance
   recall ≥ 0.7 with zero findings on SecHard's rationale comments) and the corpus manifest as a
   permanent measurement test. Not started: the narration rule's existing shared-identifier form
   is unchanged in this push, and changing it without the measured acceptance in hand is exactly
   the kind of unverified tuning the brief's rule 2 forbids.

## Security-relevant behaviour changes for owner review

- The webhook rule makes an unverified Stripe handler a **critical** finding (the brief's
  requirement); the exposure-tier extension (high for untracked-not-gitignored) is the owner's
  own instruction, recorded in `01-owner-decisions.md`.
- The zizmor persona change increases workflow findings (auditor persona).
- The detection-exclusion list narrows feature detection to the app's own sources — the honest
  direction (SecHard was misdetecting as its fixtures), recorded here for the auditor.

## After this checkpoint

Push to `docs/2026-10-10-follow-up-plan`, watch `repo-checks` to completion, and wait for the
auditor's re-check before Batch F3 (owner instruction, 2026-10-13).
