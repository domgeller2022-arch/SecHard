# Audit mode (`hardening audit`)

Batch U of the remediation plan (`docs/audit/2026-10-08-remediation-plan.md`, section "Batch A —
Audit mode", renamed U by the gap analysis D11). This document is the contract: what an audit does,
what it refuses to do, and why. Everything here is enforced by tests, not by intention.

```text
hardening audit PATH [--url ORIGIN] [--out DIR] [--depth quick|standard|deep] [--allow-local]
```

`PATH` is a local folder. `--policy` defaults to the shipped policy root, so an audit needs no
configuration.

## The never-writes contract (gap D9)

SecHard audits and suggests; it never modifies the audited code. Concretely:

- nothing is created, changed, or deleted inside the target tree — including caches, `.hardening/`
  records, and temporary files;
- all output goes to `--out` (default `sechard-audit-<timestamp>/` in the working directory), which
  **must live outside the target** — an `--out` inside it is refused with exit 2;
- scanner raw reports, the ephemeral manifest, the target inventory, and all four report formats
  live under `--out`; scanners read the target, they never write to it.

Enforcement: the acceptance test checksums the whole target tree (names and bytes) before and after
each audit and requires the digests to be identical.

## How an audit runs (it does not bypass the machinery)

1. **Detection** (`src/audit/detect.ts`) — a bounded, read-only walk identifies the stack
   (Next.js, Vite/React SPA, SvelteKit, Node API, Python web, Go, Expo, React Native, Flutter,
   Electron, or unknown) and features (payments, runtime AI, uploads, webhooks, persistent storage,
   …). Every detection records its evidence (the file and the pattern). An undetectable feature
   stays `unknown`, never silently `disabled` — the catalogue's rule.
2. **Profile composition** — `core` always, plus the stack profile, plus `supabase` when Supabase is
   detected and `payments` when payment processing is detected. A composed profile that is not
   loadable policy is dropped and recorded.
3. **An ephemeral manifest** is generated into `<out>/records/.hardening/` — never into the target —
   pinning the real policy commit, and validated against the same schema every consumer manifest
   must pass. If the generated manifest fails validation, the audit exits 2: the generator is the
   bug and must not paper over itself.
4. **Plan, check, and gate run through the same code a gate-mode consumer uses.** The audit does not
   have its own evaluation. A blocked gate in an audit means "obligations exist that source alone
   cannot satisfy" (manual attestations, release evidence), never "the application failed".
5. **The report** (`report.md`, `report.html`, `report.json`, `report.sarif`) is generated from the
   same evaluation; formatting cannot change the decision.

## Depths (gap D8)

| Depth | What runs | What it never does |
| --- | --- | --- |
| `quick` | static scanners: gitleaks repository (head), osv-scanner, opengrep, zizmor | no history scan, no client-bundle inspection, no live checks (each reports `unsupported` with the stated reason, never a silent skip) |
| `standard` (default) | everything quick, plus the full git-history secret scan, client-bundle inspection when build output exists, and live HTTP when `--url` is supplied | never executes application code |
| `deep` | the same set as `standard` in this build | deeper work — executing the application's own build and tests, live exposure probes — requires the audit isolation model (below) and is refused, with the report saying so |

## Application code is never executed (gap D1)

Every wired recipe reads files or makes bounded HTTP requests to an operator-approved target. No
recipe runs `npm test`, `next build`, or any script from the audited project. An audit therefore
needs no isolation model — and audit mode that executes untrusted project code is deliberately not
built: when that arrives (a container/VM execution path, an operator requirement), it will be
opt-in and refused when isolation is unavailable. The report's "What we could not check" box lists
the build/test/functional checks as not run rather than implying they passed.

## The `--url` guard (gap D6)

`--url` enables live checks against exactly one origin, approved by the person running the command.
The guard (`src/audit/url-guard.ts`) refuses:

- everything private: loopback (127/8, `::1`, `localhost`), link-local (169.254/16, `fe80::/10` —
  which includes cloud metadata services), RFC1918 (10/8, 172.16/12, 192.168/16), unique-local
  IPv6 (fc00::/7), mapped-IPv6 spellings of any of these, and shared/reserved space;
- URLs with embedded credentials, non-HTTP(S) schemes, and anything but an origin (a deep path is
  refused, because a half-remembered URL must not silently become the wrong target);
- hostnames that **resolve** into any refused range — the resolved addresses are what will actually
  be contacted, so they are checked and recorded in the report.

`--allow-local` is the explicit local-development opt-in the gap analysis requires. Plain HTTP is
only ever accepted with it, and such targets are pinned to the `local` environment. Note what the
catalogue itself decides: the transport controls (WEB-02, DEPLOY-01) apply to staging and
production, so an `http://localhost` audit records the target and honestly runs no transport check.

The generated target inventory is validated by the same loader the recipe uses; a generated
inventory that does not validate can never be honoured.

## What an audit reports

- **Two scores with plain verdicts** — security (severity-weighted, over the checks that ran) and
  quality (not assessed in this build; the quality controls are Batch Q). Both carry the coverage
  caveat: "N of M planned checks produced an answer". Quality can never change the security
  verdict, and the reverse.
- **Fix these first** — the top findings by severity, then deployed-surface exposure
  (browser-shipped and live findings outrank source-only ones of the same severity).
- **What we could not check** — every unsupported or errored check with its reason, detection gaps,
  the depth note, manual obligations, and the TLS boundary. Nothing is listed as a pass that did
  not run.
- **Every finding** says: what it is, where, why it matters in plain English, how to fix it, effort
  (S/M/L), confidence (`confirmed` for exact-shape rules, `likely` for static-analyser patterns,
  `signal` for advisory information — a heuristic is never presented as proof), control and
  standards references (chapter-level `related_risk` until Batch S), and a ready-to-paste prompt
  for an AI assistant. SecHard suggests; the prompt makes the fix, it never applies one.
- **`report.sarif`** for GitHub code scanning: validated against the vendored SARIF 2.1.0 schema
  (gap D5), redacted, artifact URIs relative or the approved URL (no absolute local paths), and
  **no snippets ever** — a secret finding's snippet would be the secret.

## Honest boundaries, stated rather than implied

- **Local folder only.** The plan's goal sentence mentioned a Git URL; the trust rules for cloning
  an untrusted repository (shallow clone, no submodules, no hooks, no LFS smudge) are deliberately
  not built, so the claim was dropped instead of faked. Clone it yourself, then audit the folder.
- **Python static analysis does not run** — the reviewed Opengrep rule pack is JavaScript/
  TypeScript only; the `python-web` profile does not require the method rather than fabricate
  coverage. Python rules are expansion-batch work.
- **Unsupported stacks** (Expo, React Native, Flutter, Electron, unknown) produce a prominent gap
  banner in the report; the generic checks (secrets, dependency advisories, workflows) still run
  and their findings are real.
- **Exit codes**: `0` the audit ran and produced its report (findings included — they are the
  product); `1` some check errored (for example a scanner missing — the report says which);
  `2` invalid inputs (unreachable target, `--out` inside the target, a refused `--url`). An audit
  is advisory and produces no release evidence; its report is the deliverable.

## Tests

- `tests/audit/` — detection, the URL guard, explanations, and the report (scores, ordering,
  redaction, escaping, SARIF schema validity, depth notes). No tools needed.
- `tests/scanners/audit-cli.test.ts` — the acceptance: real audits through the compiled CLI on a
  Vite+Supabase app, a Python FastAPI app, and an Expo app; the reference application; the
  tree-digest never-writes proof; depth semantics; `--out` and `--url` refusals; and the
  production live-check path against a self-signed local server, whose honest `tls-invalid`
  finding is asserted end to end.
