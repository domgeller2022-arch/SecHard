# P3.4 evidence — browser assets, source maps and scope identification (observed 2026-10-16)

A-21, and the browser-scope half of A-32 (the payments/Vite-detection half of A-32 lands with
P3.5 per the plan's split of `assigned_subphases: P3.4/5`).

## What changed

1. **A-21 fixed at the analyzer** (`src/build/client-assets.ts`): a shipped `.map` is no longer
   inventoried-only — it flows through the same size bounds, read, marker scan and JWT role
   classification as any other shipped file, so a privileged value only in a map (including
   inside embedded `sourcesContent`) fires with the same blocking secret class as a bundle.
   A malformed map is recorded as an explicit incompleteness ("scanned as text, but the map
   structure is unverified") and still text-scanned; an oversized map is recorded, not read, and
   the coverage is explicitly partial. The map-publication warning stays a separate, weaker
   finding — publication is not proven sensitive exposure.
2. **Match digests and asset-byte digests** (plan item 4, using the existing `sha256Hex`
   primitive): every secret finding now carries `secret_digest` (SHA-256 of the matched text,
   never the value — the field the Finding type already defines), and every inventoried file
   read within bounds carries a per-file content digest folded into `inventoryDigest`, so
   same-size edits are distinguishable.
3. **A-32 browser-scope half** (`runClientAssets` + new `selectBrowserOutput`): browser output
   is identified from the detected stack's reviewed build shape — nextjs → `.next/static`,
   sveltekit → `.svelte-kit/output/client`/`build`, react-spa → `dist`/`build`/`out` — and a
   generic candidate qualifies only with a browser entry point (`.html`, bounded walk): a Node
   CLI's compiled `dist` is server output and is never scanned as browser-shipped merely because
   the directory exists. Stacks with no reviewed browser shape get an explicit unsupported with
   the reason; the diagnostic names the stack, the basis for the root, and the scope statement
   keeps server output, browser output, maps and deployment configuration separate. The old
   static candidate list (`dist` first, framework-blind) is deleted.
4. `runClientAssets` calls the stack detection a second time (bounded walk, 800-file cap); the
   audit profile already runs it once. Deduping that is a refactor for another subphase, not a
   correctness need.

## Observed (2026-10-16)

- `tests/build/client-assets.test.ts`: 19/19 — new fixtures cover: secret-only-in-map (critical,
  same class as a bundle, value withheld), map match digest present, publishable-in-map
  classified not flagged, malformed map (explicit partial, raw text still scanned), oversized
  map (recorded, not read, partial, publication warning intact), same-size digest change, and
  the selection matrix (node-api has no candidates; a dist without an entry point is not
  browser-shipped even for a vite-flagged stack — the SecHard self-audit shape; dist-with-html
  selected; nextjs static trusted by framework).
- Fast suite 610/610 (42 files); example real-build 5/5; scanners suite 75/75 (8 files),
  including audit-cli; typecheck and lint clean; preflight OK (183 mandatory tasks open).
- Corpus regenerated (`tests/corpus/measure-corpus.mjs`): security 31/38, quality 17/36 —
  **zero seed outcome changes**; the 3-line diff is metadata only (generated_at, the
  measured-build pointer 627222a, audit_out_digest — the run output changed in the
  browser-output recipe's unsupported wording, which no seed pins).

## Limitations and scope

- The payments/Vite-detection half of A-32 (executable import context, dev-only Vite) is P3.5
  per the plan's split; until then the entry-point check keeps Node `dist` out of the browser
  scope regardless of the stack label.
- `sourcesContent` secrets are covered by the raw-text scan (the content is embedded in the
  file bytes); a structure-level `sources`/`sourcesContent` inventory beyond the malformed-map
  check is not claimed.
- The entry-point walk is bounded at 2000 entries; a candidate past the bound is treated as
  unverified (rejected with the reviewed reason), never scanned on faith.
- Map publication on the deployment (as opposed to in the build output) remains part of the
  P7/P8 web checks.
