# P1.3 evidence — bounded-read primitives at open time (observed 2026-10-15)

Primitive: `src/evidence/bounded-io.ts` — `readBoundedSync(path, maxBytes)`: at most maxBytes are
allocated and read at open time (never a whole-file buffer sliced afterwards); symlinks and
non-regular files return undefined instead of being followed; unreadable files return undefined
and callers count the omission.

Adopted by every source-reading scanner: `detect.ts` readText (unreadable files now appear in
the detection gaps as "source files that could not be read: N"), `quality/common.ts`
readFileSyncText, `security/migrations.ts`. Regression: `tests/commands/bounded-io.test.ts`
(observed **passed, 2/2**): a 1 MiB input returns exactly 4096 bytes; an unreadable file and a
symlink to /etc/hosts return undefined. Full unit suite after adoption: **574/574**.
