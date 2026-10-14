# P1.2 evidence — recursive failure-path persistence regressions (observed 2026-10-15)

Regression: `tests/commands/confinement.test.ts` → "P1.2 (auditor R1-02)" (2 tests). Observed
result: **passed (7/7 in the file)**.
1) Nested unreadable output directory: `out/records` with write/search but no read permission
   and a `.hardening` symlink into the target — the audit refuses before any write (the
   recursive inspection failure propagates through the entry catch), and the target tree is
   verified unchanged afterwards.
2) Failed report write: `report.md` pre-created as a directory — the audit fails loudly
   (nonzero exit) and **no `sechard-raw-*` staging directory remains in the system temp
   directory**: raw scanner output cannot survive a failed run.
