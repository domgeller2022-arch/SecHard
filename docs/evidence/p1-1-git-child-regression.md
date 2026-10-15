# P1.1 evidence — scanner-owned Git child hardening (observed 2026-10-14)

Regression: `tests/scanners/audit-cli.test.ts` → "P1.1: scanner-owned Git cannot execute
repository-configured helpers". Observed result (local run, tools fetched): **passed** —
1) fixture validity: an unhardened `git log -p -U0` executes the `.gitattributes`-selected
textconv helper (marker created); 2) the full `hardening audit` (standard depth) over the same
repository creates **no marker** through either gitleaks git-mode child (repository/history),
while the committed secret in `leak.key` **remains detectable** in the gitleaks findings and no
secret value appears in results. This is the auditor's R1-01 acceptance: actual launch
behaviour and detection, not just the env spec. CI's scanner self-scan job re-runs it on Linux.

B-06 addendum (p0_d_04, 15 Oct 2026): the auditor's branch review found the detection claim
self-deceiving — `leak.key` stayed in the worktree, so the current-files scan alone could
satisfy the files+history union assertion. The test now removes `leak.key` in a second commit
(the secret exists only in history), asserts the current-files scan holds **no** row for it
(fixture guard), and asserts **`gitleaks/history` alone** reports it through the hardened,
helper-free scan. Observed 2026-10-15: the repaired test passes; the full
`tests/scanners/audit-cli.test.ts` file passes 19/19 (typecheck, lint, and the confinement
suite 7/7 re-verified in the same round).
