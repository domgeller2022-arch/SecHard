# Vendored standard data

- `asvs-5.0.0-en.csv` — the official OWASP ASVS 5.0.0 requirement list (English), fetched from the
  `v5.0.0_release` tag of `github.com/OWASP/ASVS` on 2026-10-10. ASVS is licensed CC BY-SA 4.0;
  the licence record and the review-before-distribution note are in `upstream/sources.yaml`
  (`owasp-asvs`). The file is vendored so the requirement-level mapping is checkable against the
  real IDs and levels without a network, and so the owner can review L1 line by line against the
  actual text. The mapping summaries in `../asvs.yaml` are SecHard's own paraphrases.

SHA-256 of the vendored file is recorded in `upstream/sources.yaml` under the `owasp-asvs` source.
