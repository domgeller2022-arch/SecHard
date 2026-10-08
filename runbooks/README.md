# Runbooks

Operator procedures for the controls that cannot be verified automatically. Each names the controls
it serves, the steps, and the manual-evidence record to produce.

| Runbook | Controls |
| --- | --- |
| [restore-and-rollback.md](restore-and-rollback.md) | OPS-02, REL-02 |
| [credential-rotation.md](credential-rotation.md) | SEC-03, OPS-03 |
| [incident-response.md](incident-response.md) | OPS-03, SEC-03, OPS-01 |
| [logging-and-alerting.md](logging-and-alerting.md) | OPS-01, PRIV-01 |

**Operator confirmations remain pending until performed.** A runbook is a procedure, not evidence.
The local restore exercise is real evidence for the disposable stack only and never for the hosted
environment.
