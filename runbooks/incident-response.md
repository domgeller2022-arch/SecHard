# Runbook: incident response and disclosure

**Controls:** OPS-03 (90-day interval), SEC-03, OPS-01.

## Before an incident

- A published security contact. Without one there is no report channel, and that is a release
  blocker for a public repository.
- A named triage owner, and a deputy if the owner is unavailable.
- Known containment actions: credential revocation, session invalidation, feature disablement, patch
  deployment, and customer communication.

## During

1. Contain first: revoke the credential or disable the feature. Do not spend the first hour
   investigating.
2. Preserve evidence before changing state, and remember that logs may contain the data under
   investigation — handle them accordingly.
3. Assess scope: which data, which users, which window.
4. Notify according to the applicable obligations. For covered Australian entities the Notifiable
   Data Breaches scheme may require notification for eligible breaches likely to cause serious harm;
   applicability depends on the entity and the data. Record the assessment, including a decision that
   notification is not required.

## After

Record what happened, what was learned, and what changed. An incident that produces no change is an
incident that will repeat.

## Evidence to record

A manual-evidence record for OPS-03 covering the contact, the triage owner, the exercise or the real
event, and the outcome. For this repository the contact field is still unfilled, so OPS-03 is
blocked rather than satisfied.
