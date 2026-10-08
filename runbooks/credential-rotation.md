# Runbook: credential rotation and revocation

**Controls:** SEC-03 (credential lifecycle, 30-day interval), OPS-03.

## Inventory (do this first)

For every credential: what it is, what it grants, who owns it, where it is stored, who can read it,
and how it is revoked. A credential with no owner has no one to rotate it. This includes database
passwords, provider keys, CI secrets, deployment tokens, and the GitHub token used for platform
tests.

## Rotation

1. Create the replacement with the **minimum scope** the workload needs.
2. Deploy the replacement to every consumer, including CI and the agent's environment if it has one.
3. Verify the workload works with the new credential.
4. Revoke the old credential and **verify the revocation** by attempting to use it. Supabase's own
   documentation is explicit that creating a new key does not revoke a legacy key; the same is true
   of most providers.
5. Record the rotation, the scope, and the revocation check.

## Revocation drill

Perform a revocation on a disposable credential and confirm the request fails. A revoke button that
was never tested is a guess.

## Evidence to record

A manual-evidence record for SEC-03 with the inventory reference, the credential owner, the rotation
date, the revocation verification, and an expiry of at most 30 days. Never record the credential
value itself.
