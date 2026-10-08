# Runbook: logging, redaction, and alert delivery

**Controls:** OPS-01 (30-day interval), PRIV-01.

## What to log

Authentication outcomes, authorization denials, administrative and configuration changes, and
credential use. Each entry should answer who, what, when, and from where, without containing the
sensitive value itself.

## What never to log

Credentials and session tokens, full request bodies containing personal data, and secrets echoed from
configuration. This repository's own rule applies to logs as much as to reports: redact before
emission, and never reproduce an exposed value to illustrate a fix.

## Alert delivery

Configure one alert route, then **send a synthetic alert and confirm it arrived**. A configured route
is not evidence that a message reaches anybody. Record who received it and when.

## Evidence to record

A manual-evidence record for OPS-01 with the logging scope, a redaction sample, the synthetic alert
delivery confirmation, and an expiry of at most 30 days. The delivery confirmation is the part that
cannot be automated honestly.
