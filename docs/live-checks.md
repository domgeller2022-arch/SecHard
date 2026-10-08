# Live checks

What this repository does against a running target, what it refuses to do, and what remains manual.

## Approved targets only

A target exists because an inventory says so. `examples/nextjs-supabase/.hardening/targets.yaml`
lists, per target: scheme, host, port, environment, routes, approved redirect hosts, response limits,
TLS requirements, and per-route requirements. The inventory is schema-validated, and semantic checks
reject a wildcard host, plain HTTP outside the local environment, and an HTTPS target that does not
state TLS is required.

Nothing here contacts a host because a finding, a scanner, or a fetched page mentioned it. A
suggestion is not an inventory.

## The HTTP recipe

`src/adapters/http.ts` asserts the requirements an inventory declares, per route:

- required headers, optionally with a value that must be present;
- private routes that must not be publicly cacheable;
- content that must not appear in a response, such as a stack trace or an internal path.

Boundaries, stated rather than implied:

- requests are **anonymous**; an authenticated requirement cannot be met by this recipe and it does
  not claim to;
- time and response size are capped, and the body is read through a limit rather than after it;
- redirects are checked against the approved list, not followed blindly;
- **TLS**: a successful HTTPS request means Node validated the certificate chain and expiry against
  its trust store. Protocol versions, ciphers, and configuration depth are **not** assessed, and
  require current `testssl.sh` output or explicit manual evidence. A production transport
  requirement cannot be satisfied by the local plain-HTTP target.

Incomplete coverage is not a pass: if a declared route is unreachable, the runner exits non-zero and
reports `partial`. A run that observed nothing reports `unknown`.

```bash
# Start the reference application, then:
node tools/run-live-checks.mjs examples/nextjs-supabase/.hardening/targets.yaml local
```

## What the local run found

The first run against the running application reported two unapproved redirects. One was a
configuration gap (the inventory approved no redirects, and same-origin redirects to the sign-in page
are expected, so `localhost` and `127.0.0.1` were added). The other was a **real design issue**:

- `/auth/callback` built its redirect from `new URL(request.url).origin`, which comes from the
  **Host header**. That is the classic host-header open redirect: a link that looks like your domain
  but points elsewhere. The fix was to stop trusting the header — the route now requires a configured
  `APP_ORIGIN` and returns 500 if it is unset. The inventory was not widened to make the finding go
  away.

After the fix: **3/3 routes observed, coverage complete, 0 findings.**

## ZAP (passive baseline)

| Item | Value |
| --- | --- |
| Image | `ghcr.io/zaproxy/zaproxy:stable` |
| Image digest | `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef` |
| ZAP version | 2.17.0 |
| Mode | passive baseline only. It **does not** perform active attacks, and it provides no authenticated or business-logic coverage; those need controlled staging and a maintained configuration |
| Bounds | spider `-m 1`, total `-T 3` minutes, against the approved local target |

Working invocation, including the detail that cost several attempts: the image runs as `zap` (uid
1000) and `/zap/wrk` is owned by root, so the report cannot be written as the default user. Writing
into a Docker volume as root and copying the report out works, and avoids the macOS bind-mount share
entirely.

```bash
docker run --name zap-capture -u 0:0 -v zapdata:/zap/wrk ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://192.168.5.2:3100 -m 1 -T 3 -J zap-report.json
docker cp zap-capture:/zap/wrk/zap-report.json ./zap-report.json
docker rm -f zap-capture && docker volume rm zapdata
```

`192.168.5.2` is the colima VM's address for the host; the application must be reachable from the VM.

### Findings on the reference application, unresolved

Captured from the real report (`zap-report.json`, SHA-256 `b35b5784a250e49a…`), 60 passes and 7
warnings, no failures:

| Risk | Alert | Instances |
| --- | --- | --- |
| Medium (2) | Absence of Anti-CSRF Tokens | 2 |
| Medium (2) | Content Security Policy (CSP) Header Not Set | 4 |
| Low (1) | Cross-Origin-Embedder-Policy header missing or invalid | 2 |
| Low (1) | Cross-Origin-Opener-Policy header missing or invalid | 2 |
| Low (1) | Cross-Origin-Resource-Policy header missing or invalid | 5 |
| Low (1) | `X-Powered-By` reveals server information | 4 |

These are recorded as **open findings**. A CSP for this application needs nonces for Next's scripts
and is a deliberate piece of work, not a header string; adding a broken policy to close a warning
would be worse than the warning. The CSRF result reflects that the application's mutations are Server
Actions, which do not use tokens — that is a design fact to assess rather than a defect to fix
blindly, and it is why the finding is triaged by a human rather than auto-resolved.

## Optional staging extension points

Active and authenticated scanning belongs in controlled staging, driven by the same inventory: add a
staging target with its real host and routes, then run a maintained active configuration against it.
This repository does not implement a general active-scanning platform, and no active scan is claimed
for v1.

## What is not covered

- Authenticated crawling, active attacks, and business-logic testing.
- Certificate protocol and cipher assessment (`testssl.sh` is recorded but not pinned or run).
- Anything about a deployment that does not exist: the reference application declares hosting
  disabled and is never deployed, which is why production transport evidence is not applicable to it.
  An application that *is* deployed must provide that evidence, and a production release blocks until
  it does.
