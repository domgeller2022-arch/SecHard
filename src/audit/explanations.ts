import type { Finding } from '../domain/types.js';

/**
 * Plain-English explanations for audit findings.
 *
 * The audit report is written for an owner who does not read code: every finding must say what it
 * is, why it matters, and how to fix it, without assuming the reader knows what a rule id is.
 *
 * Honest labelling rules (remediation plan Q/A3):
 * - `confidence` states how strong the signal is. `confirmed` means the rule fires only on an
 *   exact shape (a leaked token pattern, an exact workflow anti-pattern); `likely` means a
 *   static analyser saw the pattern and a human should glance at it; `signal` means the finding
 *   is advisory information rather than a defect (advisory age, source maps).
 * - Nothing here claims proof of anything. A heuristic is never presented as a confirmed defect.
 */

export type Effort = 'S' | 'M' | 'L';
export type Confidence = 'confirmed' | 'likely' | 'signal';

export interface FindingExplanation {
  readonly what: string;
  readonly fix: string;
  readonly effort: Effort;
  readonly confidence: Confidence;
  readonly prompt: string;
}

interface RuleExplanation extends Omit<FindingExplanation, 'prompt'> {
  readonly promptIntro: string;
}

const RULES: Readonly<Record<string, RuleExplanation>> = {
  // --- gitleaks (rule ids come from the reviewed gitleaks config) ---
  'github-pat': {
    what: 'A string shaped like a GitHub personal access token is committed in the source. Anyone who obtains it can act as that GitHub account: read private repositories, approve code, or publish packages.',
    fix: 'Revoke the token in GitHub settings immediately, remove it from the source, and move the replacement into an environment variable or a secrets manager. If it exists in git history, rewrite the history or treat the repository as compromised.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A GitHub token-shaped string is committed in the source. Revoke it, then remove it from the code and read it from an environment variable instead.',
  },
  'database-url-with-password': {
    what: 'A database connection string with the password embedded in it is present in the source or configuration. Anyone who reads the file — a leaked repository, a copied codebase, a build log — can connect to that database directly, with whatever data and privileges that account has.',
    fix: 'Move the connection string into an environment variable or a secrets manager, rotate the password (it must be treated as exposed), and confirm the database account is not more privileged than the application needs.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A database connection string with an embedded password is committed in the source. Remove the embedded credentials, read the connection string from the environment instead, keep the application connecting successfully, and note that the password must be rotated.',
  },
  'generic-api-key': {
    what: 'A string that looks like a generic API key or secret is committed in the source. Committed credentials are the most common cause of account takeover: code gets copied, pasted, and shared far beyond where it was written.',
    fix: 'Revoke the credential with its provider, remove it from the source, and load it from an environment variable or a secrets manager. Check git history too: removing it today does not remove it from old commits.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A secret-shaped value is committed in the source. Remove it, read it from the environment instead, and keep the application working.',
  },
  'private-key': {
    what: 'A private key is committed in the source. A private key is the identity itself — with it, an attacker can impersonate the service, sign tokens, or decrypt traffic.',
    fix: 'Revoke or rotate the key everywhere it is used, remove it from the source and from git history, and store the replacement in a secrets manager. Treat any system that trusted the key as exposed.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A private key is committed in the source. Remove it and its passphrase handling, load it from a secrets manager instead, and keep the service working.',
  },
  'slack-bot-token': {
    what: 'A string shaped like a Slack bot token is committed in the source. It allows whoever holds it to read and post in the workspace as the bot.',
    fix: 'Revoke the token in the Slack app settings, remove it from the source, and load the replacement from the environment.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A Slack bot token is committed in the source. Remove it and read it from an environment variable instead.',
  },

  // --- opengrep (the reviewed local rule pack) ---
  'hardening.no-eval': {
    what: 'The code runs `eval` (or a similar dynamic evaluation) on a value. If any part of that value can be influenced by a user, this becomes remote code execution: an attacker can run their own code inside the application.',
    fix: 'Replace `eval` and `new Function` with explicit logic or a safe parser (for example `JSON.parse` for data). If the input is truly static, that should be provable — otherwise treat it as user-controlled.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'An `eval` call appears in the source. Replace it with explicit logic or a safe parser, keep behaviour identical for the existing inputs, and do not weaken any security test.',
  },
  'hardening.child-process-exec-interpolation': {
    what: 'The code builds a shell command with interpolated values. If any part of the interpolated value comes from a user, an attacker can append their own commands after it.',
    fix: 'Pass arguments as an array (`execFile`/`spawn` with an argument list) instead of building a command string, so values can never be re-interpreted by a shell.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A child-process call interpolates values into a shell command string. Switch to an argument-array API (`execFile` or `spawn` without `shell: true`) so user values stay data, and keep behaviour unchanged.',
  },
  'hardening.dom-innerhtml-assignment': {
    what: 'The code assigns to `innerHTML` with a value that may not be fully controlled by the application. This is the classic cross-site scripting path: injected markup runs as the page.',
    fix: 'Assign text with `textContent`, or build nodes explicitly. If rich formatting is required, sanitise the value with a reviewed sanitiser and an explicit allowlist.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'An `innerHTML` assignment may inject markup. Replace it with `textContent` or explicit DOM construction, preserving the intended rendering.',
  },

  'hardening.taint-sql-injection': {
    what: 'A database query is built from request-controlled data (a query parameter, request body, or JSON payload flows into pool.query, cursor.execute, or similar). The value can change the SQL statement: this is SQL injection, the classic path to reading or destroying a whole database.',
    fix: 'Use parameterised queries with placeholders ($1, ?, :name) so the driver sends data separately from the statement. Never build SQL with string concatenation or template interpolation.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A database query interpolates request-controlled data. Rewrite it with parameterised queries (placeholders bound by the driver), keep the query results identical, and add a test proving special characters are treated as data.',
  },
  'hardening.taint-sql-injection-python': {
    what: 'A Python cursor executes SQL built from request-controlled data with an f-string or % formatting. The value can change the statement: SQL injection.',
    fix: 'Use cursor.execute with parameter binding (the second argument) instead of formatting the value into the SQL text.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A Python cursor interpolates request data into SQL. Switch to parameter binding (execute(sql, params)), keep the query results identical, and add a test for quote handling.',
  },
  'hardening.taint-xss-innerhtml': {
    what: 'Request-controlled data reaches innerHTML, document.write, or dangerouslySetInnerHTML. Whatever the value contains runs as markup and script in the browser: this is cross-site scripting, and it steals sessions and data.',
    fix: 'Render text nodes (textContent, JSX text) instead of markup. If markup is genuinely required, sanitise with a reviewed sanitiser (DOMPurify) and an explicit allowlist.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'Request-controlled data flows into an HTML sink. Render it as text (textContent or JSX text nodes), or sanitise with a reviewed library, keeping the visible output equivalent for safe input.',
  },
  'hardening.nonliteral-html-sink': {
    what: 'A value that is not a plain string literal reaches an HTML sink (dangerouslySetInnerHTML, innerHTML, document.write). Whatever computes it - a database field, an API reply, decoded markdown - ends up as markup in the page. Even without a visible attacker path today, this is the line an injection will use.',
    fix: 'Render text nodes, or sanitise with a reviewed sanitiser and an explicit allowlist before the value touches the DOM.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A non-literal value reaches an HTML sink. Render it as text or sanitise it with a reviewed library, keeping the visible output equivalent for trusted content.',
  },
  'hardening.taint-ssrf-fetch': {
    what: 'A network request is made with a request-controlled URL. The request then goes wherever the caller wants - internal metadata services, admin endpoints behind the firewall, cloud credentials. This is server-side request forgery.',
    fix: 'Validate the destination against an allowlist of protocols and hosts before making the request, and prefer fixed URLs with user data limited to path parameters.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A fetch uses a request-controlled URL. Add a protocol and host allowlist check before the request (reject everything not explicitly permitted), keep the legitimate destinations working, and add a test for a blocked host.',
  },
  'hardening.taint-path-traversal': {
    what: 'A file path is built from request-controlled data. A value like ../../etc/passwd escapes the intended directory: the request reads or writes arbitrary files on the server.',
    fix: 'Resolve the requested name against a fixed base directory and verify the resolved real path is still inside it (path.resolve plus a startsWith check) before touching the filesystem.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A filesystem call uses a request-controlled path. Resolve the name against a fixed base and reject anything that escapes it, keep legitimate reads working, and add a test for a ../ escape.',
  },
  'hardening.path-traversal-concat': {
    what: 'A filesystem read is built by concatenating or joining a value into a fixed path prefix. A value like ../../etc/passwd escapes the directory: the request reads or writes arbitrary files.',
    fix: 'Resolve the requested name against the base directory and verify the resolved path is still inside it before reading or writing.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A filesystem call concatenates a value into a path. Resolve against a fixed base and reject escapes, keep legitimate reads working, and add a test for a ../ escape.',
  },
  'hardening.taint-open-redirect': {
    what: 'A redirect target comes from request-controlled data. An open redirect sends users to an attacker-chosen URL while the browser shows your domain, laundering phishing links.',
    fix: 'Validate the target against an allowlist of relative paths or trusted origins before redirecting; default to a known-safe page when the value fails validation.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A redirect target comes from request data. Validate it against an allowlist (relative paths or trusted origins) with a safe default, and add a test for an absolute external URL being rejected.',
  },
  'hardening.taint-command-injection': {
    what: 'A shell command is built with request-controlled data. Interpolated shell input can chain arbitrary commands: this is full server compromise, not just a bug.',
    fix: 'Stop invoking a shell: use execFile or spawn with an argument array so values stay data. If a shell is unavoidable, validate against a strict allowlist.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A child-process call interpolates request data into a shell command. Switch to execFile/spawn with an argument array so the value stays a single argument, keep behaviour identical, and add a test for a semicolon payload.',
  },
  'hardening.taint-command-injection-python': {
    what: 'A subprocess runs a shell command built from request-controlled data (shell=True or an interpolated command string). The value can chain arbitrary commands on the server.',
    fix: 'Pass an argument list with shell=False so the value stays one argument, or validate against a strict allowlist when a shell is unavoidable.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A subprocess interpolates request data into a shell command. Switch to an argument list with shell=False, keep behaviour identical, and add a test for a shell metacharacter payload.',
  },
  'hardening.weak-password-hash': {
    what: 'A password is hashed with MD5 or SHA-1. These are far too fast to brute-force on modern hardware: a leaked database is effectively plaintext for most users.',
    fix: 'Hash passwords with a memory-hard function (argon2id preferred, bcrypt or scrypt accepted) using a per-user salt, and force a reset on next login so the weak hashes leave the database.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A password is hashed with MD5 or SHA-1. Switch to argon2id or bcrypt with a per-user salt, add a migration path that re-hashes on next successful login, and keep the login tests passing.',
  },
  'hardening.jwt-none-alg': {
    what: 'A JWT is signed or verified with algorithm "none", which strips the signature entirely. Anyone can forge a token with any claims and the verify step will accept it.',
    fix: 'Sign with a real algorithm (HS256 with a strong secret or RS256 with a key pair), and pin the algorithms list on verify to exactly the one algorithm you use.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A JWT uses the "none" algorithm on sign or verify. Pin a real algorithm (HS256 with a strong secret) on both sign and verify, remove none from any algorithms list, and add a test that a forged token is rejected.',
  },
  'hardening.jwt-hardcoded-secret': {
    what: 'A JWT is signed or verified with a string literal as the secret. The literal ships in the source and the repository, so anyone who reads the code can forge valid tokens for every user.',
    fix: 'Load the secret from an environment variable (or a secrets manager), rotate it now that it has been in the repository, and fail closed when it is missing.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A JWT secret is a string literal in the source. Move it to an environment variable with a fail-closed check, keep the token format identical, and note that the old secret must be rotated.',
  },
  'hardening.insecure-cookie': {
    what: 'A session cookie is set without httpOnly or without secure. Without httpOnly any injected script reads it; without secure it also travels over plain HTTP. Both are standard session-hijacking paths.',
    fix: 'Set httpOnly: true, secure: true, and a SameSite policy on every session cookie.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A session cookie is set without httpOnly/secure. Set httpOnly: true, secure: true, and a SameSite policy, and confirm the login flow still works in the browser.',
  },
  'hardening.cors-wildcard-credentials': {
    what: 'Cross-origin access is granted to any origin together with credentials. Any site a user visits can read authenticated responses from this API with the user\'s cookies.',
    fix: 'Replace the wildcard with an explicit allowlist of trusted origins and reflect the request\'s origin only when it is on the list; keep credentials opt-in per origin.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'CORS grants any origin access with credentials. Replace the wildcard with an explicit origin allowlist, keep the legitimate frontends working, and add a test that an unknown origin is rejected.',
  },
  'hardening.weak-random-token': {
    what: 'Math.random() feeds a security value (a token, reset code, OTP, or session identifier). Its output is predictable: an attacker can reproduce the sequence and guess issued values.',
    fix: 'Use crypto.randomBytes (or crypto.randomUUID for identifiers) for anything security-relevant.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'Math.random feeds a security value. Replace it with crypto.randomBytes (or randomUUID for identifiers), keep the value format compatible where callers expect it, and add a test for uniqueness under repetition.',
  },
  'hardening.logging-secret-value': {
    what: 'A console or logger call receives a variable named like a credential. The value lands in log files and aggregators where it outlives the request and is readable by everyone with log access.',
    fix: 'Log a marker (for example "password received") instead of the value; scrub credentials from log lines before they are written.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A log line includes a credential-named variable. Replace the value with a marker, keep the log line informative, and do not log any secret material.',
  },
  'hardening.client-ai-sdk': {
    what: 'An AI SDK client is constructed with dangerouslyAllowBrowser (browser-side initialisation). The browser bundle ships to every visitor, so the embedded key is public and every visitor can spend the account\'s quota.',
    fix: 'Move AI calls behind a server route: the browser calls your API, the server holds the key and forwards the request. Remove the key from any client bundle.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'An AI SDK client runs in the browser with a key. Move the call to a server route that holds the key, have the client call that route, and remove the key from client code.',
  },
  'hardening.dangerous-next-config': {
    what: 'A Next.js build safety rail is switched off. productionBrowserSourceMaps publishes original source to every visitor; typescript.ignoreBuildErrors and eslint.ignoreDuringBuilds deploy code the type checker and linter never saw.',
    fix: 'Fix the underlying type and lint errors and remove the flags. If source maps are needed for support, serve them behind authentication instead.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'Next.js build safety rails are disabled in the config. Fix the type and lint errors so the flags can be removed, and remove productionBrowserSourceMaps unless maps are served behind authentication.',
  },
  'hardening.stripe-webhook-unverified': {
    what: 'A Stripe webhook event is handled without verifying its signature. Anyone who can reach the endpoint can POST a fake event - for example checkout.session.completed - and the handler grants the entitlement: free upgrades, fake refunds, poisoned state. This is a direct money path.',
    fix: 'Read the raw body, verify with stripe.webhooks.constructEvent(body, sigHeader, endpointSecret) before parsing or acting on the event, and reject anything that fails verification.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A Stripe webhook handler reads events without signature verification. Verify with stripe.webhooks.constructEvent(rawBody, stripe-signature header, endpoint secret) before handling, reject failed verification with a 400, and add a test that a forged event is rejected.',
  },

  'supabase.rls-missing': {
    what: 'A table is created in an API-exposed schema without enabling row level security. With RLS off, the database enforces no row checks: the publishable key reaches every row in the table.',
    fix: 'Enable RLS in a migration (alter table ... enable row level security) and add explicit policies for each access the application needs.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A table is created without row level security. Enable RLS in a migration, add policies scoped to the owning user or explicit role checks, and keep the application queries working.',
  },
  'supabase.permissive-policy': {
    what: 'A row-level-security policy uses using (true) or with check (true), which allows every row for every role that reaches the table. The policy is security theatre: RLS is on but enforces nothing.',
    fix: 'Restrict the policy to the owning user (auth.uid() = user_id) or an explicit role check, and name the operations it covers.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A Supabase policy uses using (true) or with check (true). Rewrite it to check the owning user or an explicit role, and add a test that another user cannot read or modify the rows.',
  },
  'supabase.grant-anon-write': {
    what: 'Write privileges (or ALL) on a table are granted to anon or public, so the anonymous publishable key can modify the table directly, bypassing application logic entirely.',
    fix: 'Revoke the grant and rely on RLS policies for access control; grant only SELECT to anon where reads are genuinely public, and only through views or policies.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A grant gives anon/public write privileges on a table. Revoke it, enforce access through row-level-security policies, and add a test that the anonymous key cannot write.',
  },
  'supabase.security-definer-search-path': {
    what: 'A security definer function runs with its owner\'s privileges and no fixed search_path. An attacker who can create objects in a schema earlier in the search path can hijack unqualified names inside the function.',
    fix: 'Add set search_path = public (or an explicit schema list) to the function definition, and prefer revoking execute from public where the function is not meant to be called directly.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A security-definer function lacks a fixed search_path. Add set search_path = public (or an explicit list) to its definition and keep the function behaviour identical.',
  },
  'supabase.public-bucket': {
    what: 'A storage bucket is created or updated with public = true. Every object in it is readable by anyone with the URL - leaked links, screenshots, and user uploads all become public.',
    fix: 'Keep the bucket private and use signed URLs for display; reserve public buckets for genuinely public assets.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A storage bucket is public. Make it private, serve objects with signed URLs where display is needed, and keep the app working for legitimate reads.',
  },
  'supabase.view-security-invoker': {
    what: 'A view in an API-exposed schema does not set security_invoker = true, so it executes with the view owner\'s rights: rows the calling user could never select directly become readable through the view.',
    fix: 'Recreate the view with with (security_invoker = true) so it enforces the calling user\'s policies.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A view lacks security_invoker = true. Recreate it with that setting and add a test that a restricted user sees only their rows through the view.',
  },

  // --- zizmor ---
  'template-injection': {
    what: 'A GitHub Actions workflow interpolates untrusted values (pull-request titles, branch names) directly into a script. A malicious pull request can use this to execute commands inside the workflow — with access to the repository token.',
    fix: 'Pass untrusted values to scripts through `env:` inputs and read them with `"$VAR"` quoting; never interpolate `${{ }}` expressions inside `run:`.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A workflow interpolates an untrusted expression into a `run:` script. Move it to an `env:` mapping and read it as an environment variable in the script.',
  },
  'unpinned-uses': {
    what: 'A workflow uses an action by a mutable tag (for example `@v4`). A compromised or retagged action would run automatically in this repository. Supply-chain attacks on CI actions are not theoretical — several popular actions have been compromised.',
    fix: 'Pin every `uses:` to a full commit SHA. A tag can move; a commit cannot.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A workflow uses an unpinned action reference. Pin it to the full commit SHA of the reviewed version.',
  },
  'dangerous-triggers': {
    what: 'A workflow uses a trigger combination (`pull_request_target` with a checked-out pull request) that lets an untrusted pull request run with repository secrets.',
    fix: 'Split trusted and untrusted work into separate workflows; never check out pull-request code in a workflow that holds repository secrets.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A workflow combines a trust-elevated trigger with untrusted pull-request content. Restructure it so untrusted code never runs in a job that holds repository secrets.',
  },
  'artipacked': {
    what: 'A workflow persists its GitHub credentials to the artifact storage, where a poisoned later step or a downloaded artifact can exfiltrate them.',
    fix: 'Set `persist-credentials: false` on the checkout step unless a later step genuinely needs the token, and pass tokens between steps explicitly.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A checkout step persists its GitHub token into the workspace. Add `persist-credentials: false` and pass credentials explicitly where needed.',
  },
  'excessive-permissions': {
    what: 'A workflow grants write permissions it does not need. Every permission granted is damage an attacker can do with a stolen or injected job.',
    fix: 'Set top-level `permissions: contents: read` and grant only the specific permissions a job genuinely needs.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A workflow holds permissions it does not use. Reduce it to `contents: read` plus the minimum a job actually needs.',
  },

  // --- osv-scanner (rule ids are advisory ids: GHSA-…, CVE-…, MAL-…) ---
  'osv-advisory': {
    what: 'A dependency has a known published vulnerability. The application is depending on a version that has an advisory against it — this needs a decision, not a debate: upgrade, or consciously accept with a reason.',
    fix: 'Upgrade the dependency to the advisory-free version. If a fix is impossible today, record a dated exception with the compensating control and an expiry — do not let it sit unnoticed.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A dependency has a published advisory. Upgrade it to a fixed version, run the tests, and report what changed.',
  },

  // --- client-asset inspection ---
  'browser-source-map': {
    what: 'The browser bundle ships a source map, so anyone can reconstruct the original readable source of the application — including logic that was never meant to be public.',
    fix: 'Keep source maps out of the published build output (upload them to an error tracker privately if needed), and ensure the production build does not emit them into the shipped directory.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The browser build ships source maps. Adjust the build so they are not published with the client bundle, while still being produced for debugging where needed.',
  },
  'jwt-privileged-role': {
    what: 'A browser-shipped value is a JWT that carries a privileged role (for example `service_role`). A privileged key in the browser bundle means every visitor holds the keys that bypass row-level security.',
    fix: 'Remove the privileged key from all client-reachable code and configuration. Server-only code may use it; anything imported by a browser bundle may not.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A privileged-role JWT reached the browser bundle. Find the path that ships it, remove it from all client-reachable code, and keep the application working without it.',
  },

  // --- SecHard-owned quality signals (QUAL-02, QUAL-08, QUAL-09, QUAL-11, QUAL-12) ---
  // Every quality finding is a signal or a measured fact, never proof of authorship or intent.
  'tell.narration-comment': {
    what: 'A comment describes what the next line of code does instead of why it exists. Narration comments rot: the code changes and the narration lies. They are also the classic sign of generated code that no reader ever edited.',
    fix: 'Delete the narration, or replace it with the reason the code exists. The code already says what it does.',
    effort: 'S', confidence: 'signal',
    promptIntro: 'A comment restates what the next line of code does. Delete it or rewrite it to explain why the code exists.',
  },
  'tell.step-narration': {
    what: 'A "Step N" comment tracks the writing process, not the code. It tells a reader nothing about the design.',
    fix: 'Remove the step narration and give things real names.',
    effort: 'S', confidence: 'signal',
    promptIntro: 'A "Step N" narration comment exists. Remove it and let the code structure carry the sequence.',
  },
  'tell.marketing-comment': {
    what: 'A comment asserts quality in adjectives ("robust", "comprehensive", "this ensures") without a reason. Quality claims without evidence are how weak code talks itself past a review.',
    fix: 'Replace the adjectives with the constraint, invariant, or test that demonstrates the claim — or delete the claim.',
    effort: 'S', confidence: 'signal',
    promptIntro: 'A comment asserts quality in adjectives without justification. Replace it with the concrete constraint or test that proves the claim, or remove it.',
  },
  'tell.banner-comment': {
    what: 'A decorative banner comment line — visual filler that only adds scrolling.',
    fix: 'Delete the banner.',
    effort: 'S', confidence: 'signal',
    promptIntro: 'A decorative banner comment exists. Remove it.',
  },
  'tell.emoji-in-source': {
    what: 'Source files contain emoji. Emoji break plain-text logs, some terminals, and diffs, and in production code they are almost always leftover decoration.',
    fix: 'Remove emoji from code, comments, and log messages.',
    effort: 'S', confidence: 'signal',
    promptIntro: 'Source files contain emoji. Remove them from code, comments, and log messages.',
  },
  'tell.placeholder-comment': {
    what: 'A comment marks unfinished work as if it were finished ("TODO: implement", "in a real implementation"). A silent stub ships and then fails far from where it was written.',
    fix: 'Finish the work, or make the gap loud: an explicit error, an issue, and a test that fails while the gap exists.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'A comment marks unfinished work ("TODO: implement" and similar). Either complete the implementation or make the gap fail loudly instead of silently stubbing.',
  },
  'tell.placeholder-code': {
    what: 'Production code uses placeholder or dummy data. Placeholder values in real code paths produce wrong behaviour that looks like a bug and is actually a stub.',
    fix: 'Replace with the real implementation, or move the fixture into clearly-labelled test material.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'Production code uses placeholder or dummy data. Replace it with the real implementation.',
  },
  'tell.hardcoded-local-url': {
    what: 'A hardcoded localhost or example.com address in source is a deployment assumption that breaks silently in every other environment.',
    fix: 'Read hostnames from configuration or environment variables.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A hardcoded localhost or example.com address exists in source. Replace it with configuration or an environment variable.',
  },
  'tell.debugger-statement': {
    what: 'A debugger statement halts execution wherever a debugger attaches — including in production browser tooling.',
    fix: 'Remove the statement; use conditional breakpoints in development tooling instead.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A debugger statement exists. Remove it.',
  },
  'tell.commented-out-code': {
    what: 'A block of commented-out code is kept in the source. Dead code in comments confuses every reader about what actually runs, and version control already remembers it.',
    fix: 'Delete the block.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A block of commented-out code exists. Delete it; version control keeps the history.',
  },
  'tell.comment-dominance': {
    what: "Comments make up more than 60% of this file's non-empty lines — the file is prose with some code attached, which usually means the explanation is doing the code's job.",
    fix: 'Check whether the code should be simpler, or the explanation belongs in documentation.',
    effort: 'M', confidence: 'signal',
    promptIntro: 'Comments dominate this file. Either simplify the code so it needs less explaining, or move the essential explanation into documentation.',
  },
  'ts-suppression': {
    what: 'A type-suppression marker turns the type checker off for a line. Every suppressed error is a defect the compiler found and was told to ignore.',
    fix: 'Fix the type, or use a reason-carrying suppression that fails when the error disappears.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A type-suppression marker silences the type checker on a line. Fix the underlying type error instead of suppressing it.',
  },
  'suppression-density': {
    what: 'This file suppresses the type checker more than the reviewed threshold: the type system has effectively been switched off here.',
    fix: 'Re-enable checking and fix the errors, or record a dated exception for this file with the reason.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'This file exceeds the type-suppression threshold. Restore real type checking and fix the errors it reports.',
  },
  'any-type': {
    what: 'An any/unknown escape removes every check the compiler would have run on this value.',
    fix: 'Replace the escape with the narrowest type the value can actually have.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'An any/unknown escape exists on this line. Replace it with the narrowest accurate type.',
  },
  'any-density': {
    what: 'This file is dense in any/unknown escapes — it certifies nothing about its own correctness.',
    fix: 'Type the values properly.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'This file exceeds the any/unknown threshold. Type its values properly.',
  },
  'suppression-total': {
    what: 'The project-wide type-suppression count is above the reviewed threshold: the type system is being switched off rather than satisfied, everywhere.',
    fix: 'Plan a real cleanup: fix the errors the suppressions hide, then remove the markers.',
    effort: 'L', confidence: 'likely',
    promptIntro: 'The project exceeds its total type-suppression threshold. Reduce the count by fixing the underlying type errors.',
  },
  'focused-test': {
    what: 'A focused (.only) test silently disables every other test in its file. A suite that runs one test certifies one test — and the green check looks identical.',
    fix: 'Remove the .only before merge.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A test is focused with .only, disabling the rest of the file. Remove the .only so the whole suite runs.',
  },
  'skipped-test': {
    what: 'A skipped test records an obligation that is not being met. Permanent skips are decisions hiding as TODOs.',
    fix: 'Fix or delete the test; if it must wait, give the skip a reason and an owner.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'A test is skipped. Fix it or delete it; if it genuinely must wait, record why and who owns it.',
  },
  'tautological-assertion': {
    what: 'An assertion compares a constant to itself. It cannot fail, so it certifies nothing while producing a pass.',
    fix: 'Assert on the behaviour under test.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A tautological assertion exists. Replace it with a real assertion on behaviour.',
  },
  'assertion-free-test': {
    what: 'A test body exercises code and asserts nothing. It produces a green check that certifies only that the code did not throw.',
    fix: 'Add the assertion that decides whether the behaviour is correct — or delete the test.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A test has no assertions. Add assertions that decide correctness, or remove the test.',
  },
  'no-lockfile': {
    what: 'No supported lockfile is committed. Installs are not reproducible, and no scanner can cover a dependency graph it cannot read.',
    fix: "Commit the lockfile the package manager produces.",
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'No lockfile is committed. Add the package manager lockfile so installs are reproducible.',
  },
  'no-gitignore': {
    what: 'No .gitignore file exists; nothing keeps secrets, dependencies, or build output out of commits.',
    fix: 'Add a .gitignore covering dependencies, build output, and environment files.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'No .gitignore exists. Add one covering dependency directories, build output, and .env files.',
  },
  'gitignore-missing-dependencies': {
    what: 'The .gitignore does not exclude dependency directories; committed dependencies make every diff meaningless.',
    fix: 'Add the dependency directory to .gitignore.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The .gitignore does not exclude the dependency directory. Add it.',
  },
  'gitignore-missing-env': {
    what: 'The .gitignore does not exclude environment files — the files where credentials live.',
    fix: 'Add the .env pattern to .gitignore.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The .gitignore does not exclude .env files. Add the pattern so credentials cannot be committed by accident.',
  },
  'no-readme': {
    what: 'No README exists; a newcomer (or you, in six months) has no entry point.',
    fix: 'Add a README stating what the project is, how to run it, and what "done" means.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'No README exists. Add one describing the project, how to run it, and its current state.',
  },
  'no-changelog': {
    what: 'No CHANGELOG exists; changes are invisible between releases.',
    fix: 'Add a CHANGELOG (the Keep a Changelog format works).',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'No CHANGELOG exists. Add one recording notable changes.',
  },
  'no-ci': {
    what: 'No CI configuration exists; nothing checks commits automatically.',
    fix: 'Add a CI workflow that builds, tests, and runs the security checks on every pull request.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'No CI configuration exists. Add a workflow that builds, tests, and runs the security checks on every pull request.',
  },
  'no-licence': {
    what: 'No LICENSE file exists. If the absence is deliberate (private, undistributed), that decision must be recorded alongside it — an unrecorded absence is indistinguishable from an oversight.',
    fix: 'Choose a licence, or record the deliberate decision so the absence is documented.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'No LICENSE file exists. Either add one or record the deliberate decision to have none.',
  },
  'duplicate-role': {
    what: 'Two or more libraries provide the same capability (for example two date libraries). Every extra one is another advisory surface, another install hook, and two ways to do one job for every future reader.',
    fix: 'Pick one and remove the rest.',
    effort: 'M', confidence: 'likely',
    promptIntro: 'The dependency list contains two or more libraries for one job. Pick one and remove the others.',
  },
  'hardening.quality-empty-catch': {
    what: 'An empty catch block swallows a failure completely: the operation failed, nobody was told, and the user finds out later from missing data.',
    fix: 'Handle the error — log with context, return a failure, or rethrow.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'An empty catch block swallows a failure. Handle the error: log it with context, return a failure value, or rethrow it.',
  },
  'hardening.quality-floating-promise': {
    what: 'A .then() chain with no .catch() turns a rejection into an unhandled promise rejection — the failure disappears at runtime.',
    fix: 'Add a rejection handler, or await the call and handle the error locally.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A .then() chain has no .catch(); a rejection would be lost. Add a rejection handler or await the call and handle errors locally.',
  },
  'hardening.quality-console-log-production': {
    what: 'console.log in a production source path is usually leftover debugging, and it leaks internal structure into user-visible logs.',
    fix: 'Remove it, or use a logger with levels.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'A console.log exists in a production source path. Remove it or replace it with a levelled logger.',
  },

  // --- Batch S rules: API Top 10, RFC 9700, Electron ---
  'hardening.api-unvalidated-response-consumption': {
    what: 'An external API response is returned to the caller as parsed data with no visible status or shape validation. A failed or hostile third-party response then flows straight into application state - the unsafe-consumption path.',
    fix: 'Check the response status and validate the payload shape (a type guard or schema) before returning or storing it.',
    effort: 'S', confidence: 'likely',
    promptIntro: 'An external response is returned without a status or shape check. Add the status check and validate the payload shape before returning it.',
  },
  'hardening.oauth-implicit-grant': {
    what: 'An implicit-grant response type hands access tokens directly to the browser, where history entries, logs, extensions, and any script can read them. RFC 9700 prohibits the flow.',
    fix: 'Use the authorization code flow with PKCE; tokens stay on the server side and the browser only carries a short-lived code.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'The OAuth flow uses an implicit grant (response_type token or id_token). Replace it with the authorization code flow with PKCE so tokens never reach the browser.',
  },
  'hardening.electron-node-integration': {
    what: 'Electron nodeIntegration:true exposes Node APIs (filesystem, processes) to renderer code. Any XSS in the renderer becomes remote code execution on the user machine.',
    fix: 'Keep nodeIntegration off and expose reviewed IPC through a preload script.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The Electron renderer enables nodeIntegration. Turn it off and expose reviewed functionality through a preload bridge.',
  },
  'hardening.electron-context-isolation-off': {
    what: 'Electron contextIsolation:false lets page JavaScript reach the preload script context and its privileged objects.',
    fix: 'Keep context isolation on.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The Electron renderer disables context isolation. Turn it back on so page code cannot reach privileged objects.',
  },
  'hardening.electron-sandbox-off': {
    what: 'The Electron renderer runs without the OS sandbox. A compromised renderer gets direct access to more of the machine.',
    fix: 'Leave the sandbox on unless a preload genuinely needs Node; document the exception if one is required.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'The Electron renderer disables the OS sandbox. Re-enable it, or document why the preload needs it off.',
  },

  // --- live HTTP ---
  'unapproved-redirect': {
    what: 'The deployed site redirects a request to a different host than the one approved. Open redirects are used in phishing: the victim sees a familiar start of a URL and lands somewhere hostile.',
    fix: 'Make redirects use a fixed configured origin, and validate any user-influenced redirect target against a strict allowlist.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A route redirects to an unapproved host. Build redirects from a configured origin and validate targets against a strict allowlist.',
  },
  'missing-security-header': {
    what: 'The response is missing a security header the site declared as required. Security headers are the browser-side seatbelts: they stop framing, MIME confusion, and script-injection classes of attack.',
    fix: 'Set the header in the server or edge configuration for every response that should carry it.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A required security header is missing from responses. Add it in the server or middleware configuration for all matching routes.',
  },
  'private-route-publicly-cacheable': {
    what: 'A route with private content is marked publicly cacheable. Shared caches and proxies may store and serve one user\'s private response to another.',
    fix: 'Send `Cache-Control: private, no-store` (or the site\'s equivalent) on authenticated responses.',
    effort: 'S', confidence: 'confirmed',
    promptIntro: 'A private route is publicly cacheable. Set a restrictive `Cache-Control` header on authenticated responses.',
  },
  'route-unreachable': {
    what: 'A declared route did not answer. This is a live-deployment gap: the running site does not serve what the inventory expects.',
    fix: 'Fix the deployment or correct the inventory — a declared route that does not exist is a finding either way.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A declared route is unreachable in the live deployment. Investigate the deployment and restore the route or correct its declaration.',
  },
  'tls-invalid': {
    what: 'The TLS connection could not be verified. An unverified certificate means the connection cannot be trusted: nobody can prove the client talked to the real site.',
    fix: 'Install a valid certificate for the host and make TLS mandatory.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'The live target\'s TLS certificate could not be verified. Fix certificate provisioning for that host.',
  },
  'sensitive-content-in-response': {
    what: 'A response contains content that was declared forbidden (for example internal paths or credential material). Whatever matched should never leave the server.',
    fix: 'Find the code path that renders that content into responses and remove it; keep the forbidden-content declaration in place so it stays detectable.',
    effort: 'M', confidence: 'confirmed',
    promptIntro: 'A response contains content declared forbidden. Find where it is rendered and remove it from the response path.',
  },
};

// Privileged client-asset markers share one explanation shape: the specific marker is named in
// the prompt. Every marker id in src/build/client-assets.ts with kind 'privileged' lands here.
const PRIVILEGED_MARKER_EXPLANATION: RuleExplanation = {
  what: 'A privileged credential is present in the browser-shipped bundle. Anything in the bundle is public: this is a live credential exposure, not a hygiene issue.',
  fix: 'Remove the credential from all client-reachable code, rotate it with its provider, and move server-side use behind the backend where authorization is enforced.',
  effort: 'M', confidence: 'confirmed',
  promptIntro: 'A privileged credential reached the browser bundle. Remove it from all client-reachable code and keep the application working without it, then rotate the credential.',
};

const PRIVILEGED_MARKERS = new Set([
  'supabase-secret-key', 'supabase-service-role-var', 'service-role-literal', 'private-key-block',
  'aws-access-key-id', 'openai-key', 'anthropic-key', 'stripe-live-key', 'google-api-key',
  'github-token', 'slack-token', 'twilio-api-key', 'sendgrid-key', 'resend-key',
  'firebase-service-account', 'synthetic-leak-marker',
]);

const TOOL_CONFIDENCE: Readonly<Record<string, Confidence>> = {
  gitleaks: 'confirmed',
  opengrep: 'likely',
  zizmor: 'confirmed',
  'osv-scanner': 'likely',
  'client-asset-inspection': 'confirmed',
  'live-http-check': 'confirmed',
};

function ruleExplanation(finding: Finding): RuleExplanation | undefined {
  const rule = finding.rule_id;
  if (RULES[rule] !== undefined) return RULES[rule];

  // opengrep rule ids may be namespaced differently per report format; match the suffix.
  for (const key of ['no-eval', 'child-process-exec-interpolation', 'dom-innerhtml-assignment']) {
    if (rule.includes(key)) return RULES[`hardening.${key}`] as RuleExplanation;
  }
  if (PRIVILEGED_MARKERS.has(rule)) return PRIVILEGED_MARKER_EXPLANATION;
  if (finding.tool === 'osv-scanner' || /^GHSA-|^CVE-|^MAL-/.test(rule)) return RULES['osv-advisory'] as RuleExplanation;
  if (finding.tool === 'gitleaks') {
    // Unlisted gitleaks rules are still exact token-shape matches; the fix shape is the same.
    return { ...(RULES['generic-api-key'] as RuleExplanation), what: `${RULES['generic-api-key']?.what} The rule that matched was '${rule}'.` };
  }
  return undefined;
}

export function explainFinding(finding: Finding): FindingExplanation {
  const explanation = ruleExplanation(finding);
  if (explanation !== undefined) {
    return { ...explanation, prompt: buildPrompt(explanation.promptIntro, finding) };
  }

  // No canned explanation exists for this rule id. Fall back to an honest generic that names the
  // tool and severity instead of pretending to know what the rule means.
  const generic: RuleExplanation = {
    what: `${finding.tool} reported a ${finding.severity}-severity finding${finding.rule_id === '' ? '' : ` (rule '${finding.rule_id}')`}. No plain-English explanation is recorded for this rule in this build, so treat it as needing a maintainer's judgement rather than assuming it is benign.`,
    fix: 'Read the finding in the raw report, decide whether it applies, and fix it if it does. Record a triage decision if it does not.',
    effort: 'M',
    confidence: TOOL_CONFIDENCE[finding.tool] ?? 'signal',
    promptIntro: `The ${finding.tool} scanner reported a finding (rule '${finding.rule_id}'). Investigate whether it is real, fix it if so, and record the decision either way.`,
  };
  return { ...generic, prompt: buildPrompt(generic.promptIntro, finding) };
}

function buildPrompt(intro: string, finding: Finding): string {
  const where = finding.location ?? finding.resource ?? 'the reported location';
  return [
    `${intro}`,
    `Location reported: ${where}${finding.title === undefined ? '' : `. Finding title: ${finding.title}`}.`,
    'Constraints: make the smallest correct change, keep existing tests passing, add a test for this fix where one can exist, and do not weaken or skip any security test. Do not touch unrelated code.',
  ].join(' ');
}
