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
