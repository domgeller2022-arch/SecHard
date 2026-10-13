const REDACTED = '[REDACTED]';

/**
 * Patterns for values that must never reach console output, a report, or a commit. Applied to any
 * string that came from a tool, a scanner, or an application file.
 *
 * This is a backstop, not the control: the real protections are not putting secrets in those places
 * in the first place, and rotating anything that does leak.
 */
const SECRET_PATTERNS: readonly { readonly name: string; readonly pattern: RegExp }[] = [
  { name: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { name: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'private-key-block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: 'generic-assigned-secret', pattern: /\b(?:api[_-]?key|secret|password|passwd|token|credential)\b\s*[:=]\s*["']?[A-Za-z0-9/+_-]{16,}["']?/gi },
  { name: 'supabase-service-role', pattern: /\bsb_secret_[A-Za-z0-9_-]{16,}\b/g },
  { name: 'supabase-legacy-jwt', pattern: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[A-Za-z0-9._-]{40,}\b/g },
  // Batch R1 (A-03): the audit republished these provider values in saved reports because no
  // pattern matched them. Kept alongside the classifier's provider list.
  { name: 'stripe-secret', pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: 'stripe-publishable', pattern: /\bpk_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: 'openai-key', pattern: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'database-url-with-credentials', pattern: /\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?):\/\/[^\s\/@]+:[^\s\/@]+@/g },
  { name: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

export function redactSecrets(text: string): string {
  let output = text;
  for (const { pattern } of SECRET_PATTERNS) {
    output = output.replace(pattern, REDACTED);
  }
  return output;
}

export function containsSecretPattern(text: string): boolean {
  return SECRET_PATTERNS.some(({ pattern }) => new RegExp(pattern.source, pattern.flags).test(text));
}

/**
 * Report locations are relative to the audited root. An absolute machine path in a published
 * report leaks the auditing host's layout, and rules that key on the first path segment (the
 * console.log scoping rule) read an absolute prefix as `''`, silently holding back findings in
 * audit mode. Live HTTP findings are URLs, not paths; a location outside the root is rare and
 * kept as-is rather than mangled. Already-relative locations pass through unchanged, so this is
 * idempotent wherever it is applied twice (recipe intake and result creation).
 */
export function relativizeLocation(location: string, appRoot: string): string {
  if (location.startsWith('http://') || location.startsWith('https://')) return location;
  if (appRoot === '') return location;
  if (location === appRoot) return '.';
  return location.startsWith(`${appRoot}/`) ? location.slice(appRoot.length + 1) : location;
}

/**
 * Escapes text that came from a tool, a scanner, or an application file before it is written into
 * Markdown. Untrusted output is data: it must not be able to inject structure into a report that a
 * reviewer reads.
 */
export function escapeMarkdown(text: string): string {
  return text
    .replace(/\\/g, '\\\\')
    .replace(/([*_`[\]<>|])/g, '\\$1')
    .replace(/^(\s*)([-+])(\s)/gm, '$1\\$2$3')
    .replace(/^(\s*)(\d+)\.(\s)/gm, '$1$2\\.$3')
    .replace(/^(\s*)#/gm, '$1\\#')
    .replace(/^(\s*)>/gm, '$1\\>')
    .replace(/\r?\n/g, ' ')
    .trim();
}
