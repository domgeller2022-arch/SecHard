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

export function escapeJsonString(value: unknown): string {
  return JSON.stringify(redactSecrets(String(value)));
}
