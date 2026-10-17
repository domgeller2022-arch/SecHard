/**
 * Hardened Git invocation (Batch R1, A-01): a repository's own configuration can execute code
 * through `core.fsmonitor` (and diff helpers) during read-only inspection. Every Git call that
 * touches an audited tree — SecHard's own runner and scanner-owned child processes — must disable
 * those channels.
 *
 * Diffs are a separate concern from helper hardening (plan review PR-01): `--no-ext-diff
 * --no-textconv` disables the executable helpers while keeping the normal `a/`/`b/` patch format
 * the change-report parser reads. Never substitute an empty-output `diff.external`; that hides
 * real security-sensitive changes.
 */

export const GIT_HARDENING_CONFIG: readonly (readonly [key: string, value: string])[] = [
  ['core.fsmonitor', 'false'],
  // An absolute path that does not exist: git finds no hooks to run. Never a relative path
  // (resolved against the audited repository) and never a directory that could be created.
  ['core.hooksPath', '/nonexistent-sechard-hardened-hooks'],
];

/** `-c` arguments prepended to every direct Git invocation. */
export function gitHardeningArgs(): string[] {
  return GIT_HARDENING_CONFIG.flatMap(([key, value]) => ['-c', `${key}=${value}`]);
}

/** Diff/log flags that disable executable helpers without changing patch format. */
export function diffSafetyArgs(): string[] {
  return ['--no-ext-diff', '--no-textconv'];
}

/**
 * Environment that hardens Git child processes we do not spawn ourselves (gitleaks runs its own
 * `git`). GIT_CONFIG_COUNT is the documented per-invocation config injection (Git 2.31+).
 */
export function gitConfigEnv(): Readonly<Record<string, string>> {
  const env: Record<string, string> = { GIT_CONFIG_COUNT: String(GIT_HARDENING_CONFIG.length) };
  GIT_HARDENING_CONFIG.forEach(([key, value], index) => {
    env[`GIT_CONFIG_KEY_${String(index)}`] = key;
    env[`GIT_CONFIG_VALUE_${String(index)}`] = value;
  });
  return env;
}
