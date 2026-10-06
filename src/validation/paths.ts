import { realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { issue, type ValidationIssue } from './errors.js';

export interface ConfinedPath {
  readonly path: string;
  readonly relativePath: string;
}

export interface ConfineOptions {
  readonly mustExist?: boolean;
}

/**
 * Resolves `candidate` inside `root`, following symlinks.
 *
 * A path is accepted only when its fully resolved real path is still inside the resolved root.
 * Checking the unresolved string is not enough: a symlink inside the root can point outside it, and
 * `..` segments are resolved before the comparison.
 */
export function confineToRoot(
  root: string,
  candidate: string,
  options: ConfineOptions = {},
): ConfinedPath | ValidationIssue {
  const resolvedRoot = realpathSync(root);
  const target = isAbsolute(candidate) ? candidate : join(resolvedRoot, candidate);

  const lexicallyInside = isInside(resolvedRoot, target);

  let real: string;
  try {
    real = realpathSync(target);
  } catch {
    const parent = realpathParent(target);
    if (parent === undefined) {
      return issue('path.outside_root', `path does not exist inside root: ${candidate}`, candidate);
    }
    if (!isInside(resolvedRoot, parent)) {
      return issue(
        lexicallyInside ? 'path.symlink_escape' : 'path.outside_root',
        `${describe(lexicallyInside)}: ${candidate}`,
        candidate,
      );
    }
    if (options.mustExist === true) {
      return issue('path.outside_root', `path does not exist inside root: ${candidate}`, candidate);
    }
    real = target;
  }

  if (!isInside(resolvedRoot, real)) {
    return issue(
      lexicallyInside ? 'path.symlink_escape' : 'path.outside_root',
      `${describe(lexicallyInside)}: ${candidate}`,
      candidate,
    );
  }

  return { path: real, relativePath: relative(resolvedRoot, real) };
}

function describe(viaSymlink: boolean): string {
  return viaSymlink ? 'path escapes root via a symlink' : 'path escapes root';
}

export function isInside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function realpathParent(target: string): string | undefined {
  const parent = resolve(target, '..');
  try {
    return realpathSync(parent);
  } catch {
    return undefined;
  }
}
