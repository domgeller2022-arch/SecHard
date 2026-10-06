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

/**
 * Confines an *evidence reference* to a root.
 *
 * Unlike `confineToRoot`, the leaf does not have to exist yet: a record may legitimately reference
 * evidence that will be produced later. Escape is still rejected, including through a symlinked
 * ancestor, by resolving the nearest existing ancestor.
 */
export function confineReference(root: string, candidate: string): string | ValidationIssue {
  const resolvedRoot = realpathSync(root);
  const target = isAbsolute(candidate) ? candidate : resolve(resolvedRoot, candidate);

  if (!isInside(resolvedRoot, target)) {
    return issue('path.outside_root', `reference points outside the allowed root: ${candidate}`, candidate);
  }

  let ancestor = target;
  while (ancestor !== resolvedRoot) {
    try {
      const real = realpathSync(ancestor);
      if (!isInside(resolvedRoot, real)) {
        return issue('path.symlink_escape', `reference escapes the allowed root via a symlink: ${candidate}`, candidate);
      }
      break;
    } catch {
      const parent = resolve(ancestor, '..');
      if (!isInside(resolvedRoot, parent)) {
        return issue('path.outside_root', `reference points outside the allowed root: ${candidate}`, candidate);
      }
      ancestor = parent;
    }
  }

  return target;
}

export function isRemoteReference(candidate: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(candidate);
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
