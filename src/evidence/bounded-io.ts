import { closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs';

/**
 * The bounded-read primitive (P1.3, A-29 prerequisite): at most maxBytes are allocated and read
 * from the file — the limit is enforced at open time, not by slicing a whole-file buffer. Used
 * by every source-reading scanner so an oversized input stops at the byte limit.
 */
export function readBoundedSync(path: string, maxBytes: number): string | undefined {
  // A symlink or non-regular file is never followed/read here; callers record the omission.
  try {
    if (lstatSync(path).isSymbolicLink()) return undefined;
  } catch {
    return undefined;
  }
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined;
  }
  try {
    if (!fstatSync(fd).isFile()) return undefined;
    const buffer = Buffer.alloc(maxBytes);
    let total = 0;
    while (total < maxBytes) {
      const read = readSync(fd, buffer, total, maxBytes - total, total);
      if (read <= 0) break;
      total += read;
    }
    return buffer.subarray(0, total).toString('utf8');
  } catch {
    return undefined;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // the read already succeeded or failed on its own; the close is best-effort
    }
  }
}
