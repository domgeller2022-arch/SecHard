#!/usr/bin/env node
// Writes the example's local .env.local from the running Supabase stack.
//
// Kept as a script rather than committed values because the local stack's keys change when the
// stack is reset, and because a committed key invites someone to reuse it somewhere real. The file
// it writes is gitignored. Only the publishable key is written: the secret key stays out of the
// application entirely, which is what SEC-02 checks.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const example = join(root, 'examples', 'nextjs-supabase');

let status;
try {
  status = execFileSync(
    join(example, 'node_modules', '.bin', 'supabase'),
    ['status', '-o', 'env'],
    { cwd: example, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
  );
} catch (error) {
  process.stderr.write('could not read the local Supabase status; is the stack running?\n');
  process.stderr.write(`${(error).message}\n`);
  process.exit(2);
}

const values = Object.fromEntries(
  status
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.includes('='))
    .map((line) => {
      const index = line.indexOf('=');
      return [line.slice(0, index), line.slice(index + 1).replace(/^"|"$/g, '')];
    }),
);

const url = values.API_URL;
const publishable = values.PUBLISHABLE_KEY;
if (!url || !publishable) {
  process.stderr.write('the stack did not report API_URL and PUBLISHABLE_KEY\n');
  process.exit(2);
}

const appOrigin = process.argv[2] ?? 'http://localhost:3100';

const contents = [
  '# Written by `pnpm run env:sync` from the running local Supabase stack. Gitignored.',
  '# Only the publishable key appears here. The secret key is never used by this application.',
  `NEXT_PUBLIC_SUPABASE_URL=${url}`,
  `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${publishable}`,
  '',
  '# Redirects are built from this value, not from the request Host header.',
  `APP_ORIGIN=${appOrigin}`,
  '',
].join('\n');

writeFileSync(join(example, '.env.local'), contents, 'utf8');
process.stdout.write(`wrote ${join(example, '.env.local')} (url ${url}, publishable key ${publishable.slice(0, 16)}…)\n`);
