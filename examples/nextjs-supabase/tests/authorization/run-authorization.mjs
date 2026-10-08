#!/usr/bin/env node
// Executes the authorization matrix against the unprivileged Supabase data API.
//
// Why the data API rather than the interface: the interface is one caller among many. A direct
// request with a user's own session tests the provider's boundary — grants, row-level security, and
// the policy's WITH CHECK — which is what every path ultimately depends on.
//
// Two rules this runner follows:
//   1. A denial is verified against stored state afterwards, through a separate privileged channel.
//      An HTTP status alone is not evidence that nothing changed.
//   2. The number of cases executed is asserted. A runner that silently skips cases reports success
//      for tests it never ran.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

// fileURLToPath, not URL.pathname: a pathname percent-encodes spaces, so this directory would
// become "Security%20Hardening" and every file read would fail.
const exampleRoot = fileURLToPath(new URL('../../', import.meta.url));
const env = readEnvLocal(join(exampleRoot, '.env.local'));
const base = env.NEXT_PUBLIC_SUPABASE_URL;
const publishable = env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const DB_CONTAINER = 'supabase_db_nextjs-supabase';
const PASSWORD = 'local-development-only';

if (!base || !publishable) {
  console.error('missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY; run `pnpm run env:sync`');
  process.exit(2);
}

const matrix = parse(readFileSync(join(exampleRoot, 'tests', 'authorization', 'matrix.yaml'), 'utf8'));

function readEnvLocal(file) {
  const values = {};
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    const index = trimmed.indexOf('=');
    if (index > 0) values[trimmed.slice(0, index)] = trimmed.slice(index + 1);
  }
  return values;
}

async function signIn(email) {
  const response = await fetch(`${base}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: publishable, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`sign-in failed for ${email}: ${response.status} ${JSON.stringify(body)}`);
  return { token: body.access_token, userId: body.user.id };
}

function psql(sql) {
  return execFileSync('docker', ['exec', '-i', DB_CONTAINER, 'psql', '-U', 'postgres', '-d', 'postgres', '-tA', '-v', 'ON_ERROR_STOP=1'], {
    input: sql,
    encoding: 'utf8',
    timeout: 60_000,
  }).trim();
}

/** The trusted assertion channel: reads stored state without going through the API under test. */
function storedTitle(id) {
  return psql(`select coalesce((select title from public.notes where id = '${id}'), '<absent>');`);
}
function storedOwner(id) {
  return psql(`select coalesce((select owner_id::text from public.notes where id = '${id}'), '<absent>');`);
}
function storedExists(id) {
  return psql(`select case when exists (select 1 from public.notes where id = '${id}') then 'yes' else 'no' end;`);
}

function api(actor, path, init = {}) {
  const headers = { apikey: publishable, 'content-type': 'application/json', ...(init.headers ?? {}) };
  if (actor.token) headers.authorization = `Bearer ${actor.token}`;
  return fetch(`${base}/rest/v1${path}`, {
    ...init,
    headers: { ...headers, ...(init.headers ?? {}) },
  });
}

async function runCase(testCase, actors, resources) {
  const actor = actors[testCase.actor] ?? actors.anonymous;
  const targetId = testCase.target ? resources[testCase.target].id : undefined;
  const payload = { ...(testCase.payload ?? {}) };
  if (testCase.claim_owner) payload.owner_id = actors[testCase.claim_owner].userId;

  const observations = {};

  switch (testCase.operation) {
    case 'list_notes': {
      const response = await api(actor, '/notes?select=id,title');
      observations.status = response.status;
      if (response.ok) observations.rows = (await response.json()).length;
      else observations.errorCode = await errorCode(response);
      break;
    }
    case 'read_note': {
      const response = await api(actor, `/notes?select=id,title&id=eq.${targetId}`);
      observations.status = response.status;
      if (response.ok) observations.rows = (await response.json()).length;
      else observations.errorCode = await errorCode(response);
      break;
    }
    case 'create_note': {
      const response = await api(actor, '/notes', {
        method: 'POST',
        headers: { prefer: 'return=representation' },
        body: JSON.stringify(payload),
      });
      observations.status = response.status;
      observations.ok = response.ok;
      if (!response.ok) observations.errorCode = await errorCode(response);
      break;
    }
    case 'update_note': {
      const response = await api(actor, `/notes?id=eq.${targetId}`, {
        method: 'PATCH',
        headers: { prefer: 'return=representation' },
        body: JSON.stringify(payload),
      });
      observations.status = response.status;
      if (response.ok) observations.affected = (await response.json()).length;
      else observations.errorCode = await errorCode(response);
      break;
    }
    case 'delete_note': {
      const response = await api(actor, `/notes?id=eq.${targetId}`, {
        method: 'DELETE',
        headers: { prefer: 'return=representation' },
      });
      observations.status = response.status;
      if (response.ok) observations.affected = (await response.json()).length;
      else observations.errorCode = await errorCode(response);
      break;
    }
    default:
      throw new Error(`unknown operation '${testCase.operation}'`);
  }

  return observations;
}

/** Reads the provider's error code, which is the useful evidence for a refusal. */
async function errorCode(response) {
  try {
    const body = await response.json();
    return typeof body.code === 'string' ? body.code : undefined;
  } catch {
    return undefined;
  }
}

function evaluate(testCase, observations, resources, actors) {
  const problems = [];
  const expect = testCase.expect;

  if (expect.rows !== undefined && observations.rows !== expect.rows) {
    problems.push(`expected ${expect.rows} row(s), observed ${observations.rows ?? 'no rows (status ' + observations.status + ')'}`);
  }
  if (expect.rows_at_least !== undefined && (observations.rows ?? 0) < expect.rows_at_least) {
    problems.push(`expected at least ${expect.rows_at_least} row(s), observed ${observations.rows ?? 0}`);
  }
  if (expect.affected !== undefined && observations.affected !== expect.affected) {
    problems.push(`expected ${expect.affected} row(s) written, observed ${observations.affected ?? 'none (status ' + observations.status + ')'}`);
  }
  if (expect.allowed === true && observations.ok !== true) {
    problems.push(`expected the request to succeed, got status ${observations.status}`);
  }
  if (expect.denied === true) {
    // PostgREST reports a policy violation for an insert and an empty result for a filtered write.
    const refusedByStatus = observations.ok === false || observations.status === 401 || observations.status === 403;
    const wroteNothing = observations.affected === 0 || observations.rows === 0;
    if (!refusedByStatus && !wroteNothing) {
      problems.push(`expected the request to be denied, got status ${observations.status}`);
    }
  }

  // The denial is only real if the stored row is untouched, read through a separate channel.
  if (testCase.stored_state) {
    const resource = resources[testCase.stored_state.resource];
    if (testCase.stored_state.title !== undefined && storedTitle(resource.id) !== testCase.stored_state.title) {
      problems.push(`stored title changed to '${storedTitle(resource.id)}' after a denied write`);
    }
    if (testCase.stored_state.owner !== undefined && storedOwner(resource.id) !== actors[testCase.stored_state.owner].userId) {
      problems.push(`stored owner changed to '${storedOwner(resource.id)}' after a denied write`);
    }
    if (testCase.stored_state.exists !== undefined) {
      const exists = storedExists(resource.id) === 'yes';
      if (exists !== testCase.stored_state.exists) {
        problems.push(`expected the row to ${testCase.stored_state.exists ? 'exist' : 'not exist'}, observed the opposite`);
      }
    }
  }

  return problems;
}

async function main() {
  // Preconditions fail loudly. A matrix that silently ran against nothing would report success.
  try {
    psql('select 1;');
  } catch {
    console.error('the local database is not reachable; start the stack with `pnpm exec supabase start`');
    process.exit(2);
  }

  const actors = {
    anonymous: { token: null, userId: null },
    invalid_token: { token: 'not.a.valid.token', userId: null },
    owner_a: await signIn(matrix.actors.owner_a.email),
    other_b: await signIn(matrix.actors.other_b.email),
  };

  // Re-seed the resource the create case produces, so a previous interrupted run cannot make the
  // suite pass or fail for the wrong reason.
  const created = matrix.resources.note_by_a;
  psql(`delete from public.notes where id = '${created.id}';`);

  let failures = 0;
  let executed = 0;
  const results = [];

  for (const testCase of matrix.cases) {
    const observations = await runCase(testCase, actors, matrix.resources);
    const problems = evaluate(testCase, observations, matrix.resources, actors);
    executed += 1;
    if (problems.length > 0) failures += 1;
    results.push({ id: testCase.id, problems, status: observations.status, errorCode: observations.errorCode });
  }

  // A case that did not run is a failure, not an absence of failure.
  if (executed !== matrix.cases.length) {
    console.error(`executed ${executed} of ${matrix.cases.length} cases`);
    process.exit(1);
  }

  for (const result of results) {
    const mark = result.problems.length === 0 ? 'ok  ' : 'FAIL';
    const code = result.errorCode === undefined ? '' : `, ${result.errorCode}`;
    console.log(`${mark} ${result.id} (status ${result.status}${code})`);
    for (const problem of result.problems) console.log(`       ${problem}`);
  }
  console.log(`\n${executed} cases executed, ${failures} failed`);

  // Inventory: the static facts the dynamic cases rest on.
  const rls = psql("select relrowsecurity::text || '/' || relforcerowsecurity::text from pg_class where relname = 'notes';");
  const policies = psql("select policyname || ':' || cmd || ':' || array_to_string(roles, ',') from pg_policies where tablename = 'notes' order by policyname;");
  const anonGrants = psql("select count(*) from information_schema.role_table_grants where table_name = 'notes' and grantee = 'anon';");
  const checks = [
    ['rls enabled and forced on notes', rls === 'true/true'],
    ['exactly one owner policy', policies.split('\n').filter((line) => line.length > 0).length === 1],
    ['the policy targets authenticated only', policies.includes('authenticated') && !policies.includes('{public}') && !policies.includes(':anon')],
    ['anonymous holds no table grant', anonGrants === '0'],
  ];
  for (const [name, ok] of checks) {
    console.log(`${ok ? 'ok  ' : 'FAIL'} inventory: ${name}`);
    if (!ok) failures += 1;
  }

  process.exit(failures === 0 ? 0 : 1);
}

await main();
