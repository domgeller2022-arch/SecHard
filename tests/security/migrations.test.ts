import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { analyzeMigrations, type MigrationAnalysis } from '../../src/security/migrations.js';

/**
 * The migration inventory's permanent fixtures (P3.3 — A-13/A-14). Every case is one of the
 * shapes the governing plan requires, asserted at the analyzer level: exact rule ids per
 * fixture, severities where the RLS/grants interaction matters, and the bounded-wording rule
 * (an RLS-protected anon write is never called a proven bypass). The final test pins the
 * corpus seed's five findings and locations so the corpus S21–S25 outcomes cannot drift
 * silently.
 */

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CORPUS_MIGRATION = join(REPO, 'tests', 'corpus', 'independent-nextjs', 'supabase', 'migrations', '0001_init.sql');

const roots: string[] = [];

function buildApp(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'sechard-migrations-'));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

function buildAppWithSymlink(files: Record<string, string>, symlinkName: string, target: string): string {
  const root = buildApp(files);
  symlinkSync(target, join(root, 'supabase', 'migrations', symlinkName));
  return root;
}

afterEach(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
  roots.length = 0;
});

function rulesOf(result: MigrationAnalysis): readonly string[] {
  return result.findings.map((f) => f.rule_id).sort();
}

describe('the migration inventory evaluates the ordered sequence to a final state', () => {
  it('enable then disable across files leaves the table unprotected (rls-missing fires)', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\n',
      'supabase/migrations/0002_disable.sql': 'alter table public.t disable row level security;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
    expect(result.filesRead).toEqual(['supabase/migrations/0001_init.sql', 'supabase/migrations/0002_disable.sql']);
    const detail = result.findings[0]?.detail ?? '';
    expect(detail).toContain('enabled and later disabled');
  });

  it('a later enable protects a table created unprotected (silent)', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\n',
      'supabase/migrations/0002_rls.sql': 'alter table public.t enable row level security;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual([]);
  });

  it('a commented-out enable is not protection (rls-missing fires)', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\n-- alter table public.t enable row level security;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
  });

  it('quoted identifiers keep their identity; unquoted identifiers fold to lowercase', () => {
    const quotedMatch = buildApp({
      'supabase/migrations/0001_init.sql': 'create table "Public"."Users" (id int);\nalter table "Public"."Users" enable row level security;\n',
    });
    expect(rulesOf(analyzeMigrations(quotedMatch))).toEqual([]);

    const caseFold = buildApp({
      'supabase/migrations/0001_init.sql': 'CREATE TABLE Users (id int);\nALTER TABLE USERS ENABLE ROW LEVEL SECURITY;\n',
    });
    expect(rulesOf(analyzeMigrations(caseFold))).toEqual([]);

    const quotedDistinct = buildApp({
      'supabase/migrations/0001_init.sql': 'create table "Users" (id int);\nalter table users enable row level security;\n',
    });
    const result = analyzeMigrations(quotedDistinct);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
    expect(result.findings[0]?.title).toContain('public.Users');
  });

  it('multiple statements on one line are parsed independently', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table a (id int); alter table a enable row level security; create table b (id int);',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
    expect(result.findings[0]?.title).toContain('public.b');
  });

  it('select-first then write grants fire on the write verb in the final state', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\ngrant select on public.t to anon;\n',
      'supabase/migrations/0002_write.sql': 'grant insert on public.t to anon;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.grant-anon-write', 'supabase.rls-missing']);
    const grantFinding = result.findings.find((f) => f.rule_id === 'supabase.grant-anon-write');
    expect(grantFinding?.severity).toBe('high');
    expect(grantFinding?.detail).toContain('insert');
  });

  it('all privileges and multiple roles each reach the anon role', () => {
    const allPrivileges = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\ngrant all privileges on public.t to anon;\n',
    });
    expect(rulesOf(analyzeMigrations(allPrivileges))).toContain('supabase.grant-anon-write');

    const multipleRoles = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\ngrant insert on public.t to anon, authenticated;\n',
    });
    const result = analyzeMigrations(multipleRoles);
    expect(result.findings.filter((f) => f.rule_id === 'supabase.grant-anon-write')).toHaveLength(1);
    expect(result.findings.find((f) => f.rule_id === 'supabase.grant-anon-write')?.detail).toContain('anon');
  });

  it('a revoked write grant is silent in the final state', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\ngrant insert on public.t to anon;\nrevoke insert on public.t from anon;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
  });

  it('dropped tables and their policies/grants are silent', () => {
    const dropped = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy "p" on public.t for select using (true);\ngrant insert on public.t to anon;\n',
      'supabase/migrations/0002_drop.sql': 'drop table public.t;\n',
    });
    expect(rulesOf(analyzeMigrations(dropped))).toEqual([]);
  });

  it('a rename carries protection state to the new name', () => {
    const protectedRename = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\n',
      'supabase/migrations/0002_rename.sql': 'alter table public.t rename to t2;\n',
    });
    expect(rulesOf(analyzeMigrations(protectedRename))).toEqual([]);

    const unprotectedRename = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\n',
      'supabase/migrations/0002_rename.sql': 'alter table public.t rename to t2;\n',
    });
    const result = analyzeMigrations(unprotectedRename);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
    expect(result.findings[0]?.location).toBe('supabase/migrations/0001_init.sql');
  });

  it('unexposed schemas and unlisted schemas produce no public-access claims', () => {
    const createdSchema = buildApp({
      'supabase/migrations/0001_init.sql': 'create schema private;\ncreate table private.t (id int);\n',
    });
    const result = analyzeMigrations(createdSchema);
    expect(rulesOf(result)).toEqual([]);
    expect(result.limits.join('; ')).toContain('exposed schemas default to public');
  });

  it('API exposure comes from the reviewed config, not from create schema', () => {
    const root = buildApp({
      'supabase/config.toml': '[api]\nenabled = true\nschemas = ["appdata"]\n',
      'supabase/migrations/0001_init.sql': 'create table public.hidden (id int);\ncreate table appdata.visible (id int);\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.rls-missing']);
    expect(result.findings[0]?.title).toContain('appdata.visible');
    expect(result.limits.join('; ')).toContain('supabase/config.toml [api].schemas (appdata)');
  });

  it('an intentional public read-only grant is not a write exposure', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ngrant select on public.t to anon;\n',
    });
    expect(rulesOf(analyzeMigrations(root))).toEqual([]);
  });

  it('an implicit UPDATE with check is worded as breadth, not as a proven bypass', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy "p" on public.t for update using (true);\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual(['supabase.permissive-policy']);
    expect(result.findings[0]?.detail).toContain('with check defaults to the using expression');
  });

  it('a broad additional permissive policy fires, and dropping a policy silences it', () => {
    const broad = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy "a" on public.t for select using (true);\n',
      'supabase/migrations/0002_extra.sql': 'create policy "b" on public.t for all using (true);\n',
    });
    const broadResult = analyzeMigrations(broad);
    expect(broadResult.findings.filter((f) => f.rule_id === 'supabase.permissive-policy')).toHaveLength(2);

    const droppedPolicy = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy "a" on public.t for select using (true);\n',
      'supabase/migrations/0002_extra.sql': 'create policy "b" on public.t for all using (true);\n',
      'supabase/migrations/0003_cleanup.sql': 'drop policy "a" on public.t;\n',
    });
    const droppedResult = analyzeMigrations(droppedPolicy);
    expect(droppedResult.findings.filter((f) => f.rule_id === 'supabase.permissive-policy')).toHaveLength(1);
    expect(droppedResult.findings[0]?.title).toContain('"b"');
  });

  it('a restrictive policy never counts as a permissive no-op', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy "r" on public.t as restrictive for select using (true);\n',
    });
    expect(rulesOf(analyzeMigrations(root))).toEqual([]);
  });

  it('security definer with a pinned search_path in the definition is silent; body-only pinning still fires', () => {
    const pinned = buildApp({
      'supabase/migrations/0001_init.sql': 'create or replace function public.f() returns void language plpgsql security definer set search_path = public as $$ begin end; $$;\n',
    });
    expect(rulesOf(analyzeMigrations(pinned))).toEqual([]);

    const invoker = buildApp({
      'supabase/migrations/0001_init.sql': 'create function public.f() returns void language plpgsql security invoker as $$ begin end; $$;\n',
    });
    expect(rulesOf(analyzeMigrations(invoker))).toEqual([]);

    const bodyOnly = buildApp({
      'supabase/migrations/0001_init.sql': 'create function public.f() returns void language plpgsql security definer as $$ begin set search_path = public; end; $$;\n',
    });
    const result = analyzeMigrations(bodyOnly);
    expect(rulesOf(result)).toEqual(['supabase.security-definer-search-path']);
  });

  it('SQL inside a dollar-quoted body is not executed DDL and creates no phantom tables', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create function public.f() returns void language plpgsql as $$ begin create table sneaky (id int); end; $$;\n',
    });
    const result = analyzeMigrations(root);
    expect(rulesOf(result)).toEqual([]);
  });

  it('public buckets fire on insert and update; setting public = false silences them', () => {
    const insertNamed = buildApp({
      'supabase/migrations/0001_init.sql': "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);\n",
    });
    const insertResult = analyzeMigrations(insertNamed);
    expect(rulesOf(insertResult)).toEqual(['supabase.public-bucket']);
    expect(insertResult.findings[0]?.detail).toContain('separate questions');

    const positional = buildApp({
      'supabase/migrations/0001_init.sql': "insert into storage.buckets values ('media', 'media', true);\n",
    });
    expect(rulesOf(analyzeMigrations(positional))).toEqual(['supabase.public-bucket']);

    const updatedTrue = buildApp({
      'supabase/migrations/0001_init.sql': "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);\n",
      'supabase/migrations/0002_update.sql': "update storage.buckets set public = true where id = 'avatars';\n",
    });
    expect(rulesOf(analyzeMigrations(updatedTrue))).toEqual(['supabase.public-bucket']);

    const updatedFalse = buildApp({
      'supabase/migrations/0001_init.sql': "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);\n",
      'supabase/migrations/0002_update.sql': "update storage.buckets set public = false where id = 'avatars';\n",
    });
    expect(rulesOf(analyzeMigrations(updatedFalse))).toEqual([]);
  });

  it('RLS-protected anon writes are bounded to review, never a proven bypass (A-14)', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': 'create table public.t (id int);\nalter table public.t enable row level security;\ngrant insert on public.t to anon;\n',
    });
    const result = analyzeMigrations(root);
    const grantFinding = result.findings.find((f) => f.rule_id === 'supabase.grant-anon-write');
    expect(grantFinding).toBeDefined();
    expect(grantFinding?.severity).toBe('medium');
    expect(grantFinding?.detail).toContain('does not bypass RLS');
    expect(grantFinding?.detail).not.toMatch(/can (now )?(modify|write)/);
    expect(grantFinding?.detail?.toLowerCase()).toContain('review');
  });

  it('unreadable linked inputs are recorded as skipped scope, not silently dropped', () => {
    const root = buildAppWithSymlink(
      { 'supabase/migrations/0001_init.sql': 'create table public.t (id int);\n' },
      '0002_linked.sql',
      '/etc/hosts',
    );
    const result = analyzeMigrations(root);
    expect(result.filesRead).toEqual(['supabase/migrations/0001_init.sql']);
    expect(result.limits.join('; ')).toContain('1 migration file(s) skipped');
  });

  it('keeps the corpus seed S21–S25 outcomes and locations pinned at the analyzer level', () => {
    const root = buildApp({
      'supabase/migrations/0001_init.sql': readFileSync(CORPUS_MIGRATION, 'utf8'),
    });
    const result = analyzeMigrations(root);
    expect(result.filesRead).toEqual(['supabase/migrations/0001_init.sql']);
    const byRule = new Map(result.findings.map((f) => [f.rule_id, f]));
    expect([...byRule.keys()].sort()).toEqual([
      'supabase.grant-anon-write',
      'supabase.permissive-policy',
      'supabase.public-bucket',
      'supabase.rls-missing',
      'supabase.security-definer-search-path',
    ]);
    expect(byRule.get('supabase.rls-missing')?.location).toBe('supabase/migrations/0001_init.sql');
    expect(byRule.get('supabase.permissive-policy')?.location).toBe('supabase/migrations/0001_init.sql:7');
    expect(byRule.get('supabase.grant-anon-write')?.location).toBe('supabase/migrations/0001_init.sql:10');
    expect(byRule.get('supabase.security-definer-search-path')?.location).toBe('supabase/migrations/0001_init.sql:12');
    expect(byRule.get('supabase.public-bucket')?.location).toBe('supabase/migrations/0001_init.sql:17');
    for (const finding of result.findings) expect(finding.severity).toBe('high');
  });
});
