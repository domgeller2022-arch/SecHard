import { describe, expect, it } from 'vitest';
import { normalizeIdentifier, parseIdentifier, parseQualifiedName, splitSqlStatements } from '../../src/security/sql-tokens.js';

/**
 * Unit tests for the conservative SQL tokenizer (P3.3, A-13). Each case pins one lexical shape
 * Postgres migrations use; the migration inventory's correctness rests on these, so the tests
 * assert exact statement counts, boundaries and line numbers, not just "it split something".
 */

const texts = (input: string): readonly string[] => splitSqlStatements(input).map((statement) => statement.text);

describe('the conservative SQL tokenizer', () => {
  it('splits same-line statements and reports each statement start line', () => {
    const statements = splitSqlStatements('create table a(id int); alter table a enable row level security;');
    expect(statements.map((statement) => statement.text)).toEqual([
      'create table a(id int)',
      'alter table a enable row level security',
    ]);
    expect(statements.map((statement) => statement.line)).toEqual([1, 1]);
  });

  it('keeps a dollar-quoted function body in one statement despite its internal semicolons', () => {
    const input = [
      'create or replace function public.f(target uuid)',
      'returns void language plpgsql security definer as $$',
      '  update public.profiles set is_admin = true where id = target;',
      '  insert into audit_log values (1);',
      '$$;',
      'grant all on public.profiles to anon;',
    ].join('\n');
    const statements = splitSqlStatements(input);
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toContain('update public.profiles set is_admin = true where id = target;');
    expect(statements[0]?.text).toContain('insert into audit_log values (1);');
    expect(statements[1]?.text).toBe('grant all on public.profiles to anon');
    expect(statements[1]?.line).toBe(6);
  });

  it('matches tagged dollar-quote bodies only on their own tag', () => {
    const input = 'create function f() returns void as $fn$ body with $$ nested; $$ text; $fn$; select 1;';
    const statements = splitSqlStatements(input);
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toContain('$fn$ body with $$ nested; $$ text; $fn$');
  });

  it('does not split on a semicolon inside a single-quoted string with doubled quotes', () => {
    const statements = splitSqlStatements("insert into t values ('a;b'); select 1;");
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toContain("'a;b'");
  });

  it('does not split on a backslash-escaped quote inside an E-string', () => {
    const statements = splitSqlStatements("insert into t values (E'a\\';b'); select 1;");
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toContain("E'a\\';b'");
  });

  it('does not split on a semicolon inside a quoted identifier, and preserves "" doubling', () => {
    const statements = splitSqlStatements('create table "weird;name""x" (id int); select 1;');
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toContain('"weird;name""x"');
  });

  it('ignores semicolons inside line comments, and a fully commented statement produces nothing', () => {
    const statements = splitSqlStatements('-- alter table t enable row level security;\nselect 1;');
    expect(statements).toHaveLength(1);
    expect(statements[0]?.text).toBe('select 1');
  });

  it('ignores semicolons inside block comments, including nested ones', () => {
    const input = '/* outer; /* inner; */ still comment; */ select 1;';
    const statements = splitSqlStatements(input);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.text).toBe('select 1');
  });

  it('treats positional parameters like $1 as ordinary characters, not dollar quotes', () => {
    const statements = splitSqlStatements('insert into t values ($1, $2); select 1;');
    expect(statements).toHaveLength(2);
    expect(statements[0]?.text).toBe('insert into t values ($1, $2)');
  });

  it('reports the line of the first significant character after comments and blank lines', () => {
    const input = '\n\n-- preamble\n\ncreate table t(id int);';
    const statements = splitSqlStatements(input);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.line).toBe(5);
  });

  it('flushes a final statement without a trailing semicolon', () => {
    const statements = splitSqlStatements('select 1');
    expect(statements.map((statement) => statement.text)).toEqual(['select 1']);
  });

  it('survives unterminated strings and comments at end of input', () => {
    expect(texts("select 'unterminated")).toEqual(["select 'unterminated"]);
    expect(texts('select 1 /* unterminated')).toEqual(['select 1']);
  });

  it('normalizes unquoted identifiers to lowercase and keeps quoted identity', () => {
    expect(normalizeIdentifier('Users')).toEqual({ name: 'users', quoted: false });
    expect(normalizeIdentifier('"Users"')).toEqual({ name: 'Users', quoted: true });
    expect(normalizeIdentifier('"weird""name"')).toEqual({ name: 'weird"name', quoted: true });
  });

  it('reads single and schema-qualified identifiers', () => {
    expect(parseQualifiedName('public.profiles (', 0)).toEqual({ key: 'public.profiles', end: 'public.profiles'.length });
    expect(parseQualifiedName('"Public"."Users" enable', 0)).toEqual({ key: 'Public.Users', end: '"Public"."Users"'.length });
    expect(parseQualifiedName('profiles to anon', 0)).toEqual({ key: 'public.profiles', end: 'profiles'.length });
    expect(parseIdentifier('table t to anon', 6)).toEqual({ name: 't', end: 7 });
    expect(parseQualifiedName('all tables in schema public', 0)).toEqual({ key: 'public.all', end: 3 });
  });
});
