import { lstatSync, readdirSync } from 'node:fs';
import { readBoundedSync } from '../evidence/bounded-io.js';
import { join } from 'node:path';
import type { Finding } from '../domain/types.js';
import { normalizeIdentifier, parseIdentifier, parseQualifiedName, splitSqlStatements } from './sql-tokens.js';

/**
 * Supabase migration inventory (P3.3 — A-13/A-14, fix brief F-06). A conservative tokenizer
 * (`src/security/sql-tokens.ts`) splits `supabase/migrations/*.sql` into statements — strings,
 * comments, quoted identifiers and dollar-quoted bodies never break a statement, so function
 * bodies keep their internal semicolons and commented-out SQL never reaches a matcher — and the
 * migration sequence is evaluated in order to a final state: create/drop/rename tables, RLS
 * enable/disable/force, policy create/alter/drop, grants/revokes, views, security-definer
 * functions and storage buckets. Later state changes overwrite earlier ones; an enabled set is
 * never monotonic (A-13).
 *
 * API exposure comes from reviewed configuration only (`supabase/config.toml [api].schemas`,
 * defaulting to `public`): a newly created schema is not automatically exposed. Findings are
 * worded by the evidence actually observed — grants under enabled RLS are never called proven
 * bypasses, public-read intent stays distinct from write access, and unexposed/dropped objects
 * are silent (A-14). What the shapes cannot prove is recorded as gaps in the recipe coverage
 * note and this analyzer's `limits` result.
 */

interface MigrationFile {
  readonly path: string;
  readonly location: string;
  readonly text: string;
}

interface MigrationRead {
  readonly files: readonly MigrationFile[];
  readonly skipped: number;
  readonly note?: string;
}

const MAX_MIGRATION_FILES = 200;
const MAX_MIGRATION_BYTES = 512 * 1024;
const MAX_CONFIG_BYTES = 64 * 1024;
const DEFAULT_EXPOSED_SCHEMAS: ReadonlySet<string> = new Set(['public']);

const ALL_PRIVILEGES: readonly string[] = ['select', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger'];
const WRITE_PRIVILEGES: ReadonlySet<string> = new Set(['insert', 'update', 'delete', 'truncate']);
const ANON_ROLES: ReadonlySet<string> = new Set(['anon', 'public']);

interface RlsState {
  enabled: boolean;
  forced: boolean;
  lastVerb: 'enabled' | 'disabled';
  lastLocation: string;
}

interface PolicyState {
  readonly table: string;
  readonly name: string;
  permissive: boolean;
  operation: string;
  roles: readonly string[] | null;
  usingTrue: boolean;
  checkTrue: boolean;
  location: string;
  line: number;
}

interface GrantState {
  readonly privileges: ReadonlySet<string>;
  readonly location: string;
  readonly line: number;
}

interface FunctionState {
  readonly name: string;
  readonly definer: boolean;
  readonly searchPath: boolean;
  readonly location: string;
  readonly line: number;
}

interface ViewState {
  readonly name: string;
  readonly invoker: boolean;
  readonly location: string;
  readonly line: number;
}

interface BucketState {
  readonly id: string;
  publicFlag: boolean;
  location: string;
  line: number;
}

interface TableState {
  readonly created: string;
  dropped: boolean;
}

function readMigrationFiles(appRoot: string): MigrationRead {
  const dir = join(appRoot, 'supabase', 'migrations');
  // R1-03: an ancestor symlink (supabase/ or supabase/migrations) would enumerate and read files
  // outside the scan root; skip them instead of following.
  try {
    if (lstatSync(join(appRoot, 'supabase')).isSymbolicLink()) {
      return { files: [], skipped: 0, note: 'supabase/ is a symlink; no migration files read' };
    }
    if (lstatSync(dir).isSymbolicLink()) {
      return { files: [], skipped: 0, note: 'supabase/migrations is a symlink; no migration files read' };
    }
  } catch {
    return { files: [], skipped: 0 };
  }
  let entries: string[];
  try {
    entries = readdirSync(dir).filter((name) => name.endsWith('.sql')).sort();
  } catch {
    return { files: [], skipped: 0 };
  }
  const files: MigrationFile[] = [];
  let skipped = 0;
  for (const name of entries) {
    if (files.length >= MAX_MIGRATION_FILES) {
      skipped += 1;
      continue;
    }
    const full = join(dir, name);
    try {
      // A-02: never follow symlinks out of the audited tree.
      if (!lstatSync(full).isFile()) {
        skipped += 1;
        continue;
      }
      // P1.3: bounded at open time.
      const text = readBoundedSync(full, MAX_MIGRATION_BYTES);
      if (text === undefined) {
        skipped += 1;
        continue;
      }
      files.push({ path: full, location: `supabase/migrations/${name}`, text });
    } catch {
      skipped += 1;
      continue;
    }
  }
  return { files, skipped };
}

interface Exposure {
  readonly schemas: ReadonlySet<string>;
  readonly note: string;
}

const DEFAULT_EXPOSURE_NOTE = 'no supabase/config.toml found; exposed schemas default to public';

function defaultExposure(note: string = DEFAULT_EXPOSURE_NOTE): Exposure {
  return { schemas: DEFAULT_EXPOSED_SCHEMAS, note };
}

/**
 * API exposure is read from reviewed configuration only. The reviewed shape is the
 * `[api].schemas` list of `supabase/config.toml` (bounded text read, no TOML dependency);
 * anything else — an absent file, another exposure mechanism — defaults to `public` and is
 * recorded in the note so the coverage stays honest. `create schema` statements never add
 * exposure.
 */
function readExposure(appRoot: string): Exposure {
  const configPath = join(appRoot, 'supabase', 'config.toml');
  try {
    if (lstatSync(join(appRoot, 'supabase')).isSymbolicLink() || lstatSync(configPath).isSymbolicLink()) {
      return defaultExposure('supabase/config.toml is a symlink; exposed schemas default to public');
    }
  } catch {
    return defaultExposure();
  }
  try {
    const text = readBoundedSync(configPath, MAX_CONFIG_BYTES);
    if (text === undefined) {
      return defaultExposure('supabase/config.toml exceeds the read bound; exposed schemas default to public');
    }
    const sectionStart = /^\s*\[api\]\s*$/m.exec(text);
    if (sectionStart === null || sectionStart.index === undefined) {
      return defaultExposure('no [api] section in supabase/config.toml; exposed schemas default to public');
    }
    const afterHeader = text.slice(sectionStart.index + sectionStart[0].length);
    const nextSection = /^\s*\[/m.exec(afterHeader);
    const section = nextSection === null || nextSection.index === undefined ? afterHeader : afterHeader.slice(0, nextSection.index);
    const list = /^\s*schemas\s*=\s*\[([^\]]*)\]/m.exec(section);
    if (list === null || list[1] === undefined) {
      return defaultExposure('no schemas list under [api] in supabase/config.toml; exposed schemas default to public');
    }
    const names = [...list[1].matchAll(/"([^"]+)"/g)]
      .map((match) => match[1])
      .filter((name): name is string => name !== undefined && name.length > 0);
    if (names.length === 0) {
      return defaultExposure('empty schemas list under [api] in supabase/config.toml; exposed schemas default to public');
    }
    return {
      schemas: new Set(names),
      note: `API-exposed schemas read from supabase/config.toml [api].schemas (${names.join(', ')})`,
    };
  } catch {
    return defaultExposure('supabase/config.toml unreadable; exposed schemas default to public');
  }
}

function finding(id: string, ruleId: string, severity: Finding['severity'], title: string, detail: string, location: string, controls: readonly string[]): Finding {
  return {
    id,
    tool: 'migration-inventory',
    rule_id: ruleId,
    severity,
    title,
    detail,
    location,
    control_ids: controls,
    triage: 'unresolved',
  };
}

function schemaOf(qualifiedKey: string): string {
  return qualifiedKey.slice(0, qualifiedKey.indexOf('.'));
}

interface PolicyClauses {
  permissive?: boolean;
  operation?: string;
  roles?: readonly string[] | null;
  usingTrue?: boolean;
  checkTrue?: boolean;
}

function parsePolicyClauses(rest: string): PolicyClauses {
  const clauses: PolicyClauses = {};
  const asMatch = /\bas\s+(permissive|restrictive)\b/i.exec(rest);
  if (asMatch !== null && asMatch[1] !== undefined) clauses.permissive = asMatch[1].toLowerCase() === 'permissive';
  const forMatch = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest);
  if (forMatch !== null && forMatch[1] !== undefined) clauses.operation = forMatch[1].toLowerCase();
  const toMatch = /\bto\s+([^;]+?)(?=\s+using\s*\(|\s+with\s+check\s*\(|\s*$)/i.exec(rest);
  if (toMatch !== null && toMatch[1] !== undefined) {
    clauses.roles = toMatch[1].split(',').map((role) => normalizeIdentifier(role).name);
  }
  if (/\busing\s*\(\s*true\s*\)/i.test(rest)) clauses.usingTrue = true;
  if (/\bwith\s+check\s*\(\s*true\s*\)/i.test(rest)) clauses.checkTrue = true;
  return clauses;
}

const POLICY_NAME_ON = /^(?:"((?:[^"]|"")+)"|([A-Za-z_][\w$]*))\s+on\s+/i;

function parsePolicyTarget(statement: string, from: number): { name: string; key: string; rest: number } | null {
  const nameMatch = POLICY_NAME_ON.exec(statement.slice(from));
  if (nameMatch === null) return null;
  if (nameMatch[1] === undefined && nameMatch[2] === undefined) return null;
  const name = nameMatch[1] !== undefined ? nameMatch[1].replace(/""/g, '"') : normalizeIdentifier(nameMatch[2] ?? '').name;
  const table = parseQualifiedName(statement, from + nameMatch[0].length);
  if (table === null) return null;
  return { name, key: table.key, rest: table.end };
}

function parsePrivileges(raw: string): ReadonlySet<string> {
  const withoutColumns = raw.replace(/\([^)]*\)/g, ' ');
  const privileges = new Set<string>();
  for (const part of withoutColumns.split(',')) {
    const trimmed = part.trim().toLowerCase();
    if (trimmed === 'all' || trimmed === 'all privileges') {
      for (const privilege of ALL_PRIVILEGES) privileges.add(privilege);
      continue;
    }
    const verb = /^[a-z]+/.exec(trimmed)?.[0];
    if (verb !== undefined && verb.length > 0) privileges.add(verb);
  }
  return privileges;
}

const NON_TABLE_GRANT_TARGET = /^(?:sequence|function|procedure|routine|schema|database|domain|type|language|tablespace|foreign\s+data\s+wrapper|foreign\s+server|large\s+object)\b/i;
const ALL_TABLES_IN_SCHEMA = /^all\s+tables\s+in\s+schema\s+/i;

function findStringClose(text: string, open: number): number {
  let k = open + 1;
  while (k < text.length) {
    if (text[k] === '\'') {
      if (text[k + 1] === '\'') {
        k += 2;
        continue;
      }
      return k + 1;
    }
    k += 1;
  }
  return text.length;
}

function splitTopLevelValues(text: string, from: number): readonly string[] {
  const values: string[] = [];
  let current = '';
  let depth = 0;
  let j = from;
  while (j < text.length) {
    const ch = text[j] as string;
    if (ch === '\'') {
      const close = findStringClose(text, j);
      current += text.slice(j, close);
      j = close;
      continue;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') {
      if (depth === 0) {
        values.push(current);
        return values;
      }
      depth -= 1;
    }
    if (ch === ',' && depth === 0) {
      values.push(current);
      current = '';
      j += 1;
      continue;
    }
    current += ch;
    j += 1;
  }
  return values;
}

function unquoteLiteral(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith('\'') && trimmed.endsWith('\'') ? trimmed.slice(1, -1) : trimmed;
}

export interface MigrationAnalysis {
  readonly findings: Finding[];
  readonly filesRead: readonly string[];
  readonly limits: readonly string[];
}

export function analyzeMigrations(appRoot: string): MigrationAnalysis {
  const read = readMigrationFiles(appRoot);
  const exposure = readExposure(appRoot);
  const findings: Finding[] = [];

  // Final state over the whole ordered migration sequence.
  const tables = new Map<string, TableState>();
  const rls = new Map<string, RlsState>();
  const policies = new Map<string, PolicyState>();
  const grants = new Map<string, GrantState>();
  const views = new Map<string, ViewState>();
  const functions = new Map<string, FunctionState>();
  const buckets = new Map<string, BucketState>();

  for (const file of read.files) {
    for (const statement of splitSqlStatements(file.text)) {
      const s = statement.stripped;

      const createTableMatch = /^create (?:temp |temporary |unlogged )?table (?:if not exists )?/i.exec(s);
      if (createTableMatch !== null) {
        const isSessionLocal = /^create (?:temp |temporary |unlogged )/i.test(s);
        const target = parseQualifiedName(s, createTableMatch[0].length);
        if (target !== null && !isSessionLocal) {
          const existing = tables.get(target.key);
          if (existing === undefined || existing.dropped) {
            tables.set(target.key, { created: file.location, dropped: false });
            rls.delete(target.key);
            for (const policyKey of [...policies.keys()]) {
              if (policyKey.startsWith(`${target.key}|`)) policies.delete(policyKey);
            }
            for (const grantKey of [...grants.keys()]) {
              if (grantKey.startsWith(`${target.key}|`)) grants.delete(grantKey);
            }
          }
        }
      }

      const dropTableMatch = /^drop table (?:if exists )?/i.exec(s);
      if (dropTableMatch !== null) {
        const target = parseQualifiedName(s, dropTableMatch[0].length);
        if (target !== null) {
          tables.delete(target.key);
          rls.delete(target.key);
          for (const policyKey of [...policies.keys()]) {
            if (policyKey.startsWith(`${target.key}|`)) policies.delete(policyKey);
          }
          for (const grantKey of [...grants.keys()]) {
            if (grantKey.startsWith(`${target.key}|`)) grants.delete(grantKey);
          }
        }
      }

      const alterTableMatch = /^alter table (?:if exists )?(?:only )?/i.exec(s);
      if (alterTableMatch !== null) {
        const target = parseQualifiedName(s, alterTableMatch[0].length);
        if (target !== null) {
          const renameMatch = /\brename\s+to\s+/i.exec(s);
          if (renameMatch !== null && renameMatch.index !== undefined) {
            const newName = parseQualifiedName(s, renameMatch.index + renameMatch[0].length);
            if (newName !== null && newName.key !== target.key) {
              const table = tables.get(target.key);
              if (table !== undefined) {
                tables.delete(target.key);
                tables.set(newName.key, { ...table });
              }
              const rlsState = rls.get(target.key);
              if (rlsState !== undefined) {
                rls.delete(target.key);
                rls.set(newName.key, rlsState);
              }
              for (const policyKey of [...policies.keys()]) {
                if (policyKey.startsWith(`${target.key}|`)) {
                  const policy = policies.get(policyKey);
                  policies.delete(policyKey);
                  if (policy !== undefined) policies.set(`${newName.key}|${policy.name}`, { ...policy, table: newName.key });
                }
              }
              for (const grantKey of [...grants.keys()]) {
                if (grantKey.startsWith(`${target.key}|`)) {
                  const state = grants.get(grantKey);
                  grants.delete(grantKey);
                  if (state !== undefined) grants.set(`${newName.key}|${grantKey.slice(grantKey.indexOf('|') + 1)}`, state);
                }
              }
            }
          }
          const location = `${file.location}:${String(statement.line)}`;
          if (/\benable\s+row\s+level\s+security\b/i.test(s)) {
            rls.set(target.key, { enabled: true, forced: rls.get(target.key)?.forced ?? false, lastVerb: 'enabled', lastLocation: location });
          } else if (/\bdisable\s+row\s+level\s+security\b/i.test(s)) {
            rls.set(target.key, { enabled: false, forced: rls.get(target.key)?.forced ?? false, lastVerb: 'disabled', lastLocation: location });
          }
          if (/\bforce\s+row\s+level\s+security\b/i.test(s)) {
            const state = rls.get(target.key);
            rls.set(target.key, {
              enabled: state?.enabled ?? false,
              forced: true,
              lastVerb: state?.lastVerb ?? 'enabled',
              lastLocation: state?.lastLocation ?? location,
            });
          } else if (/\bno\s+force\s+row\s+level\s+security\b/i.test(s)) {
            const state = rls.get(target.key);
            rls.set(target.key, {
              enabled: state?.enabled ?? false,
              forced: false,
              lastVerb: state?.lastVerb ?? 'enabled',
              lastLocation: state?.lastLocation ?? location,
            });
          }
        }
      }

      const createPolicyMatch = /^create (?:or replace )?policy\s+/i.exec(s);
      if (createPolicyMatch !== null) {
        const target = parsePolicyTarget(s, createPolicyMatch[0].length);
        if (target !== null) {
          const clauses = parsePolicyClauses(s.slice(target.rest));
          policies.set(`${target.key}|${target.name}`, {
            table: target.key,
            name: target.name,
            permissive: clauses.permissive ?? true,
            operation: clauses.operation ?? 'all',
            roles: clauses.roles ?? null,
            usingTrue: clauses.usingTrue ?? false,
            checkTrue: clauses.checkTrue ?? false,
            location: file.location,
            line: statement.line,
          });
        }
      }

      const alterPolicyMatch = /^alter policy\s+/i.exec(s);
      if (alterPolicyMatch !== null) {
        const target = parsePolicyTarget(s, alterPolicyMatch[0].length);
        if (target !== null) {
          const existing = policies.get(`${target.key}|${target.name}`);
          if (existing !== undefined) {
            const clauses = parsePolicyClauses(s.slice(target.rest));
            policies.set(`${target.key}|${target.name}`, {
              ...existing,
              permissive: clauses.permissive ?? existing.permissive,
              operation: clauses.operation ?? existing.operation,
              roles: clauses.roles ?? existing.roles,
              usingTrue: clauses.usingTrue ?? existing.usingTrue,
              checkTrue: clauses.checkTrue ?? existing.checkTrue,
              location: file.location,
              line: statement.line,
            });
          }
        }
      }

      const dropPolicyMatch = /^drop policy (?:if exists )?\s*/i.exec(s);
      if (dropPolicyMatch !== null) {
        const target = parsePolicyTarget(s, dropPolicyMatch[0].length);
        if (target !== null) policies.delete(`${target.key}|${target.name}`);
      }

      const grantMatch = /^grant\s+([\s\S]+?)\s+on\s+/i.exec(s);
      if (grantMatch !== null && grantMatch[1] !== undefined) {
        const privileges = parsePrivileges(grantMatch[1]);
        let cursor = grantMatch[0].length;
        const tableKeyword = /^table\s+/i.exec(s.slice(cursor));
        if (tableKeyword !== null && tableKeyword[0] !== undefined) cursor += tableKeyword[0].length;
        const allTablesMatch = ALL_TABLES_IN_SCHEMA.exec(s.slice(cursor));
        const targets: string[] = [];
        if (allTablesMatch !== null && allTablesMatch[0] !== undefined) {
          const schema = parseIdentifier(s, cursor + allTablesMatch[0].length);
          if (schema !== null) {
            for (const key of tables.keys()) {
              if (key.startsWith(`${schema.name}.`)) targets.push(key);
            }
          }
        } else if (!NON_TABLE_GRANT_TARGET.test(s.slice(cursor))) {
          const target = parseQualifiedName(s, cursor);
          if (target !== null) targets.push(target.key);
        }
        if (targets.length > 0) {
          const toMatch = /\sto\s+([^;]+?)\s*(?:with\s+grant\s+option)?\s*$/i.exec(s);
          if (toMatch !== null && toMatch[1] !== undefined) {
            const roles = toMatch[1].split(',').map((role) => normalizeIdentifier(role).name);
            for (const targetKey of targets) {
              for (const role of roles) {
                grants.set(`${targetKey}|${role}`, {
                  privileges,
                  location: file.location,
                  line: statement.line,
                });
              }
            }
          }
        }
      }

      const revokeMatch = /^revoke\s+(?:grant\s+option\s+for\s+)?([\s\S]+?)\s+on\s+/i.exec(s);
      if (revokeMatch !== null && revokeMatch[1] !== undefined) {
        const isAll = /^all(\s+privileges)?$/i.test(revokeMatch[1].trim());
        const privileges = parsePrivileges(revokeMatch[1]);
        let cursor = revokeMatch[0].length;
        const tableKeyword = /^table\s+/i.exec(s.slice(cursor));
        if (tableKeyword !== null && tableKeyword[0] !== undefined) cursor += tableKeyword[0].length;
        if (!ALL_TABLES_IN_SCHEMA.test(s.slice(cursor)) && !NON_TABLE_GRANT_TARGET.test(s.slice(cursor))) {
          const target = parseQualifiedName(s, cursor);
          if (target !== null) {
            const fromMatch = /\sfrom\s+([^;]+?)\s*(?:cascade|restrict)?\s*$/i.exec(s);
            if (fromMatch !== null && fromMatch[1] !== undefined) {
              const roles = fromMatch[1].split(',').map((role) => normalizeIdentifier(role).name);
              for (const role of roles) {
                const key = `${target.key}|${role}`;
                if (isAll) {
                  grants.delete(key);
                  continue;
                }
                const state = grants.get(key);
                if (state === undefined) continue;
                const remaining = new Set([...state.privileges].filter((privilege) => !privileges.has(privilege)));
                if (remaining.size === 0) grants.delete(key);
                else grants.set(key, { ...state, privileges: remaining });
              }
            }
          }
        }
      }

      const viewMatch = /^create (?:or replace )?view\s+/i.exec(s);
      if (viewMatch !== null) {
        const target = parseQualifiedName(s, viewMatch[0].length);
        if (target !== null) {
          views.set(target.key, {
            name: target.key,
            invoker: /security_invoker\s*=\s*true/i.test(s),
            location: file.location,
            line: statement.line,
          });
        }
      }
      const dropViewMatch = /^drop view (?:if exists )?\s*/i.exec(s);
      if (dropViewMatch !== null) {
        const target = parseQualifiedName(s, dropViewMatch[0].length);
        if (target !== null) views.delete(target.key);
      }

      const functionMatch = /^create (?:or replace )?function\s+/i.exec(s);
      if (functionMatch !== null) {
        const target = parseQualifiedName(s, functionMatch[0].length);
        if (target !== null) {
          // The function-level `set search_path` clause lives in the header; a `set search_path`
          // statement inside the body is runtime behaviour, not the pin.
          const asMatch = /\sas\b/i.exec(s);
          const header = asMatch === null || asMatch.index === undefined ? s : s.slice(0, asMatch.index);
          functions.set(target.key, {
            name: target.key,
            definer: /\bsecurity\s+definer\b/i.test(s),
            searchPath: /\bset\s+search_path\s*=/i.test(header),
            location: file.location,
            line: statement.line,
          });
        }
      }
      const dropFunctionMatch = /^drop function (?:if exists )?\s*/i.exec(s);
      if (dropFunctionMatch !== null) {
        const target = parseQualifiedName(s, dropFunctionMatch[0].length);
        if (target !== null) functions.delete(target.key);
      }

      if (/storage\.buckets/i.test(s)) {
        const insertMatch = /^insert\s+into\s+storage\.buckets\s*/i.exec(s);
        if (insertMatch !== null && insertMatch[0] !== undefined) {
          const columnsMatch = /^\(([^)]*)\)\s*values\s*\(/i.exec(s.slice(insertMatch[0].length));
          let columns: readonly string[] | null = null;
          let valuesFrom = insertMatch[0].length;
          if (columnsMatch !== null && columnsMatch[1] !== undefined) {
            columns = columnsMatch[1].split(',').map((column) => normalizeIdentifier(column).name);
            valuesFrom = insertMatch[0].length + columnsMatch[0].length;
          } else {
            // Positional insert (no column list): skip the `values (` prefix before splitting.
            const valuesKeyword = /\bvalues\s*\(/i.exec(s.slice(insertMatch[0].length));
            if (valuesKeyword !== null && valuesKeyword[0] !== undefined && valuesKeyword.index !== undefined) {
              valuesFrom = insertMatch[0].length + valuesKeyword.index + valuesKeyword[0].length;
            }
          }
          const values = splitTopLevelValues(s, valuesFrom);
          const publicIndex = columns === null ? 2 : columns.indexOf('public');
          const idIndex = columns === null ? 0 : columns.indexOf('id');
          const publicRaw = publicIndex >= 0 ? values[publicIndex] : undefined;
          if (publicRaw !== undefined) {
            const publicFlag = /^true$/i.test(publicRaw.trim());
            const idRaw = idIndex >= 0 ? values[idIndex] : undefined;
            const id = idRaw === undefined ? `bucket-${String(statement.line)}` : unquoteLiteral(idRaw);
            buckets.set(id, { id, publicFlag, location: file.location, line: statement.line });
          }
        } else {
          const updateMatch = /^update\s+storage\.buckets\s+/i.exec(s);
          if (updateMatch !== null) {
            const setMatch = /\bset\s+public\s*=\s*(true|false)\b/i.exec(s);
            if (setMatch !== null && setMatch[1] !== undefined) {
              const publicFlag = setMatch[1].toLowerCase() === 'true';
              const whereMatch = /\bwhere\s+id\s*=\s*'([^']*)'/i.exec(s);
              if (whereMatch !== null && whereMatch[1] !== undefined) {
                const existing = buckets.get(whereMatch[1]);
                if (existing !== undefined) {
                  existing.publicFlag = publicFlag;
                  existing.location = file.location;
                  existing.line = statement.line;
                } else {
                  buckets.set(whereMatch[1], { id: whereMatch[1], publicFlag, location: file.location, line: statement.line });
                }
              } else {
                for (const bucket of buckets.values()) {
                  bucket.publicFlag = publicFlag;
                  bucket.location = file.location;
                  bucket.line = statement.line;
                }
              }
            }
          }
        }
      }
    }
  }

  // Findings are read off the final state: a dropped table, a dropped policy, a revoked grant,
  // an RLS disable or a public=false update all silence what they remove.
  for (const [key, table] of tables) {
    if (table.dropped) continue;
    if (!exposure.schemas.has(schemaOf(key))) continue;
    const rlsState = rls.get(key);
    if (rlsState?.enabled === true) continue;
    const disabledNote = rlsState !== undefined && rlsState.lastVerb === 'disabled'
      ? `Row-level security was enabled and later disabled (${rlsState.lastLocation}); the final state leaves the table unprotected. `
      : '';
    findings.push(finding(
      `migration-inventory:rls-missing:${table.created}:${key}`,
      'supabase.rls-missing',
      'high',
      `Table ${key} is created in the API-exposed ${schemaOf(key)} schema without row-level security enabled in the final migration state.`,
      `${disabledNote}No migration read leaves row-level security enabled for ${key}. Rows are not gated by the database for any role that reaches the table; whether the anon key can read or write them depends on the grants in effect and the Data API exposure recorded in configuration. Enable row-level security and add the table's policies.`,
      table.created,
      ['DATA-01', 'AUTHZ-01'],
    ));
  }

  for (const policy of policies.values()) {
    if (!policy.permissive) continue;
    if (!policy.usingTrue && !policy.checkTrue) continue;
    const clauseText = policy.usingTrue && policy.checkTrue
      ? 'using (true) and with check (true)'
      : policy.usingTrue
        ? 'using (true)'
        : 'with check (true)';
    const roleText = policy.roles === null ? 'all roles' : policy.roles.join(', ');
    const updateNote = policy.operation === 'update' && !policy.checkTrue
      ? ' For UPDATE, with check defaults to the using expression, so the same breadth applies to writes; whether that is exploitable depends on the roles and grants in effect.'
      : '';
    findings.push(finding(
      `migration-inventory:permissive-policy:${policy.location}:${policy.name}`,
      'supabase.permissive-policy',
      'high',
      `Policy "${policy.name}" on ${policy.table} (${policy.operation} for ${roleText}) admits every row: ${clauseText} makes the policy a no-op gate for the roles it covers.`,
      `A row-level-security policy with ${clauseText} allows every row for each role that reaches the table (${roleText}). Restrict the policy to the owning user or an explicit role check.${updateNote}`,
      `${policy.location}:${String(policy.line)}`,
      ['DATA-01', 'AUTHZ-02'],
    ));
  }

  for (const [grantKey, grant] of grants) {
    const separator = grantKey.indexOf('|');
    const tableKey = grantKey.slice(0, separator);
    const role = grantKey.slice(separator + 1);
    if (!ANON_ROLES.has(role)) continue;
    const table = tables.get(tableKey);
    if (table === undefined || table.dropped) continue;
    if (!exposure.schemas.has(schemaOf(tableKey))) continue;
    const writePrivileges = [...grant.privileges].filter((privilege) => WRITE_PRIVILEGES.has(privilege)).sort();
    if (writePrivileges.length === 0) continue;
    const verbText = writePrivileges.join(', ');
    const rlsOn = rls.get(tableKey)?.enabled === true;
    if (rlsOn) {
      // A-14: an RLS-protected write grant is never a proven bypass — bounded wording only.
      findings.push(finding(
        `migration-inventory:grant-anon-write:${grant.location}:${tableKey}:${verbText}`,
        'supabase.grant-anon-write',
        'medium',
        `Write privileges (${verbText}) on ${tableKey} are granted to ${role} while row-level security is enabled. The RLS policies still gate which rows the role can touch; review whether a direct write grant to ${role} is needed.`,
        `A direct ${verbText} grant to ${role} is recorded in the final migration state, and row-level security is on for ${tableKey}. The grant itself does not bypass RLS: the table's policies decide which rows the role may touch. Review whether the write grant is needed at all.`,
        `${grant.location}:${String(grant.line)}`,
        ['DATA-01', 'AUTHZ-03'],
      ));
    } else {
      findings.push(finding(
        `migration-inventory:grant-anon-write:${grant.location}:${tableKey}:${verbText}`,
        'supabase.grant-anon-write',
        'high',
        `Write privileges (${verbText}) on ${tableKey} are granted to ${role} while row-level security is off in the final migration state — the grant is not row-gated by RLS.`,
        `A direct ${verbText} grant to ${role} is recorded and no migration read leaves row-level security enabled for ${tableKey}. With the schema exposed over the Data API this is a broad write path that needs review: grant only what the API needs and prefer RLS policies over direct grants.`,
        `${grant.location}:${String(grant.line)}`,
        ['DATA-01', 'AUTHZ-03'],
      ));
    }
  }

  for (const fn of functions.values()) {
    if (!fn.definer || fn.searchPath) continue;
    findings.push(finding(
      `migration-inventory:security-definer:${fn.location}:${fn.name}`,
      'supabase.security-definer-search-path',
      'high',
      `Function ${fn.name} is security definer without a fixed search_path. The function runs with owner privileges while search_path can be hijacked through the caller's schema search order.`,
      'A security-definer function without `set search_path = public` (or an explicit schema list) in its definition can be made to resolve unqualified names inside an attacker-controlled schema. Pin the search_path in the function definition.',
      `${fn.location}:${String(fn.line)}`,
      ['DATA-01', 'SEC-02'],
    ));
  }

  for (const bucket of buckets.values()) {
    if (!bucket.publicFlag) continue;
    findings.push(finding(
      `migration-inventory:public-bucket:${bucket.location}:${String(bucket.line)}`,
      'supabase.public-bucket',
      'high',
      `Storage bucket "${bucket.id}" is public in the final migration state. Anyone with the publishable key (or the URL, for public buckets) can read every object in it.`,
      'Public buckets expose all objects to anyone with the URL. Publication alone does not prove the bucket contains sensitive data — treat public publication and proven sensitive exposure as separate questions. Keep user buckets private and use signed URLs for display; only genuinely public assets belong in a public bucket.',
      `${bucket.location}:${String(bucket.line)}`,
      ['DATA-01', 'SEC-02'],
    ));
  }

  for (const view of views.values()) {
    if (view.invoker) continue;
    if (!exposure.schemas.has(schemaOf(view.name))) continue;
    findings.push(finding(
      `migration-inventory:view-security-invoker:${view.location}:${view.name}`,
      'supabase.view-security-invoker',
      'medium',
      `View ${view.name} is in an API-exposed schema without security_invoker = true, so it queries with the view owner's rights and bypasses the querying user's row-level security.`,
      'A view without security_invoker runs with its owner\u2019s privileges: rows the calling user could never select directly become readable through the view. Add `with (security_invoker = true)` to the view definition.',
      `${view.location}:${String(view.line)}`,
      ['DATA-01', 'AUTHZ-01'],
    ));
  }

  const limits: string[] = [];
  if (read.skipped > 0) {
    limits.push(`${String(read.skipped)} migration file(s) skipped at the review bounds (${String(MAX_MIGRATION_FILES)} files, ${String(Math.round(MAX_MIGRATION_BYTES / 1024))} KiB each)`);
  }
  if (read.note !== undefined) limits.push(read.note);
  limits.push(`exposure: ${exposure.note}`);

  return { findings, filesRead: read.files.map((file) => file.location), limits };
}
