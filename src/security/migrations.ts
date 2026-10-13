import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '../domain/types.js';

/**
 * Static rules over Supabase migrations (Batch F2, fix brief F-06): the six reviewed rule
 * families over `supabase/migrations/*.sql`, each reported with its location. Statement-shape
 * matching on purpose — the plan's rule for this work is that no SQL-parser dependency is added;
 * the shapes are the ones the rules name, verified against fixtures.
 *
 * Table state (created -> RLS enabled) is tracked across all migration files in name order,
 * because migrations run sequentially: a table created in 0001 and protected in 0007 is fine;
 * one never protected is the finding.
 */

interface MigrationFile {
  readonly path: string;
  readonly location: string;
  readonly text: string;
}

const MAX_MIGRATION_FILES = 200;
const MAX_MIGRATION_BYTES = 512 * 1024;

function readMigrationFiles(appRoot: string): MigrationFile[] {
  const dir = join(appRoot, 'supabase', 'migrations');
  let entries: string[];
  try {
    entries = readdirSync(dir).filter((name) => name.endsWith('.sql')).sort();
  } catch {
    return [];
  }
  const files: MigrationFile[] = [];
  for (const name of entries.slice(0, MAX_MIGRATION_FILES)) {
    const full = join(dir, name);
    try {
      if (!statSync(full).isFile()) continue;
      files.push({ path: full, location: `supabase/migrations/${name}`, text: readFileSync(full, 'utf8').slice(0, MAX_MIGRATION_BYTES) });
    } catch {
      continue;
    }
  }
  return files;
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

function lineOf(text: string, statement: string): number {
  const index = text.indexOf(statement);
  if (index < 0) return 1;
  return text.slice(0, index).split('\n').length;
}

export function analyzeMigrations(appRoot: string): { findings: Finding[]; filesRead: readonly string[] } {
  const files = readMigrationFiles(appRoot);
  const findings: Finding[] = [];

  // Table state across the whole migration sequence.
  const createdTables = new Map<string, string>();
  const rlsEnabled = new Set<string>();
  const exposedSchemas = new Set<string>(['public']);

  for (const file of files) {
    const statements = file.text.split(/;\s*(?:\n|$)/).map((statement) => statement.trim()).filter(Boolean);

    for (const statement of statements) {
      const lowered = statement.toLowerCase().replace(/\s+/g, ' ');

      const createMatch = /create table (?:if not exists )?(?:(\w+)\.)?(\w+)/i.exec(statement);
      if (createMatch !== null) {
        const schema = createMatch[1] ?? 'public';
        const name = `${schema}.${createMatch[2]}`;
        if (!createdTables.has(name)) createdTables.set(name, file.location);
      }

      const rlsMatch = /alter table (?:only )?(?:(\w+)\.)?(\w+) enable row level security/i.exec(statement);
      if (rlsMatch !== null) {
        const schema = rlsMatch[1] ?? 'public';
        rlsEnabled.add(`${schema}.${rlsMatch[2]}`);
      }

      const schemaMatch = /create schema (?:if not exists )?(\w+)/i.exec(statement);
      if (schemaMatch !== null && schemaMatch[1] !== undefined) exposedSchemas.add(schemaMatch[1]);

      // Policies that grant everything: using (true) or with check (true).
      const policyMatch = /create policy\s+"?([\w-]+)"?\s+on\s+(?:(\w+)\.)?(\w+)/i.exec(statement);
      if (policyMatch !== null && /\busing\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(lowered)) {
        const schema = policyMatch[2] ?? 'public';
        const table = policyMatch[3] ?? 'unknown';
        const policyName = policyMatch[1] ?? table;
        findings.push(finding(
          `migration-inventory:permissive-policy:${file.location}:${policyName}`,
          'supabase.permissive-policy',
          'high',
          `Policy "${policyName}" on ${schema}.${table} grants to everyone: using (true) or with check (true) makes the policy a no-op for that operation.`,
          'A row-level-security policy with using (true) or with check (true) allows every row for every role that reaches the table. Restrict the policy to the owning user or an explicit role check.',
          `${file.location}:${lineOf(file.text, statement)}`,
          ['DATA-01', 'AUTHZ-02'],
        ));
      }

      // grant all / grant write verbs to anon (or public).
      const grantMatch = /grant\s+(all(?:\s+privileges)?|insert|update|delete|truncate)(?:\s*,\s*(?:insert|update|delete|select|truncate))*\s+on\s+(?:table\s+)?(?:(\w+)\.)?([\w.]+)\s+to\s+([^;]+)/i.exec(statement);
      if (grantMatch !== null) {
        const verbs = (grantMatch[1] ?? '').toLowerCase();
        const to = (grantMatch[4] ?? '').toLowerCase();
        const schema = grantMatch[2] ?? 'public';
        const target = grantMatch[3] ?? 'unknown';
        const dangerousTo = /\banon\b|\bpublic\b/.test(to);
        const dangerousVerbs = verbs.includes('all') || /(insert|update|delete|truncate)/.test(verbs);
        if (dangerousTo && dangerousVerbs) {
          const role = /\banon\b/.test(to) ? 'anon' : 'public';
          findings.push(finding(
            `migration-inventory:grant-anon-write:${file.location}:${target}:${verbs}`,
            'supabase.grant-anon-write',
            'high',
            `${verbs.startsWith('all') ? 'All privileges' : 'Write privileges'} on ${schema}.${target} are granted to ${role}. The anonymous key can modify that table directly.`,
            `A grant of ${verbs} to ${role} lets the publishable/anonymous key write to the table without any row-level-security check of its own. Grant only what the API needs, and prefer relying on RLS policies over direct grants.`,
            `${file.location}:${lineOf(file.text, statement)}`,
            ['DATA-01', 'AUTHZ-03'],
          ));
        }
      }

      // security definer functions without a fixed search_path.
      if (/\bsecurity\s+definer\b/i.test(lowered)) {
        const hasSearchPath = /set\s+search_path\s*=/i.test(lowered);
        if (!hasSearchPath) {
          const nameMatch = /function\s+([\w.]+)/i.exec(statement);
          const name = nameMatch?.[1] ?? 'unnamed function';
          findings.push(finding(
            `migration-inventory:security-definer:${file.location}:${name}`,
            'supabase.security-definer-search-path',
            'high',
            `Function ${name} is security definer without a fixed search_path. The function runs with owner privileges while search_path can be hijacked through the caller's schema search order.`,
            'A security-definer function without `set search_path = public` (or an explicit schema list) can be made to resolve unqualified names inside an attacker-controlled schema. Pin the search_path in the function definition.',
            `${file.location}:${lineOf(file.text, statement)}`,
            ['DATA-01', 'SEC-02'],
          ));
        }
      }

      // Public storage buckets: the named form (public := true / public = true / the reviewed
      // column-position insert with true as the third value).
      if (/storage\.buckets/i.test(statement)) {
        const named = /\bpublic\b\s*[:=]\s*true/i.test(statement);
        const positional = /values\s*\(\s*'[^']+'\s*,\s*'[^']+'\s*,\s*true\s*\)/i.exec(statement) !== null;
        if (named || positional) {
          findings.push(finding(
            `migration-inventory:public-bucket:${file.location}:${lineOf(file.text, statement)}`,
            'supabase.public-bucket',
            'high',
            'A storage bucket is created or updated with public = true. Anyone with the publishable key (or the URL, for public buckets) can read every object in it.',
            'Public buckets expose all objects to anyone with the URL. Keep user buckets private and use signed URLs for display; only genuinely public assets belong in a public bucket.',
            `${file.location}:${lineOf(file.text, statement)}`,
            ['DATA-01', 'SEC-02'],
          ));
        }
      }

      // Views in an exposed schema without security_invoker = true.
      const viewMatch = /create\s+(?:or\s+replace\s+)?view\s+(?:(\w+)\.)?(\w+)/i.exec(statement);
      if (viewMatch !== null && !/security_invoker\s*=\s*true/i.test(lowered)) {
        const schema = viewMatch[1] ?? 'public';
        if (exposedSchemas.has(schema)) {
          findings.push(finding(
            `migration-inventory:view-security-invoker:${file.location}:${viewMatch[2]}`,
            'supabase.view-security-invoker',
            'medium',
            `View ${schema}.${viewMatch[2]} is in an API-exposed schema without security_invoker = true, so it queries with the view owner's rights and bypasses the querying user's row-level security.`,
            'A view without security_invoker runs with its owner\u2019s privileges: rows the calling user could never select directly become readable through the view. Add `with (security_invoker = true)` to the view definition.',
            `${file.location}:${lineOf(file.text, statement)}`,
            ['DATA-01', 'AUTHZ-01'],
          ));
        }
      }
    }
  }

  // Tables created in an exposed schema and never protected by RLS.
  for (const [table, location] of createdTables) {
    if (!rlsEnabled.has(table)) {
      findings.push(finding(
        `migration-inventory:rls-missing:${location}:${table}`,
        'supabase.rls-missing',
        'high',
        `Table ${table} is created in an API-exposed schema without enable row level security. Every row is readable (and with default grants, writable) by the anonymous key.`,
        'Row-level security is off for the whole table: the database enforces no row checks for any role, so the publishable key reaches all rows. Enable RLS in a migration and add the table\u2019s policies.',
        location,
        ['DATA-01', 'AUTHZ-01'],
      ));
    }
  }

  return { findings, filesRead: files.map((file) => file.location) };
}
