/**
 * A conservative SQL statement tokenizer (P3.3, A-13): bounded statement splitting for the
 * Supabase migration inventory. It recognises exactly the lexical shapes Postgres migrations
 * use — single-quoted strings (with '' doubling and E'' backslash escapes), quoted identifiers
 * with "" doubling, line comments, nested block comments, and dollar-quoted bodies ($$…$$ and
 * $tag$…$tag$) — and splits only on semicolons outside all of them. Function bodies keep their
 * internal semicolons, commented-out SQL never reaches a matcher, and quoted identifier case is
 * preserved while unquoted identifiers fold to lowercase. Statement shapes beyond these lexical
 * rules are out of scope by design: no SQL parser dependency enters the pack.
 */

export interface SqlStatement {
  /** The raw statement text (comments included), trimmed, without the terminating semicolon. */
  readonly text: string;
  /** The statement with comments blanked and whitespace collapsed — the matching surface. */
  readonly stripped: string;
  /** 1-based line of the statement's first significant (non-comment, non-whitespace) character. */
  readonly line: number;
}

interface StatementBuilder {
  readonly parts: string[];
  sigSeen: boolean;
  sigLine: number;
}

function isIdentifierChar(ch: string): boolean {
  return /[A-Za-z0-9_$]/.test(ch);
}

export function splitSqlStatements(text: string): SqlStatement[] {
  const statements: SqlStatement[] = [];
  let i = 0;
  let line = 1;
  let current: StatementBuilder | undefined;

  const builder = (): StatementBuilder => {
    if (current === undefined) current = { parts: [], sigSeen: false, sigLine: line };
    return current;
  };

  const append = (chunk: string): void => {
    builder().parts.push(chunk);
  };

  const markSignificant = (): void => {
    const b = builder();
    if (!b.sigSeen) {
      b.sigSeen = true;
      b.sigLine = line;
    }
  };

  const blankComment = (): void => {
    builder().parts.push(' ');
  };

  const flush = (): void => {
    if (current === undefined) return;
    const raw = current.parts.join('');
    const stripped = raw.replace(/\s+/g, ' ').trim();
    if (current.sigSeen && stripped.length > 0) {
      statements.push({ text: raw.trim(), stripped, line: current.sigLine });
    }
    current = undefined;
  };

  const scanQuoted = (quote: string, escapeDoublingOnly: boolean): void => {
    markSignificant();
    let j = i + 1;
    let chunk = quote;
    while (j < text.length) {
      const ch = text[j] as string;
      if (!escapeDoublingOnly && ch === '\\' && j + 1 < text.length) {
        chunk += text.slice(j, j + 2);
        if (text[j + 1] === '\n') line += 1;
        j += 2;
        continue;
      }
      if (ch === quote) {
        if (text[j + 1] === quote) {
          chunk += quote + quote;
          j += 2;
          continue;
        }
        chunk += quote;
        j += 1;
        break;
      }
      if (ch === '\n') line += 1;
      chunk += ch;
      j += 1;
    }
    append(chunk);
    i = j;
  };

  const scanDollarBody = (tag: string): void => {
    markSignificant();
    const opener = `$${tag}$`;
    const closer = `$${tag}$`;
    let j = i + opener.length;
    const closeIndex = text.indexOf(closer, j);
    const end = closeIndex < 0 ? text.length : closeIndex + closer.length;
    const body = text.slice(i, end);
    for (const ch of body) {
      if (ch === '\n') line += 1;
    }
    append(body);
    i = end;
  };

  /** A dollar quote opens at `$tag$`; a positional parameter like `$1` is not one. */
  const dollarTagAt = (at: number): string | null => {
    let j = at + 1;
    if (text[j] === '$') return '';
    // Postgres dollar-quote tags follow identifier rules but cannot contain `$` themselves.
    if (!/[A-Za-z_]/.test(text[j] ?? '')) return null;
    let tag = '';
    while (j < text.length && /[A-Za-z0-9_]/.test(text[j] as string)) {
      tag += text[j];
      j += 1;
    }
    if (text[j] === '$') return tag;
    return null;
  };

  while (i < text.length) {
    const ch = text[i] as string;
    if (ch === '\n') {
      line += 1;
      append(ch);
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      append(ch);
      i += 1;
      continue;
    }
    if (ch === '-' && text[i + 1] === '-') {
      const end = text.indexOf('\n', i);
      i = end < 0 ? text.length : end;
      blankComment();
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        if (text[j] === '/' && text[j + 1] === '*') {
          depth += 1;
          j += 2;
          continue;
        }
        if (text[j] === '*' && text[j + 1] === '/') {
          depth -= 1;
          j += 2;
          continue;
        }
        if (text[j] === '\n') line += 1;
        j += 1;
      }
      i = j;
      blankComment();
      continue;
    }
    if (ch === "'") {
      // E'…' strings also honour backslash escapes; plain '…' strings honour only '' doubling.
      const prev = i > 0 ? (text[i - 1] as string) : '';
      const beforePrev = i > 1 ? (text[i - 2] as string) : '';
      const escapeString = /[eE]/.test(prev) && !isIdentifierChar(beforePrev);
      scanQuoted("'", !escapeString);
      continue;
    }
    if (ch === '"') {
      scanQuoted('"', true);
      continue;
    }
    if (ch === '$') {
      const tag = dollarTagAt(i);
      if (tag !== null) {
        scanDollarBody(tag);
        continue;
      }
      markSignificant();
      append(ch);
      i += 1;
      continue;
    }
    if (ch === ';') {
      flush();
      i += 1;
      continue;
    }
    markSignificant();
    append(ch);
    i += 1;
  }
  flush();
  return statements;
}

export interface SqlIdentifier {
  readonly name: string;
  readonly quoted: boolean;
}

/** Unquoted identifiers fold to lowercase; quoted identifiers keep their case and identity. */
export function normalizeIdentifier(raw: string): SqlIdentifier {
  const trimmed = raw.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return { name: trimmed.slice(1, -1).replace(/""/g, '"'), quoted: true };
  }
  return { name: trimmed.toLowerCase(), quoted: false };
}

/** A schema-qualified name keyed as `schema.name`, defaulting the schema to `public`. */
export function qualifiedKey(schema: string | undefined, name: string): string {
  const schemaPart = schema === undefined ? 'public' : normalizeIdentifier(schema).name;
  const namePart = normalizeIdentifier(name).name;
  return `${schemaPart}.${namePart}`;
}

const IDENT_SOURCE = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;

/** Read one identifier from `stripped` at `from`, normalized per `normalizeIdentifier`. */
export function parseIdentifier(stripped: string, from: number): { name: string; end: number } | null {
  const match = new RegExp(`^${IDENT_SOURCE}`).exec(stripped.slice(from));
  if (match === null || match[0] === undefined) return null;
  return { name: normalizeIdentifier(match[0]).name, end: from + match[0].length };
}

/**
 * Read one possibly schema-qualified identifier (`table`, `public.table`, `"Public"."Users"`)
 * from `stripped` at `from`, returning its normalized key and the end offset. Whitespace around
 * the qualifying dot is tolerated because the stripped surface collapses runs of whitespace.
 */
export function parseQualifiedName(stripped: string, from: number): { key: string; end: number } | null {
  const first = new RegExp(`^${IDENT_SOURCE}`).exec(stripped.slice(from));
  if (first === null || first[0] === undefined) return null;
  const schemaIdent = normalizeIdentifier(first[0]);
  let cursor = from + first[0].length;
  const dot = /^\s*\.\s*/.exec(stripped.slice(cursor));
  if (dot === null || dot[0] === undefined) {
    return { key: `public.${schemaIdent.name}`, end: cursor };
  }
  cursor += dot[0].length;
  const second = new RegExp(`^${IDENT_SOURCE}`).exec(stripped.slice(cursor));
  if (second === null || second[0] === undefined) {
    return { key: `public.${schemaIdent.name}`, end: from + first[0].length };
  }
  const nameIdent = normalizeIdentifier(second[0]);
  cursor += second[0].length;
  return { key: `${schemaIdent.name}.${nameIdent.name}`, end: cursor };
}
