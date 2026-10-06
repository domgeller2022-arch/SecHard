import { readFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import { parseAllDocuments, visit, isAlias, type Document } from 'yaml';
import { sha256Hex } from '../evidence/digest.js';
import { issue, type ValidationIssue } from './errors.js';

export interface LoadLimits {
  readonly maxFileBytes: number;
  readonly maxDepth: number;
  readonly maxKeys: number;
  readonly maxStringLength: number;
  readonly maxArrayLength: number;
}

export const DEFAULT_LIMITS: LoadLimits = {
  maxFileBytes: 4 * 1024 * 1024,
  maxDepth: 48,
  maxKeys: 20_000,
  maxStringLength: 32_768,
  maxArrayLength: 5_000,
};

export interface LoadResult<T = unknown> {
  readonly data: T;
  readonly file: string;
  readonly rawDigest: string;
  readonly byteLength: number;
  readonly issues: readonly ValidationIssue[];
}

export interface LoadOptions {
  readonly limits?: Partial<LoadLimits>;
  readonly requireObject?: boolean;
}

const CORE_TAGS = new Set([
  'tag:yaml.org,2002:null',
  'tag:yaml.org,2002:bool',
  'tag:yaml.org,2002:int',
  'tag:yaml.org,2002:float',
  'tag:yaml.org,2002:str',
  'tag:yaml.org,2002:map',
  'tag:yaml.org,2002:seq',
]);

/**
 * Parses YAML or JSON from disk under hard structural limits.
 *
 * JSON is parsed by the YAML parser on purpose: `JSON.parse` silently keeps the last of a set of
 * duplicate keys, which is exactly the ambiguity this loader must reject.
 *
 * Never evaluates code, resolves no includes, and follows no external references.
 */
export function loadDocument<T = unknown>(
  file: string,
  options: LoadOptions = {},
): LoadResult<T> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const requireObject = options.requireObject ?? true;
  const fail = (code: ValidationIssue['code'], message: string, path?: string): LoadResult<T> => ({
    data: undefined as T,
    file,
    rawDigest: '',
    byteLength: 0,
    issues: [issue(code, message, file, path)],
  });

  let stats;
  try {
    stats = statSync(file);
  } catch {
    return fail('input.not_found', `file does not exist: ${basename(file)}`);
  }
  if (!stats.isFile()) return fail('input.not_a_file', `not a regular file: ${basename(file)}`);
  if (stats.size > limits.maxFileBytes) {
    return fail(
      'input.file_too_large',
      `file is ${stats.size} bytes; limit is ${limits.maxFileBytes}`,
    );
  }

  let text: string;
  let bytes: Buffer;
  try {
    bytes = readFileSync(file);
    text = bytes.toString('utf8');
  } catch {
    return fail('input.parse_error', `file could not be read: ${basename(file)}`);
  }

  const documents = parseAllDocuments(text, {
    customTags: [],
    merge: false,
    uniqueKeys: true,
    strict: true,
    version: '1.2',
    intAsBigInt: false,
  });

  if (documents.length === 0) {
    return fail('input.empty_document', `file contains no document: ${basename(file)}`);
  }
  if (documents.length > 1) {
    return fail(
      'input.multiple_documents',
      `expected one document, found ${documents.length}: ${basename(file)}`,
    );
  }

  const structural = checkStructure(documents[0] as Document, file, limits);
  if (structural.length > 0) return { data: undefined as T, file, rawDigest: '', byteLength: bytes.length, issues: structural };

  let data: unknown;
  try {
    data = documents[0]!.toJS({ maxAliasCount: 0 });
  } catch (error) {
    return fail('input.parse_error', `parse failed: ${(error as Error).message}`);
  }

  if (data === null || data === undefined) {
    return fail('input.empty_document', `file contains no document: ${basename(file)}`);
  }

  const limitsIssues = checkLimits(data, file, limits);
  if (limitsIssues.length > 0) {
    return { data: undefined as T, file, rawDigest: '', byteLength: bytes.length, issues: limitsIssues };
  }

  if (requireObject && (typeof data !== 'object' || Array.isArray(data))) {
    return fail('input.not_an_object', 'document root must be an object');
  }

  return { data: data as T, file, rawDigest: sha256Hex(bytes), byteLength: bytes.length, issues: [] };
}

function firstLine(message: string): string {
  return message.split('\n')[0] ?? message;
}

/**
 * The YAML parser's duplicate-key message names the position but not always the key, and the key
 * text is on a later line. Reporting which key collided is the difference between an actionable
 * error and a guess, so the offending lines are extracted where the parser includes them.
 */
function summarizeDuplicateKey(message: string): string {
  const lines = message.split('\n');
  const head = firstLine(message);
  const candidate = lines
    .slice(1)
    .map((line) => line.trim())
    .find((line) => line.length > 0 && line !== '^');

  const match = candidate?.match(/^([^:\s][^:]*):/);
  return match ? `${head} (key '${match[1]}')` : head;
}

function checkStructure(doc: Document, file: string, limits: LoadLimits): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (doc.errors.length > 0) {
    for (const error of doc.errors) {
      const code: ValidationIssue['code'] =
        error.code === 'DUPLICATE_KEY' ? 'input.duplicate_key' : 'input.parse_error';
      const detail = code === 'input.duplicate_key' ? summarizeDuplicateKey(error.message) : firstLine(error.message);
      issues.push(issue(code, detail, file));
    }
    return issues;
  }

  visit(doc, {
    Node(key, node) {
      if (isAlias(node)) {
        issues.push(issue('input.alias_or_anchor', 'YAML aliases are not accepted', file, String(key ?? '$')));
      }
      const anchor = (node as { anchor?: string }).anchor;
      if (typeof anchor === 'string' && anchor.length > 0) {
        issues.push(issue('input.alias_or_anchor', `YAML anchor &${anchor} is not accepted`, file, String(key ?? '$')));
      }
      const tag = (node as { tag?: string }).tag;
      if (typeof tag === 'string' && !CORE_TAGS.has(tag) && !tag.startsWith('tag:yaml.org,2002:str@')) {
        issues.push(issue('input.custom_tag', `YAML tag ${tag} is not accepted`, file, String(key ?? '$')));
      }
    },
  });

  void limits;
  return issues;
}

/**
 * A lone surrogate has no UTF-8 encoding, so a record containing one cannot be canonicalized or
 * hashed consistently. It is rejected as input rather than surfacing as a hashing error later.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function checkLimits(value: unknown, file: string, limits: LoadLimits): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  let keyCount = 0;

  const walk = (node: unknown, path: string, depth: number): void => {
    if (depth > limits.maxDepth) {
      issues.push(issue('input.depth_exceeded', `nesting deeper than ${limits.maxDepth}`, file, path));
      return;
    }

    // Values that cannot round-trip through canonical JSON are rejected here, at the input boundary,
    // rather than being coerced. A number that lost precision on parse would silently produce a
    // digest over a value nobody wrote.
    if (typeof node === 'number' && !Number.isFinite(node)) {
      issues.push(issue('input.non_finite_number', 'value is not a finite number and cannot be represented in canonical JSON', file, path));
      return;
    }
    if (typeof node === 'number' && Number.isInteger(node) && !Number.isSafeInteger(node)) {
      issues.push(
        issue(
          'input.unsafe_integer',
          'integer exceeds the exactly representable range; quote it as a string if it is an identifier',
          file,
          path,
        ),
      );
      return;
    }
    if (typeof node === 'bigint') {
      issues.push(issue('input.unsafe_integer', 'bigint values are not part of the supported record model; use a string', file, path));
      return;
    }

    if (typeof node === 'string') {
      if (node.length > limits.maxStringLength) {
        issues.push(
          issue('input.string_too_long', `string longer than ${limits.maxStringLength} characters`, file, path),
        );
      }
      if (LONE_SURROGATE.test(node)) {
        issues.push(issue('input.invalid_unicode', 'string contains a lone surrogate, which has no UTF-8 encoding', file, path));
      }
      return;
    }
    if (Array.isArray(node)) {
      if (node.length > limits.maxArrayLength) {
        issues.push(
          issue('input.collection_too_large', `array longer than ${limits.maxArrayLength}`, file, path),
        );
        return;
      }
      node.forEach((item, index) => walk(item, `${path}[${index}]`, depth + 1));
      return;
    }
    if (node !== null && typeof node === 'object') {
      const entries = Object.entries(node as Record<string, unknown>);
      keyCount += entries.length;
      if (keyCount > limits.maxKeys) {
        issues.push(issue('input.collection_too_large', `more than ${limits.maxKeys} total keys`, file, path));
        return;
      }
      for (const [key, child] of entries) walk(child, `${path}.${key}`, depth + 1);
    }
  };

  walk(value, '$', 0);
  return issues;
}
