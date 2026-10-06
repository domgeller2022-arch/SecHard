import { createHash } from 'node:crypto';

/** SHA-256 over raw bytes or text. Used for original files and raw reports. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Used so the same structured record always produces the same digest. The value is restricted to the
 * I-JSON subset: JSON has no way to express NaN or Infinity, and a lone surrogate has no UTF-8
 * encoding, so both are rejected rather than silently coerced or replaced.
 *
 * Object keys are sorted as arrays of UTF-16 code units compared as unsigned integers. Array order
 * is never changed.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, '$');
}

export function canonicalDigest(value: unknown): string {
  return sha256Hex(Buffer.from(canonicalize(value), 'utf8'));
}

function serialize(value: unknown, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value, path);
    case 'string':
      return serializeString(value, path);
    case 'bigint':
      throw new Error(`value at ${path} is a bigint; JCS requires an IEEE 754 double or a string`);
    case 'undefined':
      throw new Error(`value at ${path} is undefined; remove the field rather than hashing around it`);
    case 'object':
      break;
    default:
      throw new Error(`value at ${path} has unsupported type ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item, index) => serialize(item, `${path}[${index}]`)).join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(compareCodeUnits);
  const members = keys.map((key) => `${serializeString(key, path)}:${serialize(record[key], `${path}.${key}`)}`);
  return `{${members.join(',')}}`;
}

function serializeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) {
    throw new Error(`value at ${path} is ${String(value)}; JCS requires an I-JSON number`);
  }
  // ECMAScript Number::toString, which JSON.stringify already applies, including -0 -> "0".
  return JSON.stringify(value) as string;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function serializeString(value: string, path: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new Error(`value at ${path} contains a lone surrogate, which has no UTF-8 encoding`);
  }
  return JSON.stringify(value) as string;
}

function compareCodeUnits(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
