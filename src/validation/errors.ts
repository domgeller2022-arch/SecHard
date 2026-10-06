export type ValidationCode =
  | 'input.not_found'
  | 'input.not_a_file'
  | 'input.file_too_large'
  | 'input.empty_document'
  | 'input.multiple_documents'
  | 'input.duplicate_key'
  | 'input.custom_tag'
  | 'input.alias_or_anchor'
  | 'input.depth_exceeded'
  | 'input.collection_too_large'
  | 'input.string_too_long'
  | 'input.parse_error'
  | 'input.not_an_object'
  | 'schema.invalid'
  | 'path.outside_root'
  | 'path.symlink_escape'
  | 'semantic.duplicate_id'
  | 'semantic.unknown_reference'
  | 'semantic.version_conflict'
  | 'semantic.invalid_interval'
  | 'semantic.invalid_exception_scope'
  | 'semantic.unsupported_feature'
  | 'semantic.missing_field';

export interface ValidationIssue {
  readonly code: ValidationCode;
  readonly message: string;
  readonly file?: string;
  readonly path?: string;
}

export interface LoadedDocument<T = unknown> {
  readonly data: T;
  readonly file: string;
  readonly rawDigest: string;
  readonly byteLength: number;
}

export class ValidationError extends Error {
  readonly issues: readonly ValidationIssue[];

  constructor(issues: readonly ValidationIssue[]) {
    const first = issues[0];
    const where = first?.file ? ` (${first.file}${first.path ? ` at ${first.path}` : ''})` : '';
    super(`${issues.length} validation issue(s); first: ${first?.code ?? 'unknown'}${where}: ${first?.message ?? 'no message'}`);
    this.name = 'ValidationError';
    this.issues = issues;
  }
}

export function issue(
  code: ValidationCode,
  message: string,
  file?: string,
  path?: string,
): ValidationIssue {
  return { code, message, ...(file === undefined ? {} : { file }), ...(path === undefined ? {} : { path }) };
}

export function toJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
