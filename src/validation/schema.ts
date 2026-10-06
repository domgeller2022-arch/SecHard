import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
// ajv-formats is CommonJS and its declaration file re-exports the plugin as a namespace under
// NodeNext resolution, so the callable lives on .default.
import formatsPlugin from 'ajv-formats';
import { issue, type ValidationIssue } from './errors.js';

export type SchemaName =
  | 'app'
  | 'assessment'
  | 'check-result'
  | 'exception'
  | 'execution-plan'
  | 'manual-evidence'
  | 'profile'
  | 'release-evidence'
  | 'source'
  | 'control'
  | 'control-catalogue';

const SCHEMA_FILES: Record<SchemaName, string> = {
  app: 'app.schema.json',
  assessment: 'assessment.schema.json',
  'check-result': 'check-result.schema.json',
  exception: 'exception.schema.json',
  'execution-plan': 'execution-plan.schema.json',
  'manual-evidence': 'manual-evidence.schema.json',
  profile: 'profile.schema.json',
  'release-evidence': 'release-evidence.schema.json',
  source: 'source.schema.json',
  control: 'control.schema.json',
  'control-catalogue': 'control-catalogue.schema.json',
};

const cache = new Map<SchemaName, ValidateFunction>();

function ajv(): InstanceType<typeof Ajv2020> {
  const instance = new Ajv2020({
    strict: true,
    strictTypes: true,
    strictRequired: false,
    allowUnionTypes: true,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    allErrors: true,
    validateFormats: true,
  });
  formatsPlugin.default(instance, ['date-time', 'uri', 'uuid']);
  return instance;
}

function schemaPath(name: SchemaName): string {
  const dir = name === 'control' ? join(packageRoot(), 'controls') : join(packageRoot(), 'schemas');
  return join(dir, SCHEMA_FILES[name]);
}

function validateFor(name: SchemaName): ValidateFunction {
  const cached = cache.get(name);
  if (cached) return cached;

  const instance = ajv();

  // The catalogue schema references the control schema by absolute $id, so the referenced schema must
  // be registered before compiling it.
  if (name === 'control-catalogue') {
    const controlSchema: unknown = JSON.parse(readFileSync(schemaPath('control'), 'utf8'));
    instance.addSchema(controlSchema as object);
  }

  const schema: unknown = JSON.parse(readFileSync(schemaPath(name), 'utf8'));
  const compiled = instance.compile(schema as object);
  cache.set(name, compiled);
  return compiled;
}

export function packageRoot(): string {
  const fromDist = join(import.meta.dirname, '..');
  const fromSrc = join(import.meta.dirname, '..', '..');
  return existsSync(join(fromDist, 'schemas')) ? fromDist : fromSrc;
}

export interface SchemaValidationResult {
  readonly valid: boolean;
  readonly issues: readonly ValidationIssue[];
}

export function validateAgainstSchema(
  name: SchemaName,
  data: unknown,
  file?: string,
): SchemaValidationResult {
  const validate = validateFor(name);
  const valid = validate(data);
  if (valid) return { valid: true, issues: [] };
  return { valid: false, issues: (validate.errors ?? []).map((error) => toIssue(error, file)) };
}

function toIssue(error: ErrorObject, file?: string): ValidationIssue {
  const path = `${error.instancePath}${error.keyword === 'required' ? '' : ''}` || '$';
  const params = error.params as Record<string, unknown>;
  let message = error.message ?? 'is invalid';
  if (error.keyword === 'required') {
    message = `missing required property '${String(params.missingProperty)}'`;
  } else if (error.keyword === 'additionalProperties') {
    message = `unknown property '${String(params.additionalProperty)}' is not accepted`;
  } else if (error.keyword === 'format') {
    message = `must match format '${String(params.format)}'`;
  } else if (error.keyword === 'enum') {
    message = `must be one of: ${JSON.stringify(params.allowedValues)}`;
  }
  return issue('schema.invalid', message, file, path);
}
