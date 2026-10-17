import { existsSync, lstatSync, readFileSync, readlinkSync, readdirSync, statSync } from 'node:fs';
import { readBoundedSync } from '../evidence/bounded-io.js';
import { join, relative } from 'node:path';

/**
 * Stack and feature detection for audit mode.
 *
 * Audit mode must work on a folder with no manifest, so the first thing it does is look at what is
 * actually there. Two rules keep this honest:
 *
 * 1. **Every detection records its evidence** — the file and the pattern that produced it. A
 *    detected feature becomes `enabled` with that evidence in the ephemeral manifest; anything that
 *    cannot be detected from statics stays `unknown`, never silently `disabled` (the catalogue's
 *    own rule: omission means unknown).
 * 2. **Detection is read-only and bounded.** A bounded number of files, a bounded walk depth, and
 *    nothing is ever written to the target (the tree-digest test enforces that at the command
 *    level).
 */

export interface DetectionEvidence {
  readonly file: string;
  readonly detail: string;
}

export type StackKind =
  | 'nextjs'
  | 'react-spa'
  | 'sveltekit'
  | 'node-api'
  | 'python-web'
  | 'go'
  | 'expo'
  | 'react-native'
  | 'flutter'
  | 'electron'
  | 'unknown';

export interface Detection {
  readonly stack: { readonly kind: StackKind; readonly evidence: readonly DetectionEvidence[] };
  readonly languages: Readonly<Record<string, number>>;
  /** Profiles the audit composes for this app, in order, each with the evidence that selected it. */
  readonly profiles: readonly { readonly id: string; readonly evidence: readonly DetectionEvidence[] }[];
  /** Feature states for the ephemeral manifest: `enabled` with evidence, or `unknown`. */
  readonly features: Readonly<Record<string, { state: 'enabled' | 'unknown'; evidence: readonly DetectionEvidence[] }>>;
  /** Set when the stack has no catalogue support: the report must show a gap banner, not a clean pass. */
  readonly unsupported_stack?: { readonly reason: string; readonly generic_checks: readonly string[] };
  /** Detection-level gaps the report must state rather than imply away. */
  readonly gaps: readonly string[];
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.output', '.turbo', '.cache',
  'vendor', '__pycache__', '.venv', 'venv', 'target', 'Pods', '.dart_tool',
]);

const MAX_WALK_FILES = 4000;
const MAX_WALK_DEPTH = 8;

/** File extensions counted per language for the report's "what was examined" line. */
const EXTENSION_LANGUAGES: Readonly<Record<string, string>> = {
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.py': 'python', '.go': 'go', '.rb': 'ruby', '.java': 'java', '.rs': 'rust', '.php': 'php',
  '.cs': 'c-sharp', '.swift': 'swift', '.kt': 'kotlin', '.dart': 'dart',
  '.css': 'css', '.scss': 'css', '.html': 'html', '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml',
  '.sql': 'sql', '.sh': 'shell', '.tf': 'terraform',
};

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mts', '.mjs', '.py', '.go', '.rb', '.php', '.java', '.rs', '.kt', '.swift']);

export interface WalkedFile {
  readonly path: string;
  readonly size: number;
}

/** Bounded, read-only walk. Skips dependency and build directories entirely. Exported: the quality
 * scanners use the same bounded walk and the same skip rules. */
export function walk(root: string, onSkippedLink?: (path: string, target: string) => void): WalkedFile[] {
  const files: WalkedFile[] = [];
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (queue.length > 0 && files.length < MAX_WALK_FILES) {
    const { dir, depth } = queue.shift() as { dir: string; depth: number };
    let entries: readonly string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of [...entries].sort()) {
      if (files.length >= MAX_WALK_FILES) break;
      if (SKIP_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      // A-02 input confinement: lstat — symlinks are never followed (a link out of the tree must
      // not pull outside content into the scan) and non-regular files are never read. The
      // concurrent link-swap race is documented as out of scope in the walk's doc comment.
      let stats;
      try {
        stats = lstatSync(full);
      } catch {
        continue;
      }
      if (stats.isSymbolicLink()) {
        let linkTarget: string | undefined;
        try {
          linkTarget = readlinkSync(full);
        } catch {
          linkTarget = undefined;
        }
        onSkippedLink?.(full, linkTarget ?? '?');
        continue;
      }
      if (stats.isDirectory()) {
        if (depth < MAX_WALK_DEPTH) queue.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (stats.isFile()) files.push({ path: full, size: stats.size });
    }
  }
  return files;
}

const rel = (root: string, file: string): string => relative(root, file) || file;

interface PackageJson {
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
}

function readPackageJson(root: string): { parsed?: PackageJson; evidence?: DetectionEvidence } {
  const file = join(root, 'package.json');
  if (!existsSync(file)) return {};
  try {
    // R1-03: a symlinked package.json can point outside the scan root; it is skipped, not followed.
    if (lstatSync(file).isSymbolicLink()) {
      return { evidence: { file: 'package.json', detail: 'a symlinked package.json was not followed (R1-03)' } };
    }
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as PackageJson;
    return { parsed, evidence: { file: 'package.json', detail: 'read dependency and script declarations' } };
  } catch {
    return { evidence: { file: 'package.json', detail: 'present but not parseable as JSON' } };
  }
}

function hasDep(packageJson: PackageJson | undefined, name: string): boolean {
  return packageJson?.dependencies?.[name] !== undefined || packageJson?.devDependencies?.[name] !== undefined;
}

function readText(file: string, limitBytes = 512 * 1024): string | undefined {
  // P1.3: the bound is enforced at open time; unreadable files are counted, not silently lost.
  return readBoundedSync(file, limitBytes);
}

const IMPORT_MARKERS: readonly { readonly feature: string; readonly pattern: RegExp; readonly detail: string }[] = [
  { feature: 'runtime_ai', pattern: /from\s+['"]openai[/']/, detail: 'imports the OpenAI SDK' },
  { feature: 'runtime_ai', pattern: /from\s+['"]@anthropic-ai\/sdk/, detail: 'imports the Anthropic SDK' },
  { feature: 'runtime_ai', pattern: /from\s+['"](langchain|@langchain\/[\w-]+)/, detail: 'imports LangChain' },
  { feature: 'runtime_ai', pattern: /from\s+['"]ai['"]/, detail: 'imports the Vercel AI SDK' },
  // A-32/F-09: the SDK import counts only as an executable import statement at line start — a
  // matcher definition or explanatory string that mentions the import is not an integration.
  { feature: 'payments', pattern: /(?:^|\n)\s*(?:import\s+[^;\n]*from\s+['"]stripe['"]|const\s+\w+\s*=\s*require\(['"]stripe['"]\))/, detail: 'imports the Stripe SDK' },
  { feature: 'persistent_storage', pattern: /from\s+['"]@supabase\/(supabase-js|ssr)['"]/, detail: 'imports the Supabase client' },
  { feature: 'persistent_storage', pattern: /from\s+['"](prisma|mongoose|sequelize|knex|sqlite3|pg|mysql2)['"]/, detail: 'imports a database client' },
  { feature: 'uploads', pattern: /from\s+['"](multer|busboy|formidable|@fastify\/multipart)['"]|require\(['"](multer|busboy)['"]\)/, detail: 'imports a file-upload library' },
  { feature: 'outbound_requests', pattern: /from\s+['"](axios|got|undici|node-fetch)['"]/, detail: 'imports an outbound HTTP client' },
];

function detectStackFromEvidence(root: string, files: readonly WalkedFile[], packageJson: PackageJson | undefined): { kind: StackKind; evidence: DetectionEvidence[] } {
  const existsAt = (name: string): boolean => existsSync(join(root, name));
  const evidence: DetectionEvidence[] = [];
  const pkg = (detail: string): DetectionEvidence => ({ file: 'package.json', detail });

  if (hasDep(packageJson, 'next')) {
    return { kind: 'nextjs', evidence: [pkg('declares a dependency on next')] };
  }
  if (hasDep(packageJson, 'expo')) {
    return { kind: 'expo', evidence: [pkg('declares a dependency on expo')] };
  }
  if (hasDep(packageJson, 'react-native') || existsAt('metro.config.js')) {
    return {
      kind: 'react-native',
      evidence: [pkg('declares a dependency on react-native'), ...(existsAt('metro.config.js') ? [{ file: 'metro.config.js', detail: 'React Native bundler config' }] : [])],
    };
  }
  if (existsAt('pubspec.yaml')) {
    return { kind: 'flutter', evidence: [{ file: 'pubspec.yaml', detail: 'Flutter project manifest' }] };
  }
  if (hasDep(packageJson, 'electron')) {
    return { kind: 'electron', evidence: [pkg('declares a dependency on electron')] };
  }
  if (existsAt('svelte.config.js') || existsAt('svelte.config.ts')) {
    return { kind: 'sveltekit', evidence: [{ file: 'svelte.config.js', detail: 'SvelteKit project config' }] };
  }
  // A-32: dev-only Vite/Vitest is tooling, not a browser SPA — a bundler devDependency alone
  // must not classify the project as a browser stack. An actual SPA declares a production
  // browser-framework dependency, or ships an HTML entry point for a vanilla Vite app.
  const browserFramework = packageJson === undefined
    ? undefined
    : ['react', 'vue', 'svelte', 'preact', 'solid-js'].find((name) => packageJson.dependencies?.[name] !== undefined);
  if (browserFramework !== undefined) {
    return { kind: 'react-spa', evidence: [pkg(`declares a production dependency on ${browserFramework}`)] };
  }
  if (existsSync(join(root, 'index.html')) || existsSync(join(root, 'src', 'index.html'))) {
    if (hasDep(packageJson, 'vite') || existsAt('vite.config.ts') || existsAt('vite.config.js')) {
      return { kind: 'react-spa', evidence: [{ file: 'index.html', detail: 'a Vite app with a browser entry point' }] };
    }
  }
  if (hasDep(packageJson, 'express') || hasDep(packageJson, 'fastify') || hasDep(packageJson, '@hono/node-server') || hasDep(packageJson, 'koa')) {
    const name = ['express', 'fastify', '@hono/node-server', 'koa'].find((candidate) => hasDep(packageJson, candidate)) as string;
    return { kind: 'node-api', evidence: [pkg(`declares a dependency on ${name}`)] };
  }
  // Python web frameworks: the dependency list is the evidence; imports alone are too weak.
  const pythonFiles = files.filter((file) => file.path.endsWith('.py'));
  if (existsSync(join(root, 'requirements.txt')) || existsSync(join(root, 'pyproject.toml'))) {
    for (const file of ['requirements.txt', 'pyproject.toml'] as const) {
      const text = readText(join(root, file));
      if (text === undefined) continue;
      const framework = /(fastapi|flask|django)/i.exec(text);
      if (framework !== null) {
        return { kind: 'python-web', evidence: [{ file, detail: `declares a dependency on ${framework[1]?.toLowerCase() ?? 'a python web framework'}` }] };
      }
    }
    if (pythonFiles.length > 0) {
      return {
        kind: 'python-web',
        evidence: [{ file: 'requirements.txt', detail: 'python project detected with no named web framework; treated as python-web for audit purposes' }],
      };
    }
  }
  if (existsSync(join(root, 'go.mod'))) {
    return { kind: 'go', evidence: [{ file: 'go.mod', detail: 'Go module manifest' }] };
  }
  if (pythonFiles.length > 0) {
    return { kind: 'python-web', evidence: [{ file: rel(root, pythonFiles[0]?.path ?? ''), detail: `python sources present (${pythonFiles.length} file(s))` }] };
  }
  return { kind: 'unknown', evidence };
}

/** Stacks the catalogue has stack-profile support for; everything else gets a gap banner. */
const SUPPORTED_STACKS: ReadonlySet<StackKind> = new Set(['nextjs', 'react-spa', 'sveltekit', 'node-api', 'python-web']);

export function detectStackAndFeatures(root: string): Detection {
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new Error(`audit target is not a directory: ${root}`);
  }

  // A-02: symlinks are never followed; each skip is recorded so the scope statement stays honest.
  const skippedLinks: string[] = [];
  const files = walk(root, (path, target) => skippedLinks.push(`${rel(root, path)} -> ${target}`));
  const { parsed: packageJson } = readPackageJson(root);
  const stack = detectStackFromEvidence(root, files, packageJson);

  const languages: Record<string, number> = {};
  for (const file of files) {
    const extension = /\.(?<ext>[a-z0-9]+)$/u.exec(file.path)?.groups?.['ext'];
    const language = extension === undefined ? undefined : EXTENSION_LANGUAGES[`.${extension}`];
    if (language === undefined) continue;
    languages[language] = (languages[language] ?? 0) + 1;
  }

  // Features: a feature is `enabled` only with concrete evidence; anything undetected stays
  // `unknown`. Unknown is the honest default — audit mode cannot prove a feature absent from a
  // folder scan.
  const features: Record<string, { state: 'enabled' | 'unknown'; evidence: readonly DetectionEvidence[] }> = {};
  const enable = (feature: string, evidence: DetectionEvidence): void => {
    const existing = features[feature];
    features[feature] = {
      state: 'enabled',
      evidence: existing === undefined ? [evidence] : [...existing.evidence, evidence],
    };
  };

  const hasInterfaceEvidence =
    stack.kind === 'nextjs' || stack.kind === 'react-spa' || stack.kind === 'sveltekit' ||
    stack.kind === 'node-api' || stack.kind === 'python-web' || stack.kind === 'electron';
  if (hasInterfaceEvidence) {
    enable('interfaces', { file: stack.evidence[0]?.file ?? 'package.json', detail: 'a web framework is declared' });
  }

  if (existsSync(join(root, 'supabase')) || packageJson !== undefined && (hasDep(packageJson, '@supabase/supabase-js') || hasDep(packageJson, '@supabase/ssr'))) {
    enable('persistent_storage', { file: existsSync(join(root, 'supabase')) ? 'supabase/' : 'package.json', detail: 'Supabase project detected' });
  }
  if (existsSync(join(root, 'firebase.json')) || packageJson !== undefined && hasDep(packageJson, 'firebase')) {
    enable('persistent_storage', { file: existsSync(join(root, 'firebase.json')) ? 'firebase.json' : 'package.json', detail: 'Firebase project detected' });
  }
  if (packageJson !== undefined && (hasDep(packageJson, 'next-auth') || hasDep(packageJson, '@auth0/nextjs-auth0') || hasDep(packageJson, 'passport') || hasDep(packageJson, 'jsonwebtoken'))) {
    enable('accounts', { file: 'package.json', detail: 'an authentication library is declared' });
  }

  // F-09: a payment integration is declared by dependency, not only by SDK import. Apps that
  // only use @stripe/stripe-js elements, Paddle, or Lemon Squeezy never import the server SDK,
  // and the money-path obligations must still apply.
  if (packageJson !== undefined && (hasDep(packageJson, 'stripe') || hasDep(packageJson, '@stripe/stripe-js') || hasDep(packageJson, 'paddle') || hasDep(packageJson, 'lemonsqueezy'))) {
    const declared = ['stripe', '@stripe/stripe-js', 'paddle', 'lemonsqueezy'].filter((candidate) => hasDep(packageJson, candidate));
    enable('payments', { file: 'package.json', detail: `declares a payments dependency (${declared.join(', ')})` });
  }

  const workflowsDir = join(root, '.github', 'workflows');
  const hasWorkflows = existsSync(workflowsDir) && readdirSync(workflowsDir).some((name) => name.endsWith('.yml') || name.endsWith('.yaml'));
  // Source import scan, bounded. Only source files, only the first bytes of each.
  // F-09: the detection-exclusion list — tests, fixtures, examples, and corpora are not the
  // application's own stack. Without this, a repository that vendors fixture applications
  // (SecHard itself) is detected as the union of its fixtures.
  const DETECTION_EXCLUDED_PREFIXES = ['tests/', 'test/', 'examples/', 'fixtures/', '__tests__/', 'corpus/'];
  const sourceFiles = files.filter((file) => {
    const extension = /\.[a-z0-9]+$/u.exec(file.path)?.[0] ?? '';
    if (!SOURCE_EXTENSIONS.has(extension)) return false;
    const relativePath = rel(root, file.path);
    return !DETECTION_EXCLUDED_PREFIXES.some((prefix) => relativePath.startsWith(prefix));
  });
  const gaps: string[] = [];
  const scanLimit = 800;
  const scannedImports = sourceFiles.slice(0, scanLimit);
  let unreadable = 0;
  for (const file of scannedImports) {
    const text = readText(file.path, 256 * 1024);
    if (text === undefined) { unreadable += 1; continue; }
    for (const marker of IMPORT_MARKERS) {
      if (marker.pattern.test(text)) {
        enable(marker.feature, { file: rel(root, file.path), detail: marker.detail });
      }
    }
    // F-09: payment webhooks are detectable from the event types a route handles, not only from
    // the SDK import — a checkout.session.completed handler is a payments integration even when
    // the SDK is only used server-side behind an adapter. A-32: the event names count only as
    // quoted string literals in source — SecHard's own matcher definitions and explanatory
    // strings are not an integration.
    if (/['"](?:checkout\.session\.completed|payment_intent\.[a-z_]+|invoice\.paid)['"]/.test(text)) {
      enable('payments', { file: rel(root, file.path), detail: 'handles payment lifecycle event types' });
      enable('webhooks', { file: rel(root, file.path), detail: 'handles payment lifecycle event types' });
    }
    if (/\bwebhook\b/i.test(text) && file.path.toLowerCase().includes('webhook')) {
      enable('webhooks', { file: rel(root, file.path), detail: 'a webhook handler source file' });
    }
    // A-32: the loose "mentions stripe AND webhook" text check is gone — it matched SecHard's own
    // adapter, matcher definition, and explanation prose. A real handler is detected by the
    // quoted event literals above, the line-start SDK import, or a webhook path.
  }
  if (sourceFiles.length > scanLimit) {
    gaps.push(`the import scan covered ${scanLimit} of ${sourceFiles.length} source files (bounded walk); feature detection beyond that is unknown`);
  }
  // R1-03: a skipped link is an omission on every project size, not only large ones.
  if (unreadable > 0) {
    gaps.push(`source files that could not be read: ${String(unreadable)}`);
  }
    if (skippedLinks.length > 0) {
    gaps.push(`symlinks not followed: ${skippedLinks.slice(0, 5).join(', ')}${skippedLinks.length > 5 ? ` and ${String(skippedLinks.length - 5)} more` : ''}`);
  }

  // Undetected features stay unknown — never `disabled`, which the catalogue treats as a claim.
  const knownFeatures = [
    'accounts', 'private_resources', 'roles', 'tenancy', 'recovery', 'payments', 'webhooks',
    'uploads', 'outbound_requests', 'personal_data', 'runtime_ai', 'hosting', 'interfaces',
    'environments', 'persistent_storage',
  ];
  for (const feature of knownFeatures) {
    if (features[feature] === undefined) features[feature] = { state: 'unknown', evidence: [] };
  }
  features['environments'] = { state: 'enabled', evidence: [{ file: '.', detail: 'audit mode always evaluates against a local environment unless a --url target is supplied' }] };

  // Profile composition from detection. `core` always applies (the gate-mode rule mirrored here),
  // and `quality` always composes because the owner's 2026-10-08 goal makes quality a required
  // capability reported in its own section — never changing a security verdict, and the reverse.
  const profiles: { id: string; evidence: readonly DetectionEvidence[] }[] = [];
  const coreEvidence: DetectionEvidence = { file: '.', detail: 'the core profile applies to every audited application' };
  profiles.push({ id: 'core', evidence: [coreEvidence] });
  profiles.push({ id: 'quality', evidence: [{ file: '.', detail: 'quality is a required capability of every audit (owner goal 2026-10-08); its findings are reported in their own section' }] });

  if (SUPPORTED_STACKS.has(stack.kind)) {
    const stackProfile: readonly { id: string; kinds: readonly StackKind[] }[] = [
      { id: 'nextjs', kinds: ['nextjs'] },
      { id: 'react-spa', kinds: ['react-spa'] },
      { id: 'node-api', kinds: ['node-api', 'sveltekit'] },
      { id: 'python-web', kinds: ['python-web'] },
    ];
    const match = stackProfile.find((entry) => entry.kinds.includes(stack.kind));
    if (match !== undefined) {
      profiles.push({ id: match.id, evidence: stack.evidence.length > 0 ? stack.evidence : [{ file: '.', detail: `stack kind ${stack.kind}` }] });
    }
  }
  if (features['persistent_storage']?.state === 'enabled' && features['persistent_storage'].evidence.some((item) => item.detail.includes('Supabase'))) {
    profiles.push({ id: 'supabase', evidence: features['persistent_storage'].evidence.filter((item) => item.detail.includes('Supabase')) });
  }
  if (features['payments']?.state === 'enabled') {
    profiles.push({ id: 'payments', evidence: features['payments'].evidence });
  }

  let unsupportedStack: Detection['unsupported_stack'] = undefined;
  if (!SUPPORTED_STACKS.has(stack.kind)) {
    unsupportedStack = {
      reason: `the detected stack (${stack.kind}) has no stack profile in this build; stack-specific controls were not evaluated`,
      generic_checks: ['secret scan (repository and history)', 'dependency advisory scan', 'workflow analysis', 'supply-chain records'],
    };
    gaps.push(`detected stack '${stack.kind}' is not supported by any stack profile; only the generic checks ran`);
  }
  if (stack.kind === 'python-web') {
    // A-17: the reviewed Python rule families are planned (detection-depth pack); the expansion
    // families stay recorded gaps instead of a blanket "Python unsupported" claim.
    gaps.push('static analysis covers the reviewed Python rule families only (SQL injection, SSRF, path traversal, cookie attributes); framework-specific secret handling, template injection, and the Bandit/Ruff expansion remain recorded gaps');
  }
  if (features['persistent_storage']?.state === 'enabled' && features['persistent_storage'].evidence.some((item) => item.detail.includes('Firebase'))) {
    gaps.push('Firebase detected: no Firebase-specific verification recipes exist in this build; storage and rules controls are evaluated generically only');
  }
  if (!hasWorkflows) {
    gaps.push('no GitHub workflows detected; workflow analysis will report nothing to scan');
  }
  if (sourceFiles.length > scanLimit) {
    gaps.push(`the import scan covered ${scanLimit} of ${sourceFiles.length} source files (bounded walk); feature detection beyond that is unknown`);
  }

  return {
    stack: { kind: stack.kind, evidence: stack.evidence.length > 0 ? stack.evidence : [{ file: '.', detail: 'no stack marker detected' }] },
    languages,
    profiles,
    features,
    ...(unsupportedStack === undefined ? {} : { unsupported_stack: unsupportedStack }),
    gaps,
  };
}
