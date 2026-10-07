import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { generateAgentRules, loadRulesSource, rulesDigest, GENERATED_MARKER } from '../../src/agent/generate.js';
import { packageRoot } from '../../src/validation/schema.js';

const scratch = mkdtempSync(join(tmpdir(), 'hardening-agent-rules-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const source = loadRulesSource();

/**
 * Constructions that would permit a shortcut. These are checked against the generated text so a
 * future edit to the source cannot quietly introduce a permission the repository forbids. A
 * prohibition phrased as "never claim that a simulated check passed" is fine; "you may simulate a
 * check" is not, and these patterns only match the latter.
 */
const PERMISSIVE_PATTERNS: readonly { readonly name: string; readonly pattern: RegExp }[] = [
  { name: 'permission to skip or ignore', pattern: /\byou may (?:skip|ignore|disable|omit)\b/i },
  { name: 'permission to simulate', pattern: /\b(?:it is (?:fine|ok|okay) to|feel free to) (?:simulate|mock|skip)\b/i },
  { name: 'no need to run', pattern: /\bno need to (?:run|execute|verify)\b/i },
  { name: 'trusting tool output', pattern: /\btrust (?:the )?(?:tool|scanner|output|agent)\b/i },
  { name: 'optionality', pattern: /\boptional\b/i },
];

describe('the rules source', () => {
  it('covers every area the plan requires', () => {
    const categories = new Set(source.rules.map((rule) => rule.category));
    for (const required of [
      'authorized_work',
      'untrusted_context',
      'dependencies',
      'secret_boundaries',
      'actual_execution',
      'preserved_tests',
      'unresolved_findings',
    ]) {
      expect(categories.has(required), required).toBe(true);
    }
  });

  it('is a draft until the owner reviews it', () => {
    expect(source.review_status).toBe('draft');
  });

  it('states only must and must_not, never a soft preference', () => {
    // A rule that is optional in an instruction file is an option the agent will take.
    for (const rule of source.rules) {
      expect(['must', 'must_not']).toContain(rule.strength);
    }
    const raw = readFileSync(join(packageRoot(), 'agent-rules', 'core', 'rules.yaml'), 'utf8');
    expect(raw).not.toMatch(/strength:\s*should/);
  });

  it('has a unique id, a rationale, and a statement for every rule', () => {
    const ids = new Set<string>();
    for (const rule of source.rules) {
      expect(ids.has(rule.id), rule.id).toBe(false);
      ids.add(rule.id);
      expect(rule.statement.length).toBeGreaterThan(30);
      expect(rule.rationale.length).toBeGreaterThan(20);
    }
  });
});

describe('generated instruction files', () => {
  it('are deterministic', () => {
    const first = generateAgentRules({ source, outDir: join(scratch, 'a') });
    const second = generateAgentRules({ source, outDir: join(scratch, 'b') });
    for (let index = 0; index < first.length; index += 1) {
      expect(first[index]?.contents).toBe(second[index]?.contents);
    }
    // No timestamp, so unchanged input means unchanged bytes.
    expect(first[0]?.contents).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('includes every rule in both formats', () => {
    const results = generateAgentRules({ source, outDir: join(scratch, 'c') });
    expect(results).toHaveLength(2);
    for (const result of results) {
      for (const rule of source.rules) {
        expect(result.contents, `${result.path} missing ${rule.id}`).toContain(rule.statement.split(' ').slice(0, 6).join(' '));
      }
    }
  });

  it('records the source digest and generator provenance', () => {
    const digest = rulesDigest(source);
    const results = generateAgentRules({ source, outDir: join(scratch, 'd') });
    for (const result of results) {
      expect(result.contents).toContain(GENERATED_MARKER);
      expect(result.contents).toContain(digest);
      expect(result.sourceDigest).toBe(digest);
    }
  });

  it('says plainly that a prompt is not a permission boundary', () => {
    const results = generateAgentRules({ source, outDir: join(scratch, 'e') });
    for (const result of results) {
      expect(result.contents).toMatch(/a prompt cannot restrict what a tool is permitted to do/);
    }
  });

  it('contains no permissive construction', () => {
    const results = generateAgentRules({ source, outDir: join(scratch, 'f') });
    for (const result of results) {
      for (const { name, pattern } of PERMISSIVE_PATTERNS) {
        const match = result.contents.match(pattern);
        expect(match?.[0], `${result.path} contains ${name}: '${match?.[0] ?? ''}'`).toBeUndefined();
      }
    }
  });

  it('instructs the agent to stop on a conflict rather than resolve it', () => {
    const results = generateAgentRules({ source, outDir: join(scratch, 'g') });
    for (const result of results) {
      expect(result.contents).toMatch(/Say so and stop/);
    }
  });

  it('refuses to overwrite a hand-written file and leaves it untouched', () => {
    const dir = join(scratch, 'hand');
    mkdirSync(dir, { recursive: true });
    const handWritten = '# Our own guidance\n\nThis was written by a human.\n';
    writeFileSync(join(dir, 'AGENTS.md'), handWritten, 'utf8');

    const results = generateAgentRules({ source, outDir: dir });
    const agents = results.find((result) => result.path.endsWith('AGENTS.md'));
    expect(agents?.written).toBe(false);
    expect(agents?.refused).toBe('hand_edited_file');
    // The human's file is exactly as it was.
    expect(readFileSync(join(dir, 'AGENTS.md'), 'utf8')).toBe(handWritten);
    // A file that does not exist yet is generated normally.
    expect(existsSync(join(dir, 'CLAUDE.md'))).toBe(true);
  });

  it('regenerates a file it previously generated', () => {
    const dir = join(scratch, 'regen');
    generateAgentRules({ source, outDir: dir });
    const second = generateAgentRules({ source, outDir: dir });
    expect(second.every((result) => result.written)).toBe(true);
  });
});

describe('operator requirements are documented, not assumed', () => {
  it('names the four restriction areas and states that prompts are not a boundary', () => {
    const doc = readFileSync(join(packageRoot(), 'agent-rules', 'operator-requirements.md'), 'utf8');
    for (const area of ['Filesystem', 'Credentials', 'Network', 'Runtime permissions']) {
      expect(doc, area).toContain(area);
    }
    expect(doc).toMatch(/Prompt text cannot satisfy AGT-01/);
    // Each area tells the operator how to check it, rather than only what to configure.
    expect((doc.match(/\*\*Check:\*\*/g) ?? []).length).toBeGreaterThanOrEqual(4);
  });
});
