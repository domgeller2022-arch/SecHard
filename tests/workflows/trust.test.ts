import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';
import { runTool } from '../../src/execution/registry.js';

/**
 * Trust tests for the CI configuration.
 *
 * The properties below are the ones that decide whether a pull request can weaken the checks that
 * assess it. They are asserted here rather than trusted to review, because a workflow edit that
 * removes a pin or adds a permission looks like an ordinary change.
 *
 * What these tests cannot do: they cannot observe the platform's settings. Required checks, review
 * rules, and bypass permissions are configured in GitHub, not in YAML, and asserting on YAML does
 * not establish that any of them is enforced. That limit is stated in `docs/ci-trust.md`.
 */

const WORKFLOW_DIR = join(packageRoot(), '.github', 'workflows');
const workflowFiles = readdirSync(WORKFLOW_DIR).filter((name) => name.endsWith('.yaml') || name.endsWith('.yml'));

interface Workflow {
  readonly name?: string;
  readonly on?: unknown;
  readonly permissions?: unknown;
  readonly jobs?: Record<string, Job>;
}

interface Job {
  readonly if?: string;
  readonly needs?: string | readonly string[];
  readonly permissions?: unknown;
  readonly uses?: string;
  readonly steps?: readonly Step[];
}

interface Step {
  readonly uses?: string;
  readonly run?: string;
  readonly with?: Record<string, unknown>;
  readonly env?: Record<string, unknown>;
}

function load(name: string): Workflow {
  return parse(readFileSync(join(WORKFLOW_DIR, name), 'utf8')) as Workflow;
}

function keysOf(value: unknown): string[] {
  if (value === null || typeof value !== 'object') return typeof value === 'string' ? [value] : [];
  return Object.keys(value as Record<string, unknown>);
}

describe('every workflow is pinned and minimally privileged', () => {
  it('has workflows to check', () => {
    expect(workflowFiles.length).toBeGreaterThan(0);
  });

  for (const file of workflowFiles) {
    const workflow = load(file);

    it(`${file}: pins every action to a full commit SHA`, () => {
      const uses = Object.values(workflow.jobs ?? {}).flatMap((job) => [
        ...(job.uses === undefined ? [] : [job.uses]),
        ...(job.steps ?? []).flatMap((step) => (step.uses === undefined ? [] : [step.uses])),
      ]);
      expect(uses.length).toBeGreaterThan(0);
      for (const reference of uses) {
        // A local action reference would be allowed; a tag or branch is not.
        if (reference.startsWith('./')) continue;
        const afterAt = reference.split('@')[1];
        expect(afterAt, `${file}: '${reference}' must be pinned to a commit SHA`).toMatch(/^[0-9a-f]{40}$/);
      }
    });

    it(`${file}: grants no write permission`, () => {
      const permissions = [
        ...keysOf(workflow.permissions).length === 0 ? [] : [workflow.permissions],
        ...Object.values(workflow.jobs ?? {}).map((job) => job.permissions),
      ].filter((value) => value !== undefined);

      for (const entry of permissions) {
        const rendered = JSON.stringify(entry);
        expect(rendered, `${file}: '${rendered}' grants write access`).not.toMatch(/write/);
      }
    });

    it(`${file}: never interpolates an expression into a shell script`, () => {
      // A `${{ }}` written into `run:` becomes shell text. Values belong in `env:`.
      for (const job of Object.values(workflow.jobs ?? {})) {
        for (const step of job.steps ?? []) {
          if (step.run === undefined) continue;
          const offending = step.run.match(/\$\{\{[^}]+\}\}/g);
          expect(offending, `${file}: run step interpolates ${offending?.join(', ') ?? ''} directly`).toBeNull();
        }
      }
    });

    it(`${file}: does not use pull_request_target`, () => {
      // A privileged trigger plus a checkout of untrusted code is the classic CI compromise.
      expect(JSON.stringify(workflow.on ?? {})).not.toContain('pull_request_target');
    });

    it(`${file}: disables credential persistence on every checkout`, () => {
      for (const job of Object.values(workflow.jobs ?? {})) {
        for (const step of job.steps ?? []) {
          if (step.uses === undefined || !step.uses.startsWith('actions/checkout@')) continue;
          expect(step.with?.['persist-credentials'], `${file}: checkout must set persist-credentials: false`).toBe(false);
        }
      }
    });

    it(`${file}: has a stable final gate job that ignores dependency failure`, () => {
      const gate = workflow.jobs?.['hardening-gate'];
      expect(gate, `${file}: no hardening-gate job`).toBeDefined();
      // `if: always()` is what stops a skipped dependency from looking like success.
      expect(String(gate?.if ?? '').replace(/\s+/g, '')).toContain('always()');
      const needs = typeof gate?.needs === 'string' ? [gate.needs] : [...(gate?.needs ?? [])];
      const others = Object.keys(workflow.jobs ?? {}).filter((name) => name !== 'hardening-gate');
      for (const dependency of others) {
        expect(needs, `${file}: gate must depend on ${dependency}`).toContain(dependency);
      }
    });
  }

  it('the callable workflows declare workflow_call and a pinned-input contract', () => {
    for (const file of ['hardening-pr.yaml', 'hardening-release.yaml']) {
      const workflow = load(file);
      expect(Object.keys(workflow.on as Record<string, unknown>), file).toContain('workflow_call');
      const call = (workflow.on as Record<string, { inputs?: Record<string, { required?: boolean }> }>).workflow_call;
      expect(call?.inputs?.['hardening_ref']?.required, `${file}: hardening_ref must be required`).toBe(true);
    }
  });

  it('the consumer template pins the called workflow and the policy ref to a commit', () => {
    const template = readFileSync(join(packageRoot(), 'templates', 'consumer-workflow.template.yaml'), 'utf8');
    const uses = template.match(/uses:\s*\S+/g) ?? [];
    expect(uses.length).toBeGreaterThan(0);
    for (const reference of uses) {
      // The placeholder is where the pinned commit goes; a tag or branch is not acceptable here.
      expect(reference).toMatch(/@REPLACE_WITH_REVIEWED_COMMIT_SHA$/);
      expect(reference).not.toMatch(/@(main|master|v\d)/);
    }
    // The caller passes the same ref it pins, so policy and tooling cannot diverge.
    expect((template.match(/hardening_ref:\s*REPLACE_WITH_REVIEWED_COMMIT_SHA/g) ?? []).length).toBeGreaterThanOrEqual(2);
  });
});

describe('the workflows pass the workflow analyser', () => {
  it('zizmor reports nothing on the pinned workflows', async () => {
    const result = await runTool('zizmor', ['--format', 'json', '--no-progress', '.github/workflows'], {
      cwd: packageRoot(),
      timeoutMs: 120_000,
    });
    expect(result.ran, 'zizmor is required for this suite; run `pnpm run fetch:tools`').toBe(true);
    const findings = JSON.parse(result.outcome?.stdout ?? '[]') as readonly { ident: string; determinations?: { severity?: string } }[];
    expect(findings.map((finding) => `${finding.ident}:${finding.determinations?.severity ?? '?'}`)).toEqual([]);
  });
});

describe('CODEOWNERS names the recorded owner', () => {
  const codeownersPath = join(packageRoot(), '.github', 'CODEOWNERS');

  it('exists and contains no placeholder', () => {
    expect(existsSync(codeownersPath)).toBe(true);
    const contents = readFileSync(codeownersPath, 'utf8');
    expect(contents).not.toMatch(/REPLACE_WITH/);
    // Every handle must look like a GitHub username or team reference.
    for (const handle of contents.match(/@\S+/g) ?? []) {
      expect(handle, handle).toMatch(/^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/);
    }
  });

  it('uses exactly the identity recorded in the owner decisions', () => {
    // A handle that does not exist, or that lacks write access, is skipped silently by GitHub —
    // the file would look like protection while matching nobody. The owner decisions file is the
    // record of which identity was actually chosen.
    const decisionsPath = join(packageRoot(), '..', '01-owner-decisions.md');
    if (!existsSync(decisionsPath)) {
      // Consumed outside the build pack; there is no record to compare against in that layout.
      return;
    }
    const decisions = readFileSync(decisionsPath, 'utf8');
    const match = decisions.match(/^github_codeowners:\s*(.+)$/m);
    const recorded = (match?.[1] ?? '').trim();
    expect(recorded.length, 'github_codeowners is unfilled but CODEOWNERS exists').toBeGreaterThan(0);
    expect(recorded).not.toBe('TODO');

    const contents = readFileSync(codeownersPath, 'utf8');
    const handles = new Set((contents.match(/@\S+/g) ?? []).map((handle) => handle.slice(1)));
    for (const identity of recorded.split(',').map((entry) => entry.trim())) {
      expect(handles, `CODEOWNERS must name ${identity}`).toContain(identity);
    }
    expect(handles.size).toBe(recorded.split(',').filter((entry) => entry.trim().length > 0).length);
  });

  it('covers every sensitive area and protects itself', () => {
    const contents = readFileSync(codeownersPath, 'utf8');
    for (const path of ['/controls/', '/policy/', '/src/domain/', '/tests/', '/agent-rules/', '/.github/', '/ci/configs/']) {
      expect(contents, path).toContain(path);
    }
    // The workflow trust tests and this file itself are inside /.github/, which is covered above.
    expect(contents).toMatch(/^\*\s+@/m);
  });

  it('keeps a template for consumers, with no invented identity', () => {
    const template = readFileSync(join(packageRoot(), 'templates', 'CODEOWNERS.template'), 'utf8');
    const handles = template.match(/@\S+/g) ?? [];
    expect(handles.length).toBeGreaterThan(0);
    for (const handle of handles) {
      expect(handle, 'the template must not contain an invented handle').toBe('@REPLACE_WITH_REVIEWER');
    }
  });
});
