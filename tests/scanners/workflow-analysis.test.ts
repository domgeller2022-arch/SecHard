import { describe, expect, it } from 'vitest';
import { packageRoot } from '../../src/validation/schema.js';
import { runTool } from '../../src/execution/registry.js';

/**
 * zizmor against this repository's own workflows, run through the identity registry so a missing or
 * mismatched binary fails loudly rather than being silently replaced by a PATH tool.
 *
 * This suite needs `pnpm run fetch:tools`; it lives in `test:scanners`, which provisions them.
 */

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

