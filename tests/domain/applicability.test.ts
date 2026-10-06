import { describe, expect, it } from 'vitest';
import { evaluateApplicability, coverageGap, type ManifestLike } from '../../src/domain/applicability.js';

function manifest(overrides: Partial<ManifestLike['features']>, environments = ['local']): ManifestLike {
  return { features: overrides, environments: environments.map((kind) => ({ kind })) };
}

const enabled = { state: 'enabled' } as const;
const disabled = { state: 'disabled' } as const;

describe('applicability', () => {
  it('always applies an unconditional control', () => {
    expect(evaluateApplicability({ rule: 'always' }, manifest({}), 'production')).toBe('applicable');
  });

  it('applies when the feature is enabled', () => {
    expect(
      evaluateApplicability({ rule: 'when_feature_enabled', features: ['payments'] }, manifest({ payments: enabled }), 'local'),
    ).toBe('applicable');
  });

  it('does not apply when every named feature is explicitly disabled', () => {
    expect(
      evaluateApplicability({ rule: 'when_feature_enabled', features: ['payments'] }, manifest({ payments: disabled }), 'local'),
    ).toBe('not_applicable');
  });

  // This is the significant case: a missing declaration must not silently drop a requirement.
  it('is unknown, not not_applicable, when the feature is omitted from the manifest', () => {
    expect(
      evaluateApplicability({ rule: 'when_feature_enabled', features: ['tenancy'] }, manifest({ accounts: enabled }), 'local'),
    ).toBe('unknown');
  });

  it('is unknown when one of several named features is undeclared', () => {
    expect(
      evaluateApplicability(
        { rule: 'when_any_feature_enabled', features: ['roles', 'tenancy'] },
        manifest({ roles: enabled }),
        'local',
      ),
    ).toBe('applicable');

    expect(
      evaluateApplicability(
        { rule: 'when_any_feature_enabled', features: ['roles', 'tenancy'] },
        manifest({ roles: disabled }),
        'local',
      ),
    ).toBe('unknown');
  });

  it('requires every feature for when_all', () => {
    const rule = { rule: 'when_all', features: ['roles', 'tenancy'] } as const;
    expect(evaluateApplicability(rule, manifest({ roles: enabled, tenancy: enabled }), 'local')).toBe('applicable');
    expect(evaluateApplicability(rule, manifest({ roles: enabled, tenancy: disabled }), 'local')).toBe('not_applicable');
    expect(evaluateApplicability(rule, manifest({ roles: enabled }), 'local')).toBe('unknown');
  });

  it('restricts an environment rule and distinguishes unknown environments', () => {
    const rule = { rule: 'when_environment', environments: ['production'] } as const;
    const declared = manifest({}, ['local', 'production']);

    expect(evaluateApplicability(rule, declared, 'production')).toBe('applicable');
    expect(evaluateApplicability(rule, declared, 'local')).toBe('not_applicable');
    expect(evaluateApplicability(rule, declared, 'staging')).toBe('unknown');
  });

  it('combines feature and environment requirements', () => {
    const rule = {
      rule: 'when_all',
      features: ['personal_data'],
      environments: ['production'],
    } as const;

    const ready = manifest({ personal_data: enabled }, ['local', 'production']);
    expect(evaluateApplicability(rule, ready, 'production')).toBe('applicable');
    expect(evaluateApplicability(rule, ready, 'local')).toBe('not_applicable');

    const undeclared = manifest({}, ['local', 'production']);
    expect(evaluateApplicability(rule, undeclared, 'production')).toBe('unknown');
  });
});

describe('coverage gaps for excluded features', () => {
  it('reports a gap when an excluded feature is enabled', () => {
    const gaps = coverageGap(manifest({ payments: enabled, tenancy: enabled }), ['payments', 'webhooks']);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toContain('payments');
    expect(gaps[0]).toContain('no implied pass');
  });

  it('reports nothing for a disabled or unknown excluded feature', () => {
    expect(coverageGap(manifest({ payments: disabled }), ['payments'])).toEqual([]);
    expect(coverageGap(manifest({}), ['payments'])).toEqual([]);
  });

  it('reports each enabled excluded feature separately', () => {
    const gaps = coverageGap(manifest({ payments: enabled, runtime_ai: enabled }), ['payments', 'runtime_ai']);
    expect(gaps).toHaveLength(2);
  });
});
