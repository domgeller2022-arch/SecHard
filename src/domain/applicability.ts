export interface FeatureState {
  readonly state: 'enabled' | 'disabled' | 'unknown';
}

export type ApplicabilityRule =
  | { readonly rule: 'always' }
  | { readonly rule: 'when_feature_enabled'; readonly features: readonly string[] }
  | { readonly rule: 'when_any_feature_enabled'; readonly features: readonly string[] }
  | { readonly rule: 'when_environment'; readonly environments: readonly string[] }
  | {
      readonly rule: 'when_all';
      readonly features: readonly string[];
      readonly environments?: readonly string[];
    };

export type Applicability = 'applicable' | 'not_applicable' | 'unknown';

export interface ManifestLike {
  readonly features: Readonly<Record<string, FeatureState | undefined>>;
  readonly environments: readonly { readonly kind: string; readonly internet_facing?: boolean }[];
}

/**
 * A declared feature is treated as `unknown` when the manifest omits it. Omission must never
 * silently remove a tenant, role, or ownership requirement, so an unknown feature makes the
 * control's applicability `unknown` rather than `not_applicable`.
 */
export function evaluateApplicability(
  applicability: ApplicabilityRule,
  manifest: ManifestLike,
  environment: string,
): Applicability {
  switch (applicability.rule) {
    case 'always':
      return 'applicable';

    case 'when_feature_enabled': {
      const states = applicability.features.map((feature) => featureState(manifest, feature));
      if (states.some((state) => state === 'enabled')) return 'applicable';
      if (states.some((state) => state === 'unknown')) return 'unknown';
      return 'not_applicable';
    }

    case 'when_any_feature_enabled': {
      const states = applicability.features.map((feature) => featureState(manifest, feature));
      if (states.some((state) => state === 'enabled')) return 'applicable';
      if (states.some((state) => state === 'unknown')) return 'unknown';
      return 'not_applicable';
    }

    case 'when_environment': {
      const matches = applicability.environments.includes(environment);
      if (matches) return 'applicable';
      const knownEnvironments = manifest.environments.map((entry) => entry.kind);
      if (!knownEnvironments.includes(environment)) return 'unknown';
      return 'not_applicable';
    }

    case 'when_all': {
      const states = applicability.features.map((feature) => featureState(manifest, feature));
      const environmentMatches =
        applicability.environments === undefined || applicability.environments.includes(environment);
      if (!environmentMatches) {
        const knownEnvironments = manifest.environments.map((entry) => entry.kind);
        return knownEnvironments.includes(environment) ? 'not_applicable' : 'unknown';
      }
      if (states.every((state) => state === 'enabled')) return 'applicable';
      if (states.some((state) => state === 'unknown')) return 'unknown';
      return 'not_applicable';
    }

    default: {
      const exhaustive: never = applicability;
      throw new Error(`unsupported applicability rule: ${JSON.stringify(exhaustive)}`);
    }
  }
}

export function featureState(manifest: ManifestLike, feature: string): FeatureState['state'] {
  const declared = manifest.features[feature];
  return declared?.state ?? 'unknown';
}

export function coverageGap(
  manifest: ManifestLike,
  excludedFeatures: readonly string[],
): readonly string[] {
  const gaps: string[] = [];
  for (const feature of excludedFeatures) {
    if (featureState(manifest, feature) === 'enabled') {
      gaps.push(
        `feature '${feature}' is enabled but is excluded by the selected profile; additional maintained verification is required and no implied pass is available`,
      );
    }
  }
  return gaps;
}
