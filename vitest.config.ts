import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // The calibration corpora and fixtures are audit data, not suites of their own.
    exclude: ['tests/corpus/**', 'tests/fixtures/**', 'node_modules/**'],
    reporters: ['default'],
    globalSetup: ['tests/global-setup.ts'],
    // CLI and integration tests spawn real processes and run real git, so the default 5s is too low.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
