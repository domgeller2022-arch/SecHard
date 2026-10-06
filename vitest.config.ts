import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    reporters: ['default'],
    // CLI and integration tests spawn real processes and run real git, so the default 5s is too low.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
