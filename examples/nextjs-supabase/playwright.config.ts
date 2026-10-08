import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end configuration.
 *
 * One browser, one worker, no retries. A security assertion that passes on the second attempt is a
 * flaky assertion, and retrying until green is how a failure gets hidden. The suite runs against a
 * production build (`next start`) rather than the dev server so that what is tested is what ships.
 *
 * The local Supabase stack must be running and `.env.local` must be current (`pnpm run env:sync`).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:3100',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'pnpm exec next start -p 3100',
    url: 'http://127.0.0.1:3100',
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
