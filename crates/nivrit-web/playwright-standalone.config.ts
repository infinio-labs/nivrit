import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests that need only a running API and dev server, no Docker.
 *
 * The default config's global setup brings up Docker Compose and seeds users
 * through the CLI, which makes it awkward to run and therefore rarely run. This
 * config has no global setup: point it at any API and start the dev server
 * yourself.
 */
export default defineConfig({
  testDir: './e2e',
  testMatch: 'ui-smoke.spec.ts',
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.NIVRIT_WEB_URL ?? 'http://localhost:5199',
    trace: 'retain-on-failure',
    headless: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
