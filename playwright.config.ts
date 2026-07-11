import { defineConfig, devices } from '@playwright/test';

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4222/crypto-lab-bitcoin-wallet/',
    // The page derives its initial theme from prefers-color-scheme when no
    // saved preference exists; pin it to dark so the default scan is dark and
    // the toggle deterministically moves to light.
    colorScheme: 'dark',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run preview -- --port 4222 --strictPort',
    url: 'http://localhost:4222/crypto-lab-bitcoin-wallet/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
