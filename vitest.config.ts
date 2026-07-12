import { defineConfig } from 'vitest/config';

// Unit tests only. The Playwright a11y gate lives in e2e/ and the puppeteer
// browser flow is tests/browser-e2e.mjs — neither should be collected by
// vitest (they need a real browser + preview server).
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
