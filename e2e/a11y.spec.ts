import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the BIP test vectors;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> expanded, in both the dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

/**
 * Neutralise motion before scanning.
 *
 * The byte-flow diagram animates on load, and `.bf-stage` transitions its
 * background over 250ms. Toggling the theme therefore leaves every stage box
 * mid-blend, and axe samples that intermediate colour as the background behind
 * `.bf-kicker` / `.bf-sub` — reporting a contrast failure for a colour pair
 * that exists for a quarter of a second and is in the palette at neither end.
 * Snapping transitions off makes the scan measure the colours that actually
 * ship. Nothing about the palette or the rule set is relaxed.
 */
async function freezeMotion(page: Page): Promise<void> {
  // Let the byte-flow finish its beats so the final, settled state is scanned.
  await page.waitForFunction(
    () => document.querySelector('[data-bytes="bech"]')?.textContent !== '—',
    undefined,
    { timeout: 10_000 },
  );
  await page.addStyleTag({
    content: `*, *::before, *::after {
      transition: none !important;
      animation: none !important;
    }`,
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await freezeMotion(page);
  await expandAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await freezeMotion(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expandAll(page);
  await scan(page);
});
