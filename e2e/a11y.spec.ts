import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: a private key generated and
 * its address derived, a 12-word mnemonic generated, its last word mangled so
 * the checksum refuses the phrase, validation run against a bad phrase and then
 * retired by an edit, an address derived at a native-segwit path, the
 * memorisation drill started and reset, and every disclosure opened by its own
 * summary. Every resulting state is scanned in both themes at desktop and phone
 * width.
 *
 * See `gate.ts` for why nothing is injected into the page, why reduced motion
 * is asked for rather than forced, why every step is scanned rather than only
 * the first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
