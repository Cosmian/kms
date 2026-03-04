/**
 * Site-map navigation test.
 *
 * Visits every page listed in `routes.ts` and verifies that the page renders
 * its primary action button (`[data-testid="submit-btn"]`).
 *
 * This test has no functional assertions; its sole purpose is to catch broken
 * routes, blank screens, and runtime crashes that would prevent a page from
 * rendering correctly.
 *
 * Individual flow spec files (`sym-key-flow.spec.ts`, etc.) are responsible
 * for testing actual KMIP functionality; this test focuses exclusively on
 * reachability and basic render health.
 */
import { expect, test } from "@playwright/test";

import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";
import { ALL_ROUTES } from "./routes";

for (const { section, routes } of ALL_ROUTES) {
    test.describe(section, () => {
        for (const { name, path, locator } of routes) {
            test(`navigate to ${name}`, async ({ page }) => {
                await gotoAndWait(page, path);
                await expect(
                    page.locator(locator ?? '[data-testid="submit-btn"]'),
                ).toBeVisible({ timeout: UI_READY_TIMEOUT });
            });
        }
    });
}
