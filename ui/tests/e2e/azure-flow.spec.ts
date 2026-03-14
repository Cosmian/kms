/**
 * Azure BYOK flow E2E tests.
 *
 * Covers (navigation/smoke tests — Azure integration requires external KEK files):
 *   • Import Azure KEK  (/azure/import-kek)
 *   • Export Azure BYOK (/azure/export-byok)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";
import { AZURE_ROUTES } from "./routes";

test.describe("Azure BYOK", () => {
    for (const { name, path } of AZURE_ROUTES) {
        test(`navigate to Azure ${name} page`, async ({ page }) => {
            await gotoAndWait(page, path);
            await expect(
                page.locator('[data-testid="submit-btn"]'),
            ).toBeVisible({ timeout: UI_READY_TIMEOUT });
        });
    }
});
