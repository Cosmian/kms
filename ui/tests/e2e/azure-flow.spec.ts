/**
 * Azure BYOK flow E2E tests.
 *
 * Covers (navigation/smoke tests — Azure integration requires external KEK files):
 *   • Import Azure KEK  (/azure/import-kek)
 *   • Export Azure BYOK (/azure/export-byok)
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait } from "./helpers";

test.describe("Azure BYOK", () => {
    test("navigate to Azure import KEK page", async ({ page }) => {
        await gotoAndWait(page, "/ui/azure/import-kek");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 30_000 });
    });

    test("navigate to Azure export BYOK page", async ({ page }) => {
        await gotoAndWait(page, "/ui/azure/export-byok");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 30_000 });
    });
});
