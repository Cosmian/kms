/**
 * AWS BYOK flow E2E tests.
 *
 * Covers (navigation/smoke tests — AWS integration requires external KEK files):
 *   • Import AWS KEK  (/aws/import-kek)
 *   • Export AWS key material (/aws/export-key-material)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";
import { AWS_ROUTES } from "./routes";

test.describe("AWS BYOK", () => {
    for (const { name, path, locator } of AWS_ROUTES) {
        test(`navigate to AWS ${name} page`, async ({ page }) => {
            await gotoAndWait(page, path);
            await expect(page.locator(locator ?? '[data-testid="submit-btn"]').first()).toBeVisible({ timeout: UI_READY_TIMEOUT });
        });
    }
});
