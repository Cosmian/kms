/**
 * Certificates flow E2E tests.
 *
 * Covers (navigation/smoke tests for all 8 certificate menu items):
 *   • certify    (/certificates/certs/certify)
 *   • export     (/certificates/certs/export)
 *   • import     (/certificates/certs/import)
 *   • revoke     (/certificates/certs/revoke)
 *   • destroy    (/certificates/certs/destroy)
 *   • validate   (/certificates/certs/validate)
 *   • encrypt    (/certificates/encrypt)
 *   • decrypt    (/certificates/decrypt)
 *
 * Full E2E submission tests (certify/validate/encrypt/decrypt) require
 * external CSR / certificate files and are therefore kept as navigation tests.
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";
import { CERT_ROUTES } from "./routes";

test.describe("Certificates", () => {
    for (const { name, path } of CERT_ROUTES) {
        test(`navigate to certificate ${name} page`, async ({ page }) => {
            await gotoAndWait(page, path);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
        });
    }
});
