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
import { gotoAndWait } from "./helpers";

const CERT_PAGES = [
    { name: "certify", path: "/ui/certificates/certs/certify" },
    { name: "export", path: "/ui/certificates/certs/export" },
    { name: "import", path: "/ui/certificates/certs/import" },
    { name: "revoke", path: "/ui/certificates/certs/revoke" },
    { name: "destroy", path: "/ui/certificates/certs/destroy" },
    { name: "validate", path: "/ui/certificates/certs/validate" },
    { name: "encrypt", path: "/ui/certificates/encrypt" },
    { name: "decrypt", path: "/ui/certificates/decrypt" },
];

test.describe("Certificates", () => {
    for (const { name, path } of CERT_PAGES) {
        test(`navigate to certificate ${name} page`, async ({ page }) => {
            await gotoAndWait(page, path);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
        });
    }
});
