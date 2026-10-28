/**
 * Generate-CSR page E2E: the form is reachable from the Certificates menu and refuses an empty
 * submission. CSR content is covered by the server and CLI integration tests.
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";

test.describe("Certificates - Generate CSR", () => {
    test("form validates required fields", async ({ page }) => {
        await gotoAndWait(page, "/ui/certificates/certs/generate-csr");
        const submit = page.locator('[data-testid="submit-generate-csr"]');
        await expect(submit).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await submit.click();
        await expect(page.getByText(/Please enter the private key ID/i)).toBeVisible();
        await expect(page.getByText(/Please enter the subject distinguished name/i)).toBeVisible();
    });

    test("generating the key pair asks for an algorithm and, in the HSM, for an hsm:: key id", async ({ page }) => {
        await gotoAndWait(page, "/ui/certificates/certs/generate-csr");
        await page.locator('[data-testid="csr-key-source-generate"]').click({ timeout: UI_READY_TIMEOUT });
        await expect(page.locator('[data-testid="csr-algorithm-select"]')).toBeVisible();
        await page.locator('[data-testid="csr-in-hsm"]').click();
        await expect(page.locator('[data-testid="csr-sensitive"]')).toBeDisabled();
        await page.locator('[data-testid="private-key-id"]').fill("subca");
        await page.locator('[data-testid="submit-generate-csr"]').click();
        await expect(page.getByText(/Please select an algorithm/i)).toBeVisible();
        await expect(page.getByText(/An HSM key ID starts with hsm::/i)).toBeVisible();
    });
});
