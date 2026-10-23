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
        await expect(page.getByText("Please enter the private key ID")).toBeVisible();
        await expect(page.getByText("Please enter the subject distinguished name")).toBeVisible();
    });
});
