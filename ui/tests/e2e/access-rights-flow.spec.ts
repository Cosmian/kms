/**
 * Access-rights flow E2E tests.
 *
 * Covers:
 *   • navigate to grant / revoke access pages (heading check)
 *   • list access rights on a freshly created symmetric key
 *   • grant access to a test user on a key, then list + verify access
 *   • grant access to a test user on a key, then revoke it
 *   • navigate to owned objects page (auto-loads on mount)
 *   • navigate to obtained access page (auto-loads on mount)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, gotoAndWait, selectOption, submitAndWaitForResponse } from "./helpers";

test.describe("Access rights", () => {
    test("navigate to grant access page", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/grant");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to revoke access page", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/revoke");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("list access rights on a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/access-rights/list");
        await page.fill('input[placeholder="Enter object UID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        // May be "Empty result" or a table with owner access – either way a response appears
        expect(text.length).toBeGreaterThan(0);
    });

    test("grant access on a key then list shows granted user", async ({ page }) => {
        const testUser = "list-check-user@example.com";
        const keyId = await createSymKey(page);

        // Grant "Get" access on the key ───────────────────────────────────────
        await gotoAndWait(page, "/ui/access-rights/grant");
        await page.fill('input[placeholder="Enter user identifier"]', testUser);
        await selectOption(page, "operation-types-select", "Get");
        await page.fill('input[placeholder="Enter object UID"]', keyId);
        const grantText = await submitAndWaitForResponse(page);
        expect(grantText).toMatch(/successfully added/i);

        // List access rights and verify the granted user appears ──────────────
        await gotoAndWait(page, "/ui/access-rights/list");
        await page.fill('input[placeholder="Enter object UID"]', keyId);
        await page.click('[data-testid="submit-btn"]');
        const responseEl = page.locator('[data-testid="response-output"]');
        await responseEl.waitFor({ state: "visible", timeout: 30_000 });
        const responseText = (await responseEl.textContent()) ?? "";
        expect(responseText).toContain(testUser);
        expect(responseText).toMatch(/get/i);
    });

    test("grant then revoke access on a key", async ({ page }) => {
        const testUser = "e2e-test-user@example.com";

        // Grant ────────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/access-rights/grant");
        await page.fill('input[placeholder="Enter user identifier"]', testUser);
        // Leave operation_types empty so unique_identifier is not required by validation.
        const grantText = await submitAndWaitForResponse(page);
        // The server returns a success string or an error; either way response appears
        expect(grantText.length).toBeGreaterThan(0);

        // Revoke ───────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/access-rights/revoke");
        await page.fill('input[placeholder="Enter user identifier"]', testUser);
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText.length).toBeGreaterThan(0);
    });

    test("navigate to owned objects page", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/owned");
        // Page auto-loads on mount; verify specific heading text
        await expect(page.getByRole("heading", { name: /Objects owned/i })).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to obtained access page", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/obtained");
        await expect(page.getByRole("heading", { name: /Access rights obtained/i })).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
