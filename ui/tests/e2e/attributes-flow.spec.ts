/**
 * Attributes flow E2E tests.
 *
 * Covers:
 *   • navigate to get / set / delete attribute pages (heading check)
 *   • get attributes of a freshly created symmetric key
 *   • set an attribute (child_id link) on the key
 *   • delete that attribute from the key
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, gotoAndWait, selectOptionById, submitAndWaitForResponse } from "./helpers";

test.describe("Object attributes", () => {
    test("navigate to attributes get page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/get");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to attributes set page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/set");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to attributes delete page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/delete");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("get attributes of a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        // Any non-empty response is valid (should include the key's algorithm, length, etc.)
        expect(text.length).toBeGreaterThan(0);
    });

    test("set and delete a child_id attribute on a key", async ({ page }) => {
        const keyId = await createSymKey(page);
        const placeholder = "00000000-0000-0000-0000-000000000001";

        // Set attribute ────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOptionById(page, "#attribute_name", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', placeholder);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Delete attribute ─────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOptionById(page, "#attribute_name", "Child ID link");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);
    });
});
