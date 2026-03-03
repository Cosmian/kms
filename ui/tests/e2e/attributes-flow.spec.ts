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
import { extractUuid, gotoAndWait, submitAndWaitForResponse } from "./helpers";

/** Create a fresh AES-256 key and return its UUID. */
async function createSymKey(page: Parameters<typeof gotoAndWait>[0]): Promise<string> {
    await gotoAndWait(page, "/ui/sym/keys/create");
    await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/has been created/i);
    const id = extractUuid(text);
    expect(id).not.toBeNull();
    return id!;
}

/**
 * Pick an option from an AntD Select that has no data-testid.
 * Identifies the select by its AntD Form id (derived from the Form.Item name).
 */
async function selectAntDById(page: Parameters<typeof gotoAndWait>[0], formItemId: string, optionText: string): Promise<void> {
    const trigger = page.locator(`#${formItemId}`);
    await trigger.scrollIntoViewIfNeeded();
    await trigger.click({ force: true });
    // Wait for dropdown to open
    await page.locator(".ant-select-dropdown:visible").waitFor({ timeout: 10_000 });
    // Scroll the dropdown list so virtual-list renders all items
    const dropdown = page.locator(".ant-select-dropdown:visible .rc-virtual-list-holder").first();
    await dropdown.evaluate((el) => {
        el.scrollTop = el.scrollHeight;
    });
    const option = page.locator(".ant-select-item-option", { hasText: optionText }).first();
    try {
        await option.scrollIntoViewIfNeeded();
        await option.click({ force: true });
    } catch {
        await option.dispatchEvent("click");
    }
}

test.describe("Object attributes", () => {
    test("navigate to attributes get page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/get");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to attributes set page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/set");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to attributes delete page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/delete");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
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
        await selectAntDById(page, "attribute_name", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', placeholder);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Delete attribute ─────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectAntDById(page, "attribute_name", "Child ID link");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);
    });
});
