/**
 * AlwaysSensitive attribute E2E tests (KMIP 2.1 §4.3).
 *
 * Covers:
 *   • a Sensitive key reports AlwaysSensitive = true via GetAttributes
 *   • a non-sensitive key reports AlwaysSensitive = false
 *   • AlwaysSensitive is read-only: absent from the Set / Modify / Delete
 *     attribute selectors (server-managed attribute)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, extractUuid, gotoAndWait, submitAndWaitForResponse } from "./helpers";

/**
 * Create an AES-256 symmetric key, optionally marking it Sensitive, and return
 * its UID.
 */
async function createSymKey(page: import("@playwright/test").Page, sensitive: boolean): Promise<string> {
    await gotoAndWait(page, "/ui/sym/keys/create");
    // The algorithm Select is populated by WASM; wait until it shows a value.
    await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
    if (sensitive) {
        await page.locator('input[type="checkbox"]').first().check();
    }
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/has been created/i);
    const id = extractUuid(text);
    expect(id).not.toBeNull();
    return id!;
}

/**
 * Get the AlwaysSensitive attribute of an object and return the raw response
 * text. Requests all attributes (no filter) so that AlwaysSensitive is always
 * included regardless of UI select-dropdown behaviour.
 */
async function getAlwaysSensitive(page: import("@playwright/test").Page, keyId: string): Promise<string> {
    await gotoAndWait(page, "/ui/attributes/get");
    await page.fill('input[placeholder="Enter object ID"]', keyId);
    // No attribute filter — the server returns all attributes including AlwaysSensitive.
    return submitAndWaitForResponse(page);
}

test.describe("AlwaysSensitive attribute", () => {
    test("sensitive key reports AlwaysSensitive true", async ({ page }) => {
        const keyId = await createSymKey(page, true);
        const text = await getAlwaysSensitive(page, keyId);
        expect(text).toMatch(/always_?sensitive/i);
        expect(text).toMatch(/true/i);
    });

    test("non-sensitive key reports AlwaysSensitive false", async ({ page }) => {
        const keyId = await createSymKey(page, false);
        const text = await getAlwaysSensitive(page, keyId);
        expect(text).toMatch(/always_?sensitive/i);
        expect(text).toMatch(/false/i);
    });

    test("AlwaysSensitive is not offered in Set / Modify / Delete selectors", async ({ page }) => {
        for (const path of ["/ui/attributes/set", "/ui/attributes/modify", "/ui/attributes/delete"]) {
            await gotoAndWait(page, path);
            await page.locator('[data-testid="attribute-name-select"] .ant-select-selector').click({ force: true });
            const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
            await expect(dropdown).toBeVisible({ timeout: UI_READY_TIMEOUT });
            await expect(dropdown.getByRole("option", { name: "Always Sensitive", exact: true })).toHaveCount(0);
        }
    });
});
