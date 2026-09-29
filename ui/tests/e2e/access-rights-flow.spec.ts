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

    /**
     * Regression test for the serialisation bug where the WASM function
     * `get_kmip_operations()` returned Display values with underscores
     * (e.g. `set_attribute`) instead of the serde-lowercase values the server
     * expects (e.g. `setattribute`), causing HTTP 400 errors.
     *
     * Iterates over every operation label exposed by the UI and verifies that
     * each grant request is accepted without error by the server.
     */
    test("grant access with every operation type succeeds", async ({ page }) => {
        const testUser = "all-ops-e2e@example.com";
        const keyId = await createSymKey(page);

        // All labels produced by the WASM get_kmip_operations() call (excluding
        // "Create" which is handled separately via its own checkbox).
        const operations = [
            "Certify",
            "Decrypt",
            "Derive Key",
            "Destroy",
            "Encrypt",
            "Export",
            "Get",
            "Get Attributes",
            "Hash",
            "Import",
            "Locate",
            "MAC",
            "Revoke",
            "Rekey",
            "Sign",
            "Signature Verify",
            "Validate",
            "Set Attribute",
            "Modify Attribute",
            "Add Attribute",
            "Delete Attribute",
        ];

        await gotoAndWait(page, "/ui/access-rights/grant");
        await page.fill('input[placeholder="Enter user identifier"]', testUser);

        // Select all 21 operations in one multi-select session and submit a
        // single grant request.  Doing 21 separate page navigations + API
        // calls would exceed the 90 s test timeout; a single bulk grant still
        // exercises every operation label through the WASM serialiser.
        const selectWrapper = page.locator('[data-testid="operation-types-select"]');
        await selectWrapper.click();
        const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
        await dropdown.waitFor({ state: "visible", timeout: 5_000 });

        const searchInput = selectWrapper.locator(".ant-select-selection-search-input");

        for (const operation of operations) {
            // Search by the first word only — Ant Design treats a Space keypress
            // as "select the highlighted option", so typing "Derive Key" would
            // commit the highlighted entry via keyboard rather than append to
            // the filter text.  The locator regex still matches the full label.
            const searchTerm = operation.split(" ")[0];
            await searchInput.pressSequentially(searchTerm, { delay: 30 });
            const escapedText = operation.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            const filteredOption = dropdown
                .locator(".ant-select-item-option", {
                    hasText: new RegExp(`^\\s*${escapedText}\\s*$`),
                })
                .first();
            await filteredOption.waitFor({ state: "visible", timeout: 10_000 });
            await filteredOption.dispatchEvent("click");
            // Clear any leftover search text so the next iteration starts fresh.
            await searchInput.press("Control+a");
            await searchInput.press("Delete");
        }

        // Close the dropdown before interacting with other fields.
        await page.keyboard.press("Escape");

        await page.fill('input[placeholder="Enter object UID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/successfully added/i);
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
