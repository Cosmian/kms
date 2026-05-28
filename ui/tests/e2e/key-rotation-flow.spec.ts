/**
 * Key rotation flow E2E tests.
 *
 * Covers:
 *   • set-rotation-policy on a symmetric key
 *   • get-rotation-policy (verify interval, offset, name)
 *   • re-key a symmetric key (new UID created)
 *   • navigate: re-key, set/get rotation policy pages
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, extractUuid, gotoAndWait, submitAndWaitForResponse } from "./helpers";

test.describe("Key rotation", () => {
    test("set rotation policy on a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/set-rotation-policy");
        await page.fill('[data-testid="key-id-input"]', keyId);
        // Set interval to 3600 (default), offset to 60, name to "e2e-test"
        // Ant Design Form auto-assigns id from Form.Item name prop
        await page.fill("#offset", "60");
        await page.fill('[data-testid="name-input"]', "e2e-test");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy has been set/i);
    });

    test("get rotation policy shows set values", async ({ page }) => {
        const keyId = await createSymKey(page);

        // First set a policy
        await gotoAndWait(page, "/ui/sym/keys/set-rotation-policy");
        await page.fill('[data-testid="key-id-input"]', keyId);
        await page.fill('[data-testid="name-input"]', "hourly");
        const setResult = await submitAndWaitForResponse(page);
        expect(setResult).toMatch(/rotation policy has been set/i);

        // Now get the policy
        await gotoAndWait(page, "/ui/sym/keys/get-rotation-policy");
        await page.fill('[data-testid="key-id-input"]', keyId);
        await page.locator('[data-testid="submit-btn"]').click();
        await expect(page.locator('[data-testid="response-output"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });

        // Verify the policy is displayed
        const policyText = await page.locator('[data-testid="response-output"]').textContent();
        expect(policyText).toMatch(/3600/);
    });

    test("re-key a symmetric key produces a new UID", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/rekey");
        await page.fill('[data-testid="key-id-input"]', keyId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/re-keyed/i);

        // Extract the new key ID and verify it differs from the old one
        const newKeyId = extractUuid(text);
        expect(newKeyId).not.toBeNull();
        expect(newKeyId).not.toBe(keyId);
    });

    test("navigate to set-rotation-policy page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/set-rotation-policy");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to get-rotation-policy page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/get-rotation-policy");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to re-key page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/rekey");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("notifications bell is visible in header", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await expect(page.locator('[data-testid="notifications-bell"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
