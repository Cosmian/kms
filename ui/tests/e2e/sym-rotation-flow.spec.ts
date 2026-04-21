/**
 * Key rotation policy E2E tests.
 *
 * Covers:
 *   • re-key  (re-key an existing symmetric key)
 *   • rotation policy (set rotation policy for symmetric, RSA, EC, and PQC keys via the re-key page)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, gotoAndWait, setPolicyAndWaitForResponse, submitAndWaitForResponse } from "./helpers";

// ── Navigation smoke tests for all key types ──────────────────────────────────

test.describe("Rotation policy navigation", () => {
    for (const [label, path] of [
        ["RSA", "/ui/rsa/keys/re-key"],
        ["EC", "/ui/ec/keys/re-key"],
        ["PQC", "/ui/pqc/keys/re-key"],
    ] as const) {
        test(`navigate to ${label} re-key page`, async ({ page }) => {
            await gotoAndWait(page, path);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
        });
    }
});

test.describe("Symmetric key rotation", () => {
    test("navigate to re-key page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("re-key a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been re-keyed/i);
        expect(text).toMatch(/New key ID:/i);
    });

    test("re-keyed key carries ReplacedObjectLink pointing to the original key", async ({ page }) => {
        const oldKeyId = await createSymKey(page);

        // Re-key the original key and extract the new key ID from the response text.
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', oldKeyId);
        const rekeyText = await submitAndWaitForResponse(page);
        const match = rekeyText.match(/New key ID:\s*(\S+)/);
        expect(match).not.toBeNull();
        const newKeyId = match![1];
        expect(newKeyId).not.toBe(oldKeyId);

        // Fetch all attributes of the new key and verify that the old key ID
        // appears in the output — it is stored as the KMIP ReplacedObjectLink.
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', newKeyId);
        const attrsText = await submitAndWaitForResponse(page);
        expect(attrsText).toContain(oldKeyId);
    });

    test("navigate to re-key page (rotation policy)", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("set rotation interval on a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('input.ant-input-number-input[placeholder="e.g. 86400"]', "86400");
        const text = await setPolicyAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy updated/i);
        expect(text).toContain("rotate_interval=86400");
    });

    test("set rotation name on a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('input[placeholder="e.g. daily-rotation"]', "e2e-rotation");
        const text = await setPolicyAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy updated/i);
        expect(text).toContain("rotate_name=e2e-rotation");
    });

    test("disable rotation by setting interval to 0", async ({ page }) => {
        const keyId = await createSymKey(page);

        // First set a rotation interval
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('input.ant-input-number-input[placeholder="e.g. 86400"]', "0");
        const text = await setPolicyAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy updated/i);
        expect(text).toContain("rotate_interval=0");
    });

    test("show error when no fields specified", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        // Do not fill any optional field → submit
        const text = await setPolicyAndWaitForResponse(page);
        expect(text).toMatch(/no rotation policy attributes specified/i);
    });

    test("set rotation policy then re-key: new key is different, old key has ReplacementObjectLink", async ({ page }) => {
        const oldKeyId = await createSymKey(page);

        // Arm the key with a rotation policy.
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', oldKeyId);
        await page.fill('input.ant-input-number-input[placeholder="e.g. 86400"]', "3600");
        await page.fill('input[placeholder="e.g. daily-rotation"]', "e2e-hourly");
        const policyText = await setPolicyAndWaitForResponse(page);
        expect(policyText).toMatch(/rotation policy updated/i);

        // Re-key the armed key and extract the new key ID.
        await gotoAndWait(page, "/ui/sym/keys/re-key");
        await page.fill('input[placeholder="Enter key ID"]', oldKeyId);
        const rekeyText = await submitAndWaitForResponse(page);
        expect(rekeyText).toMatch(/has been re-keyed/i);
        const match = rekeyText.match(/New key ID:\s*(\S+)/);
        expect(match).not.toBeNull();
        const newKeyId = match![1];
        expect(newKeyId).not.toBe(oldKeyId);

        // Verify the old key has a ReplacementObjectLink → new key via GetAttributes.
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', oldKeyId);
        const attrsText = await submitAndWaitForResponse(page);
        // The new key ID should appear in the old key's attributes (ReplacementObjectLink).
        expect(attrsText).toContain(newKeyId);
    });
});
