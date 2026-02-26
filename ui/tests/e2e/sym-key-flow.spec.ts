/**
 * Symmetric-key flow E2E tests.
 *
 * Covers:
 *   • create  (AES-256, default settings)
 *   • export  (json-ttlv download)
 *   • import  (round-trip: export then import the same file)
 *   • revoke  (requires a live key)
 *   • destroy (requires a revoked key)
 *   • navigate: encrypt, decrypt pages
 */
import { expect, test } from "@playwright/test";
import { extractUuid, gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

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

test.describe("Symmetric key", () => {
    test("create AES-256 key with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/create");
        // The algorithm Select is populated by WASM; wait until it shows a value.
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create AES-256 key then export as json-ttlv", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("export then import sym key", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Export ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await page.locator("#keyFormat").click({ force: true });
        await page.locator(".ant-select-item-option:visible", { hasText: "JSON TTLV (default)" }).first().click({ force: true });
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
    });

    test("revoke and destroy sym key", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to sym encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to sym decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });
});
