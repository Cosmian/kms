/**
 * Secret-data flow E2E tests.
 *
 * Covers:
 *   • create (random 32-byte seed, default)
 *   • create (Password type with explicit value)
 *   • export and import (round-trip)
 *   • revoke and destroy
 */
import { expect, test } from "@playwright/test";
import { extractUuid, gotoAndWait, selectOption, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

/** Create a random secret-data object and return its UUID. */
async function createSecretData(page: Parameters<typeof gotoAndWait>[0]): Promise<string> {
    await gotoAndWait(page, "/ui/secret-data/create");
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/has been created/i);
    const id = extractUuid(text);
    expect(id).not.toBeNull();
    return id!;
}

test.describe("Secret data", () => {
    test("create random 32-byte seed (default)", async ({ page }) => {
        await gotoAndWait(page, "/ui/secret-data/create");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create Password secret with a value", async ({ page }) => {
        await gotoAndWait(page, "/ui/secret-data/create");
        await page.fill('textarea[placeholder="Enter secret value"]', "my-e2e-password");
        await selectOption(page, "secret-type-select", "Password");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("export then import secret data", async ({ page }) => {
        const id = await createSecretData(page);

        // Export ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/secret-data/export");
        await page.fill('input[placeholder="Enter secret data ID"]', id);
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/secret-data/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await page.locator("#keyFormat").scrollIntoViewIfNeeded();
        await page.locator("#keyFormat").click({ force: true });
        await page.locator(".ant-select-item-option:visible", { hasText: "JSON TTLV (default)" }).first().click({ force: true });
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
    });

    test("revoke and destroy secret data", async ({ page }) => {
        const id = await createSecretData(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/secret-data/revoke");
        await page.fill('input[placeholder="Enter secret data ID"]', id);
        await page.fill('textarea[placeholder="Enter the reason for secret data revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/secret-data/destroy");
        await page.fill('input[placeholder="Enter secret data ID"]', id);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });
});
