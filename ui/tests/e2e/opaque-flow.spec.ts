/**
 * Opaque-object flow E2E tests.
 *
 * Covers:
 *   • create (empty object)
 *   • create (with explicit UTF-8 data)
 *   • export and import (round-trip)
 *   • revoke and destroy
 */
import { expect, test } from "@playwright/test";
import { extractUuid, gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

/** Create an empty opaque object and return its UUID. */
async function createOpaqueObject(page: Parameters<typeof gotoAndWait>[0]): Promise<string> {
    await gotoAndWait(page, "/ui/opaque-object/create");
    await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 30_000 });
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/has been created/i);
    const id = extractUuid(text);
    expect(id).not.toBeNull();
    return id!;
}

test.describe("Opaque object", () => {
    test("create empty opaque object", async ({ page }) => {
        await gotoAndWait(page, "/ui/opaque-object/create");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 30_000 });
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create opaque object with explicit data", async ({ page }) => {
        await gotoAndWait(page, "/ui/opaque-object/create");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 30_000 });
        await page.fill('textarea[placeholder="Enter opaque data"]', "e2e-test-opaque-payload");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("export then import opaque object", async ({ page }) => {
        const id = await createOpaqueObject(page);

        // Export ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/opaque-object/export");
        await page.fill('input[placeholder="Enter opaque object ID"]', id);
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/opaque-object/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await page.locator("#keyFormat").scrollIntoViewIfNeeded();
        await page.locator("#keyFormat").click({ force: true });
        await page
            .locator(".ant-select-item-option:visible", { hasText: "JSON TTLV (default)" })
            .first()
            .click({ force: true });
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
    });

    test("revoke and destroy opaque object", async ({ page }) => {
        const id = await createOpaqueObject(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/opaque-object/revoke");
        await page.fill('input[placeholder="Enter opaque object ID"]', id);
        await page.fill('textarea[placeholder="Enter the reason for opaque object revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/opaque-object/destroy");
        await page.fill('input[placeholder="Enter opaque object ID"]', id);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });
});
