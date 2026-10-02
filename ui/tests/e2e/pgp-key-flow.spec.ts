/**
 * OpenPGP key flow E2E tests.
 *
 * Covers:
 *   (1) create Ed25519 key (default)
 *   (2) create RSA-3072 key
 *   (3) create and export pgp-public (.asc)
 *   (4) export -> import roundtrip
 *   (5) revoke and destroy
 *   (6) navigate to encrypt, decrypt, sign, verify pages
 */
import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    createPgpKey,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

test.describe("OpenPGP key", () => {
    test("create Ed25519 key with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/pgp/keys/create");
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create RSA-3072 key", async ({ page }) => {
        await gotoAndWait(page, "/ui/pgp/keys/create");
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
        await selectOptionById(page, "#algorithm", "RSA");
        await page.fill("#keySize", "3072");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create OpenPGP key then export as pgp-public (.asc)", async ({ page }) => {
        const keyId = await createPgpKey(page);

        await gotoAndWait(page, "/ui/pgp/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOptionById(page, "#keyFormat", "OpenPGP Public Key (.asc)");
        const { text, download } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
        expect(download.suggestedFilename()).toMatch(/\.asc$/);
    });

    test("export then import OpenPGP public key", async ({ page }) => {
        const keyId = await createPgpKey(page);

        // Export ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/pgp/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOptionById(page, "#keyFormat", "OpenPGP Public Key (.asc)");
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/pgp/keys/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await selectOptionById(page, "#keyFormat", "OpenPGP (.asc or binary)");
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
    });

    test("revoke and destroy OpenPGP key", async ({ page }) => {
        const keyId = await createPgpKey(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/pgp/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/pgp/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to pgp crypto operation pages", async ({ page }) => {
        for (const op of ["encrypt", "decrypt", "sign", "verify"]) {
            await gotoAndWait(page, `/ui/pgp/${op}`);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
        }
    });
});
