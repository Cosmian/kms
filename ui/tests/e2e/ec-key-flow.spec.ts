/**
 * EC key-pair flow E2E tests.
 *
 * Covers:
 *   • create  (default curve from WASM)
 *   • export  (private key, json-ttlv download)
 *   • revoke  (private key)
 *   • destroy (private key, after revocation)
 *   • navigate: import, encrypt, decrypt, sign, verify pages
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

/** Create a fresh EC key pair and return { privKeyId, pubKeyId }. */
async function createEcKeyPair(page: Parameters<typeof gotoAndWait>[0]) {
    await gotoAndWait(page, "/ui/ec/keys/create");
    await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const privKeyId = text.match(/Private key Id:\s*([0-9a-f-]{36})/i)?.[1];
    const pubKeyId = text.match(/Public key Id:\s*([0-9a-f-]{36})/i)?.[1];
    expect(privKeyId).toBeDefined();
    expect(pubKeyId).toBeDefined();
    return { privKeyId: privKeyId!, pubKeyId: pubKeyId! };
}

test.describe("EC key pair", () => {
    test("create EC key pair with default curve", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/keys/create");
        // The curve Select is populated by WASM; wait until a value is shown.
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);
    });

    test("create EC key pair then export private key", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/ec/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("revoke and destroy EC key", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/ec/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/ec/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to ec import page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/keys/import");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to ec encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to ec decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to ec sign page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/sign");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("navigate to ec verify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/verify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });
});
