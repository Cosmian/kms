/**
 * RSA key-pair flow E2E tests.
 *
 * Covers:
 *   • create  (4096-bit, default)
 *   • export  (public key, json-ttlv download)
 *   • revoke  (private key)
 *   • destroy (private key, after revocation)
 *   • navigate: import, encrypt, decrypt, sign, verify pages
 */
import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    extractAllUuids,
    extractUuidAfterLabel,
    gotoAndWait,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

/** Create a fresh RSA key pair and return { privKeyId, pubKeyId }. */
async function createRsaKeyPair(page: Parameters<typeof gotoAndWait>[0]) {
    await gotoAndWait(page, "/ui/rsa/keys/create");
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const privKeyId = extractUuidAfterLabel(text, "Private key Id");
    const pubKeyId = extractUuidAfterLabel(text, "Public key Id");
    expect(privKeyId).not.toBeNull();
    expect(pubKeyId).not.toBeNull();
    return { privKeyId: privKeyId!, pubKeyId: pubKeyId! };
}

test.describe("RSA key pair", () => {
    test("create 4096-bit RSA key pair with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/keys/create");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);

        // Both IDs should look like UUIDs.
        const ids = extractAllUuids(text);
        expect(ids.length).toBeGreaterThanOrEqual(2);
    });

    test("create RSA key pair then export public key as json-ttlv", async ({ page }) => {
        const { pubKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rsa/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("revoke and destroy RSA key", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to rsa import page", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/keys/import");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to rsa encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to rsa decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to rsa sign page", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/sign");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to rsa verify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/verify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
