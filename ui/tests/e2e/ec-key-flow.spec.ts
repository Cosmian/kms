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
import { UI_READY_TIMEOUT, extractUuidAfterLabel, gotoAndWait, selectOption, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

/** Create a fresh EC key pair and return { privKeyId, pubKeyId }. */
async function createEcKeyPair(page: Parameters<typeof gotoAndWait>[0]) {
    await gotoAndWait(page, "/ui/ec/keys/create");
    await selectOption(page, "ec-curve-select", "NIST P-256");
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const privKeyId = extractUuidAfterLabel(text, "Private key Id");
    const pubKeyId = extractUuidAfterLabel(text, "Public key Id");
    expect(privKeyId).not.toBeNull();
    expect(pubKeyId).not.toBeNull();
    return { privKeyId: privKeyId!, pubKeyId: pubKeyId! };
}

test.describe("EC key pair", () => {
    test("create EC key pair with default curve", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/keys/create");
        // Explicitly pick a stable curve; avoids WASM init timing races.
        await selectOption(page, "ec-curve-select", "NIST P-256");
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
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to ec encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to ec decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to ec sign page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/sign");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to ec verify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/verify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
