/**
 * PQC key-pair flow E2E tests.
 *
 * Covers:
 *   • create  (ML-KEM-512 by default)
 *   • export  (private key, json-ttlv download)
 *   • revoke  (private key)
 *   • destroy (private key, after revocation)
 *   • navigate: import, encapsulate, decapsulate, sign, verify pages
 */
import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    createPqcKeyPair,
    gotoAndWait,
    selectOption,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

test.describe("PQC key pair", () => {
    test("create ML-KEM-512 key pair", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/keys/create");
        await selectOption(page, "pqc-algorithm-select", "ML-KEM-512");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);
    });

    test("create ML-DSA-65 key pair", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/keys/create");
        await selectOption(page, "pqc-algorithm-select", "ML-DSA-65");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);
    });

    test("create then export private key", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-KEM-512");

        await gotoAndWait(page, "/ui/pqc/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("revoke and destroy PQC key", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-KEM-768");

        // Revoke
        await gotoAndWait(page, "/ui/pqc/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy
        await gotoAndWait(page, "/ui/pqc/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to pqc import page", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/keys/import");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to pqc encapsulate page", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/encapsulate");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to pqc decapsulate page", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/decapsulate");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to pqc sign page", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/sign");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to pqc verify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/verify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
