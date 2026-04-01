/**
 * Derive Key flow E2E tests.
 *
 * Covers:
 *   • navigation smoke test (page renders)
 *   • PBKDF2 key derivation from an existing AES key
 *   • HKDF key derivation from an existing AES key
 *
 * The base key is created via direct KMIP API call (bypasses the UI) because
 * the standard key-creation form does not expose the `DeriveKey` cryptographic
 * usage mask (0x0000_0200 = 512) required by the server.
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createDerivableSymKey, gotoAndWait, submitAndWaitForResponse } from "./helpers";

/** 16-byte salt expressed as a 32-character lowercase hex string. */
const SALT_HEX = "0102030405060708090a0b0c0d0e0f10";

// ── Navigation smoke test ─────────────────────────────────────────────────────

test.describe("Derive Key navigation", () => {
    test("navigate to derive key page", async ({ page }) => {
        await gotoAndWait(page, "/ui/derive-key");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});

// ── PBKDF2 derivation ─────────────────────────────────────────────────────────

test.describe("Derive Key – PBKDF2", () => {
    test("derive AES-256 key from existing key using PBKDF2", async ({ page }) => {
        const baseKeyId = await createDerivableSymKey();

        await gotoAndWait(page, "/ui/derive-key");

        // Key ID source is the default — fill the key ID field
        await page.fill('input[placeholder="Enter source key ID"]', baseKeyId);

        // Salt (required)
        await page.fill('input[placeholder*="0011223344556677"]', SALT_HEX);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/derived key created with id/i);
    });

    test("PBKDF2 derivation with optional output ID field filled in", async ({ page }) => {
        const baseKeyId = await createDerivableSymKey();
        const desiredId = `e2e-derived-${Date.now()}`;

        await gotoAndWait(page, "/ui/derive-key");

        await page.fill('input[placeholder="Enter source key ID"]', baseKeyId);
        await page.fill('input[placeholder*="0011223344556677"]', SALT_HEX);
        await page.fill('input[placeholder*="Optional: enter desired key ID"]', desiredId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/derived key created with id/i);
    });
});

// ── HKDF derivation ───────────────────────────────────────────────────────────

test.describe("Derive Key – HKDF", () => {
    test("derive AES-256 key from existing key using HKDF", async ({ page }) => {
        const baseKeyId = await createDerivableSymKey();

        await gotoAndWait(page, "/ui/derive-key");

        await page.fill('input[placeholder="Enter source key ID"]', baseKeyId);

        // Switch to HKDF
        await page.locator(".ant-radio-wrapper", { hasText: "HKDF" }).click();

        // Salt (required even for HKDF)
        await page.fill('input[placeholder*="0011223344556677"]', SALT_HEX);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/derived key created with id/i);
    });
});
