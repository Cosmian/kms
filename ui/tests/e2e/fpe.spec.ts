/**
 * FPE (Format-Preserving Encryption) E2E tests
 *
 * Validates the full UI → WASM → KMIP → KMS pipeline for FPE:
 *   - Key creation (256-bit AES FPE-FF1)
 *   - Encrypt via KMIP Encrypt with FPE_FF1 CryptographicParameters
 *   - Decrypt via KMIP Decrypt with FPE_FF1 CryptographicParameters
 *   - Roundtrip: encrypt then decrypt returns the original plaintext
 *
 * FPE keys are symmetric keys created with CryptographicAlgorithm::FPE_FF1.
 * Encrypt/Decrypt use the same KMIP operations as symmetric but with
 * FPE-specific CryptographicParameters and authenticated_data that encodes
 * the data type and alphabet.
 *
 * Skipped in FIPS mode: FPE is gated behind #[cfg(feature = "non-fips")].
 */
import { expect, test } from "@playwright/test";
import { extractUuid, gotoAndWait, selectOption, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

// ── Navigation smoke tests ─────────────────────────────────────────────────

test.describe("FPE navigation", () => {
    const pages = [
        { name: "keys/create", path: "/ui/fpe/keys/create" },
        { name: "keys/export", path: "/ui/fpe/keys/export" },
        { name: "keys/import", path: "/ui/fpe/keys/import" },
        { name: "keys/revoke", path: "/ui/fpe/keys/revoke" },
        { name: "keys/destroy", path: "/ui/fpe/keys/destroy" },
        { name: "encrypt", path: "/ui/fpe/encrypt" },
        { name: "decrypt", path: "/ui/fpe/decrypt" },
    ];

    for (const { name, path } of pages) {
        test(`navigate to FPE ${name} page`, async ({ page }) => {
            test.skip(FIPS_MODE, "FPE not available in FIPS mode");
            await gotoAndWait(page, path);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({
                timeout: UI_READY_TIMEOUT,
            });
        });
    }
});

// ── Key creation ───────────────────────────────────────────────────────────

test.describe("FPE — Key Creation", () => {
    test("create FPE key returns a UUID", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        await gotoAndWait(page, "/ui/fpe/keys/create");
        const text = await submitAndWaitForResponse(page);
        const uuid = extractUuid(text);
        expect(uuid).not.toBeNull();
        expect(text).toMatch(/has been created/);
    });
});

// ── Encrypt / Decrypt roundtrip ────────────────────────────────────────────

test.describe("FPE — Encrypt + Decrypt roundtrip", () => {
    test("encrypt text and decrypt returns original value", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        // Step 1: Create an FPE key
        await gotoAndWait(page, "/ui/fpe/keys/create");
        const createText = await submitAndWaitForResponse(page);
        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        // Step 2: Encrypt a credit card-like number
        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("1234567890123456");
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        // Data type defaults to text, alphabet to alpha_numeric.
        // Switch alphabet to numeric for digit-only text.
        await page.click('[data-testid="fpe-alphabet-select"]');
        await page.locator('.ant-select-dropdown :text("Numeric (0-9)")').first().click();

        const encText = await submitAndWaitForResponse(page);
        expect(encText).toMatch(/Ciphertext:/);
        // Extract the ciphertext value
        const ciphertextMatch = encText.match(/Ciphertext:\s*(\S+)/);
        expect(ciphertextMatch).not.toBeNull();
        const ciphertext = ciphertextMatch![1];
        // FPE preserves length
        expect(ciphertext.length).toBe("1234567890123456".length);
        // Ciphertext should differ from plaintext
        expect(ciphertext).not.toBe("1234567890123456");

        // Step 3: Decrypt
        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill(ciphertext);
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        // Same alphabet
        await page.click('[data-testid="fpe-alphabet-select"]');
        await page.locator('.ant-select-dropdown :text("Numeric (0-9)")').first().click();

        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/Plaintext:\s*1234567890123456/);
    });
});

// ── Tweak validation ───────────────────────────────────────────────────────

test.describe("FPE — Tweak validation", () => {
    test("encrypt rejects odd-length tweak", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("hello");
        await page.fill('input[placeholder="e.g. aabbccdd"]', "abc"); // odd length
        await page.locator('[data-testid="submit-btn"]').click();
        await expect(page.locator("text=even number of hex digits")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("encrypt rejects non-hex tweak", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("hello");
        await page.fill('input[placeholder="e.g. aabbccdd"]', "xxyyzz"); // non-hex chars
        await page.locator('[data-testid="submit-btn"]').click();
        await expect(page.locator("text=only hex characters")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("decrypt rejects odd-length tweak", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill("hello");
        await page.fill('input[placeholder="e.g. aabbccdd"]', "abc"); // odd length
        await page.locator('[data-testid="submit-btn"]').click();
        await expect(page.locator("text=even number of hex digits")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("decrypt rejects non-hex tweak", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill("hello");
        await page.fill('input[placeholder="e.g. aabbccdd"]', "xxyyzz"); // non-hex chars
        await page.locator('[data-testid="submit-btn"]').click();
        await expect(page.locator("text=only hex characters")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("encrypt + decrypt roundtrip with valid even-length hex tweak", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        // Create key
        await gotoAndWait(page, "/ui/fpe/keys/create");
        const createText = await submitAndWaitForResponse(page);
        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        const tweak = "deadbeef";

        // Encrypt with tweak
        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("1234567890");
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await page.click('[data-testid="fpe-alphabet-select"]');
        await page.locator('.ant-select-dropdown :text("Numeric (0-9)")').first().click();
        await page.fill('input[placeholder="e.g. aabbccdd"]', tweak);
        const encText = await submitAndWaitForResponse(page);
        expect(encText).toMatch(/Ciphertext:/);
        const ciphertextMatch = encText.match(/Ciphertext:\s*(\S+)/);
        expect(ciphertextMatch).not.toBeNull();
        const ciphertext = ciphertextMatch![1];

        // Decrypt with same tweak
        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill(ciphertext);
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await page.click('[data-testid="fpe-alphabet-select"]');
        await page.locator('.ant-select-dropdown :text("Numeric (0-9)")').first().click();
        await page.fill('input[placeholder="e.g. aabbccdd"]', tweak);
        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/Plaintext:\s*1234567890/);
    });
});

// ── Integer data type roundtrip ────────────────────────────────────────────

test.describe("FPE — Integer data type", () => {
    test("encrypt integer and decrypt returns original value", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        // Create an FPE key
        await gotoAndWait(page, "/ui/fpe/keys/create");
        const createText = await submitAndWaitForResponse(page);
        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        // Encrypt with integer data type
        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("12345678901");
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await selectOption(page, "fpe-datatype-select", "Integer");

        const encText = await submitAndWaitForResponse(page);
        expect(encText).toMatch(/Ciphertext:/);
        const ciphertextMatch = encText.match(/Ciphertext:\s*(\S+)/);
        expect(ciphertextMatch).not.toBeNull();
        const ciphertext = ciphertextMatch![1];
        expect(ciphertext).not.toBe("12345678901");

        // Decrypt
        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill(ciphertext);
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await selectOption(page, "fpe-datatype-select", "Integer");

        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/Plaintext:\s*12345678901/);
    });
});

// ── Float data type roundtrip ──────────────────────────────────────────────

test.describe("FPE — Float data type", () => {
    test("encrypt float and decrypt returns original value", async ({ page }) => {
        test.skip(FIPS_MODE, "FPE not available in FIPS mode");

        // Create an FPE key
        await gotoAndWait(page, "/ui/fpe/keys/create");
        const createText = await submitAndWaitForResponse(page);
        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        // Encrypt with float data type — "3.14159265" has enough digits for the domain
        await gotoAndWait(page, "/ui/fpe/encrypt");
        await page.locator('[data-testid="fpe-plaintext"]').fill("3.14159265");
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await selectOption(page, "fpe-datatype-select", "Float");

        const encText = await submitAndWaitForResponse(page);
        expect(encText).toMatch(/Ciphertext:/);
        const ciphertextMatch = encText.match(/Ciphertext:\s*(\S+)/);
        expect(ciphertextMatch).not.toBeNull();
        const ciphertext = ciphertextMatch![1];
        expect(ciphertext).not.toBe("3.14159265");

        // Decrypt
        await gotoAndWait(page, "/ui/fpe/decrypt");
        await page.locator('[data-testid="fpe-ciphertext"]').fill(ciphertext);
        await page.fill('input[placeholder="Enter key ID"]', keyId!);
        await selectOption(page, "fpe-datatype-select", "Float");

        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/Plaintext:\s*3\.14159265/);
    });
});
