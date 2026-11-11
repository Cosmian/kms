/**
 * MAC compute / verify E2E roundtrip tests (issue #786 – HMAC-SHA-1 / SHA-224 support).
 *
 * Validates the full UI → KMIP → KMS pipeline for MAC operations, equivalent to:
 *   ckms mac compute --key-id <id> --hash-fn sha256 --data 0011223344556677
 *   ckms mac verify  --key-id <id> --hash-fn sha256 --data 0011223344556677 --mac-data <hex>
 *
 * Key creation bypasses the UI (no "create HMAC key" page exists yet) and hits
 * the KMS KMIP endpoint directly via the `createHmacKey` test helper.
 */
import { expect, test } from "@playwright/test";
import { createHmacKey, gotoAndWait, selectOption, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

/** Fixed hex payload used across all tests (8 bytes). */
const DATA_HEX = "0011223344556677";

// ── Navigation smoke tests ────────────────────────────────────────────────────

test.describe("MAC navigation", () => {
    test("navigate to mac compute page", async ({ page }) => {
        await gotoAndWait(page, "/ui/mac/compute");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("navigate to mac verify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/mac/verify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });
});

// ── MAC compute ───────────────────────────────────────────────────────────────

test.describe("MAC compute", () => {
    test("compute HMAC-SHA256 returns hex MAC", async ({ page }) => {
        const keyId = await createHmacKey(page, "HMACSHA256");

        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        // Default algorithm is already SHA-256; fill the data field and submit.
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const text = await submitAndWaitForResponse(page);

        // Response must contain a non-empty hex MAC string.
        expect(text).toMatch(/MAC \(hex\):\s*[0-9a-f]+/i);
    });

    test("compute HMAC-SHA1 returns hex MAC (issue #786)", async ({ page }) => {
        const keyId = await createHmacKey(page, "HMACSHA256");

        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOption(page, "mac-algorithm-select", "SHA-1");
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/MAC \(hex\):\s*[0-9a-f]+/i);
    });

    test("compute AES-CMAC returns 16-byte hex MAC (issue #1367)", async ({ page }) => {
        const keyId = await createHmacKey(page, "AES");

        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOption(page, "mac-type-select", "AES-CMAC");
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/MAC \(hex\):\s*[0-9a-f]{32}\b/i);
    });

    test("compute without key ID shows error", async ({ page }) => {
        await gotoAndWait(page, "/ui/mac/compute");
        // Leave key ID blank; fill only data.
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const text = await submitAndWaitForResponse(page);
        // The component sets "Missing key identifier." when no key/tags given.
        expect(text).toMatch(/missing|error|key/i);
    });
});

// ── MAC compute → verify roundtrip ────────────────────────────────────────────

test.describe("MAC compute → verify roundtrip", () => {
    test("HMAC-SHA256 compute then verify returns Valid", async ({ page }) => {
        const keyId = await createHmacKey(page, "HMACSHA256");

        // ── Step 1: Compute MAC ─────────────────────────────────────────────
        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const computeText = await submitAndWaitForResponse(page);
        expect(computeText).toMatch(/MAC \(hex\):\s*[0-9a-f]+/i);

        const macMatch = computeText.match(/MAC \(hex\):\s*([0-9a-f]+)/i);
        expect(macMatch).not.toBeNull();
        const macHex = macMatch![1];

        // ── Step 2: Verify the MAC ──────────────────────────────────────────
        await gotoAndWait(page, "/ui/mac/verify");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        // Default algorithm is SHA-256; fill data and MAC value.
        await page.fill('textarea[placeholder="e.g. 0011223344556677889900"]', DATA_HEX);
        await page.fill('textarea[placeholder="e.g. F91DDB96D12CF8FA..."]', macHex);
        const verifyText = await submitAndWaitForResponse(page);

        expect(verifyText).toMatch(/valid/i);
        expect(verifyText).not.toMatch(/invalid/i);
    });

    test("HMAC-SHA1 compute then verify roundtrip (issue #786)", async ({ page }) => {
        const keyId = await createHmacKey(page, "HMACSHA256");

        // ── Compute with SHA-1 ──────────────────────────────────────────────
        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOption(page, "mac-algorithm-select", "SHA-1");
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const computeText = await submitAndWaitForResponse(page);
        expect(computeText).toMatch(/MAC \(hex\):\s*[0-9a-f]+/i);

        const macMatch = computeText.match(/MAC \(hex\):\s*([0-9a-f]+)/i);
        expect(macMatch).not.toBeNull();
        const macHex = macMatch![1];

        // ── Verify with SHA-1 ───────────────────────────────────────────────
        await gotoAndWait(page, "/ui/mac/verify");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOption(page, "mac-verify-algorithm-select", "SHA-1");
        await page.fill('textarea[placeholder="e.g. 0011223344556677889900"]', DATA_HEX);
        await page.fill('textarea[placeholder="e.g. F91DDB96D12CF8FA..."]', macHex);
        const verifyText = await submitAndWaitForResponse(page);

        expect(verifyText).toMatch(/valid/i);
        expect(verifyText).not.toMatch(/invalid/i);
    });

    test("AES-GMAC compute then verify roundtrip, tampered MAC is Invalid (issue #1367)", async ({ page }) => {
        const keyId = await createHmacKey(page, "AES");

        // ── Compute: the MAC is the 12-byte IV followed by the 16-byte tag (56 hex digits) ──
        await gotoAndWait(page, "/ui/mac/compute");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await selectOption(page, "mac-type-select", "AES-GMAC");
        await page.fill('textarea[placeholder="e.g. 0011223344556677"]', DATA_HEX);
        const computeText = await submitAndWaitForResponse(page);
        const macMatch = computeText.match(/MAC \(hex\):\s*([0-9a-f]{56})\b/i);
        expect(macMatch).not.toBeNull();
        const macHex = macMatch![1];

        // ── Verify the MAC, then a MAC whose last tag digit is changed ──────────
        const verify = async (mac: string): Promise<string> => {
            await gotoAndWait(page, "/ui/mac/verify");
            await page.fill('input[placeholder="Enter key ID"]', keyId);
            await selectOption(page, "mac-verify-type-select", "AES-GMAC");
            await page.fill('textarea[placeholder="e.g. 0011223344556677889900"]', DATA_HEX);
            await page.fill('textarea[placeholder="e.g. F91DDB96D12CF8FA..."]', mac);
            return submitAndWaitForResponse(page);
        };
        const validText = await verify(macHex);
        expect(validText).toMatch(/valid/i);
        expect(validText).not.toMatch(/invalid/i);

        const lastDigit = macHex.slice(-1) === "0" ? "1" : "0";
        const tamperedText = await verify(macHex.slice(0, -1) + lastDigit);
        expect(tamperedText).toMatch(/invalid/i);
    });

    test("verify with wrong MAC data returns Invalid", async ({ page }) => {
        const keyId = await createHmacKey(page, "HMACSHA256");
        const wrongMac = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        await gotoAndWait(page, "/ui/mac/verify");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('textarea[placeholder="e.g. 0011223344556677889900"]', DATA_HEX);
        await page.fill('textarea[placeholder="e.g. F91DDB96D12CF8FA..."]', wrongMac);
        const verifyText = await submitAndWaitForResponse(page);

        expect(verifyText).toMatch(/invalid/i);
    });
});
