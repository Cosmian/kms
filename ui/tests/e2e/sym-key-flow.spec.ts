/**
 * Symmetric-key flow E2E tests.
 *
 * Covers:
 *   • Create a symmetric key with default settings (AES-256).
 *   • Export the newly created key (json-ttlv format) and verify a file is
 *     downloaded together with the "File has been exported" response message.
 */
import { expect, test } from "@playwright/test";
import { extractUuid, gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

test.describe("Symmetric key", () => {
    test("create AES-256 key with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/create");

        // The algorithm Select is populated by WASM; wait until it shows a value.
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create AES-256 key then export as json-ttlv", async ({ page }) => {
        // ── Step 1: Create ────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/create");
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: 15_000 });

        const createText = await submitAndWaitForResponse(page);
        expect(createText).toMatch(/has been created/i);

        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        // ── Step 2: Export ────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId!);

        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });
});
