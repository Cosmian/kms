/**
 * EC key-pair flow E2E tests.
 *
 * Covers:
 *   • Create an EC key pair using the default curve (first option supplied by
 *     the WASM module).
 *   • Verify both private-key and public-key IDs are returned.
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForResponse } from "./helpers";

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
});
