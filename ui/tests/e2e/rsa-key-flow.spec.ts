/**
 * RSA key-pair flow E2E tests.
 *
 * Covers:
 *   • Create a 4096-bit RSA key pair with default settings.
 *   • Verify both private-key and public-key IDs are returned.
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

test.describe("RSA key pair", () => {
    test("create 4096-bit RSA key pair with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/keys/create");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);

        // Both IDs should look like UUIDs.
        const ids = text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi);
        expect(ids?.length).toBeGreaterThanOrEqual(2);
    });

    test("create RSA key pair then export public key as json-ttlv", async ({ page }) => {
        // ── Step 1: Create ────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/keys/create");
        const createText = await submitAndWaitForResponse(page);
        expect(createText).toMatch(/Key pair has been created/i);

        const pubKeyId = createText.match(/Public key Id:\s*([0-9a-f-]{36})/i)?.[1];
        expect(pubKeyId).not.toBeUndefined();

        // ── Step 2: Export public key ─────────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId!);

        // Use json-ttlv (default) – no format change needed.
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });
});
