/**
 * Locate / search E2E tests: create objects then verify they can be found with filters.
 *
 * Validates the WASM → KMIP → KMS pipeline for the Locate operation,
 * equivalent to:
 *   ckms locate --tag my-tag
 *   ckms locate --algorithm RSA --object-type PrivateKey
 *   ckms locate --state Active
 */
import { expect, test } from "@playwright/test";
import { createRsaKeyPair, createSymKey, gotoAndWait, selectOptionById, submitAndWaitForResponse } from "./helpers";

test.describe("Locate filters", () => {
    test("locate by object type finds keys", async ({ page }) => {
        // Create a symmetric key so we have at least one
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        // Should find at least 1
        const countMatch = text.match(/(\d+)\s*object/i);
        expect(countMatch).not.toBeNull();
        expect(Number.parseInt(countMatch![1], 10)).toBeGreaterThanOrEqual(1);
    });

    test("locate Active objects returns results", async ({ page }) => {
        // Create an RSA key pair to make sure there are Active objects
        await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#state", "Active");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        const countMatch = text.match(/(\d+)\s*object/i);
        expect(countMatch).not.toBeNull();
        expect(Number.parseInt(countMatch![1], 10)).toBeGreaterThanOrEqual(1);
    });

    test("locate with nonexistent tag returns 0 results or error", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        // Enter a tag that no object has
        const tagsInput = page.locator("#tags");
        await tagsInput.click();
        await page.keyboard.type("nonexistent-tag-xyz-9999");
        await page.keyboard.press("Enter");
        const text = await submitAndWaitForResponse(page);
        // Should either show 0 results or an error
        expect(text).toMatch(/0 object|error|no object|not found/i);
    });

    test("locate without filters returns all objects", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        const countMatch = text.match(/(\d+)\s*object/i);
        expect(countMatch).not.toBeNull();
        expect(Number.parseInt(countMatch![1], 10)).toBeGreaterThanOrEqual(1);
    });
});
