/**
 * Attributes flow E2E tests.
 *
 * Covers:
 *   • navigate to get / set / delete / modify attribute pages (heading check)
 *   • get attributes of a freshly created symmetric key
 *   • link attributes (child_id): set → delete, set → modify
 *   • Name attribute (standard KMIP, fix for issue #746):
 *       - set
 *       - set → get (value readable, not hex bytes in VendorExtension)
 *       - set → modify → delete (full lifecycle)
 *   • cryptographic_length: set → get (value present) → modify
 *   • key_usage: set → delete
 *   • cryptographic_algorithm: set
 *   • multiple link attributes set in one key
 *   • error handling: non-existent object ID returns a response (no UI crash)
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, gotoAndWait, selectOption, selectOptionById, submitAndWaitForResponse } from "./helpers";

test.describe("Object attributes", () => {
    // ── Navigation smoke tests ────────────────────────────────────────────────

    test("navigate to attributes get page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/get");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to attributes set page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/set");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to attributes modify page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/modify");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to attributes delete page", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/delete");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    // ── GetAttributes ─────────────────────────────────────────────────────────

    test("get attributes of a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        // Any non-empty response is valid (should include the key's algorithm, length, etc.)
        expect(text.length).toBeGreaterThan(0);
    });

    // ── child_id link attribute ───────────────────────────────────────────────

    test("set and delete a child_id attribute on a key", async ({ page }) => {
        const keyId = await createSymKey(page);
        const placeholder = "00000000-0000-0000-0000-000000000001";

        // Set attribute ────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', placeholder);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Delete attribute ─────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Child ID link");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);
    });

    test("set then modify a child_id attribute on a key", async ({ page }) => {
        const keyId = await createSymKey(page);
        const initialId = "00000000-0000-0000-0000-000000000002";
        const modifiedId = "00000000-0000-0000-0000-000000000003";

        // Set initial attribute ────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', initialId);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Modify attribute to a new value ──────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/modify");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', modifiedId);
        const modifyText = await submitAndWaitForResponse(page);
        expect(modifyText).toMatch(/Attribute has been modified for/i);
    });

    // ── Name attribute (standard KMIP — fix for issue #746) ──────────────────
    //
    // Before the fix, using --attribute-name Name stored the value as a
    // VendorAttribute (hex bytes), not as the standard KMIP Name attribute.
    // These tests verify the correct end-to-end behaviour: the Name attribute
    // must be readable as plain text, not hidden inside VendorExtension.

    test("set a Name attribute on a symmetric key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        await page.fill('input[placeholder="Enter object name"]', "e2e-test-key-name");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);
    });

    test("Name attribute is stored as standard KMIP attribute: value readable in get response", async ({ page }) => {
        const keyId = await createSymKey(page);
        const nameValue = "e2e-kmip-name-readable";

        // Set ──────────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        await page.fill('input[placeholder="Enter object name"]', nameValue);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Get ──────────────────────────────────────────────────────────────────
        // The name must appear as readable text (not hex bytes buried in
        // VendorExtension, which was the pre-fix behaviour).
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getText = await submitAndWaitForResponse(page);
        expect(getText).toContain(nameValue);
    });

    test("Name attribute full lifecycle: set → modify → get → delete", async ({ page }) => {
        const keyId = await createSymKey(page);
        const initialName = "initial-name-e2e";
        const modifiedName = "modified-name-e2e";

        // Set ──────────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        await page.fill('input[placeholder="Enter object name"]', initialName);
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Modify ───────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/modify");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        await page.fill('input[placeholder="Enter object name"]', modifiedName);
        const modifyText = await submitAndWaitForResponse(page);
        expect(modifyText).toMatch(/Attribute has been modified for/i);

        // Get: modified name must be present, initial name must be gone ─────────
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getAfterModify = await submitAndWaitForResponse(page);
        expect(getAfterModify).toContain(modifiedName);
        expect(getAfterModify).not.toContain(initialName);

        // Delete ───────────────────────────────────────────────────────────────
        // Deletes all Name entries on the object (by tag reference).
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);
    });

    test("set Name attribute then delete it: get response no longer contains name", async ({ page }) => {
        const keyId = await createSymKey(page);
        const nameValue = "transient-name-e2e";

        // Set
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        await page.fill('input[placeholder="Enter object name"]', nameValue);
        await submitAndWaitForResponse(page);

        // Delete
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Name");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);

        // Get: name must no longer appear
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getAfterDelete = await submitAndWaitForResponse(page);
        expect(getAfterDelete).not.toContain(nameValue);
    });

    // ── Cryptographic Length ──────────────────────────────────────────────────

    test("set and modify a cryptographic_length attribute", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Set to 128 ───────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Cryptographic Length");
        await page.locator('input[type="number"]').fill("128");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Get: verify value is 128 ─────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getAfterSet = await submitAndWaitForResponse(page);
        expect(getAfterSet).toContain("128");

        // Modify to 256 ────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/modify");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Cryptographic Length");
        await page.locator('input[type="number"]').fill("256");
        const modifyText = await submitAndWaitForResponse(page);
        expect(modifyText).toMatch(/Attribute has been modified for/i);

        // Get: verify value is now 256 ─────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getAfterModify = await submitAndWaitForResponse(page);
        expect(getAfterModify).toContain("256");
    });

    // ── Key Usage ─────────────────────────────────────────────────────────────

    test("set and delete a key_usage attribute", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Set usage to Encrypt ─────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Key Usage");
        await selectOptionById(page, "#attribute_value", "Encrypt");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Delete by CryptographicUsageMask tag ────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/delete");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Key Usage");
        const deleteText = await submitAndWaitForResponse(page);
        expect(deleteText).toMatch(/has been deleted for/i);
    });

    test("modify key_usage attribute", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Set to Sign ──────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Key Usage");
        await selectOptionById(page, "#attribute_value", "Sign");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Modify to Decrypt ────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/modify");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Key Usage");
        await selectOptionById(page, "#attribute_value", "Decrypt");
        const modifyText = await submitAndWaitForResponse(page);
        expect(modifyText).toMatch(/Attribute has been modified for/i);
    });

    // ── Cryptographic Algorithm ───────────────────────────────────────────────

    test("set a cryptographic_algorithm attribute", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Cryptographic Algorithm");

        // Wait for the algorithm select to appear and be populated by WASM
        await expect(page.locator("#attribute_value")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await selectOptionById(page, "#attribute_value", "AES");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);
    });

    test("modify cryptographic_algorithm attribute", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Set to AES ───────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Cryptographic Algorithm");
        await expect(page.locator("#attribute_value")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await selectOptionById(page, "#attribute_value", "AES");
        const setText = await submitAndWaitForResponse(page);
        expect(setText).toMatch(/Attribute has been set for/i);

        // Modify (re-set to AES to verify the modify API works) ───────────────
        await gotoAndWait(page, "/ui/attributes/modify");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Cryptographic Algorithm");
        await expect(page.locator("#attribute_value")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await selectOptionById(page, "#attribute_value", "AES");
        const modifyText = await submitAndWaitForResponse(page);
        expect(modifyText).toMatch(/Attribute has been modified for/i);
    });

    // ── Multiple link attributes on a single key ──────────────────────────────

    test("set multiple link attributes (public_key_id and certificate_id) on a key", async ({ page }) => {
        const keyId = await createSymKey(page);
        const pubKeyId = "00000000-0000-0000-0000-000000000010";
        const certId = "00000000-0000-0000-0000-000000000011";

        // Set public_key_id ────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Public Key ID link");
        await page.fill('input[placeholder="Enter ID value"]', pubKeyId);
        const setPubKey = await submitAndWaitForResponse(page);
        expect(setPubKey).toMatch(/Attribute has been set for/i);

        // Set certificate_id ───────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        await selectOption(page, "attribute-name-select", "Certificate ID link");
        await page.fill('input[placeholder="Enter ID value"]', certId);
        const setCert = await submitAndWaitForResponse(page);
        expect(setCert).toMatch(/Attribute has been set for/i);

        // Get: both IDs must appear in response ────────────────────────────────
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', keyId);
        const getText = await submitAndWaitForResponse(page);
        expect(getText).toContain(pubKeyId);
        expect(getText).toContain(certId);
    });

    // ── Error handling ────────────────────────────────────────────────────────

    test("get attributes with non-existent object ID returns a response without crashing", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/get");
        await page.fill('input[placeholder="Enter object ID"]', "00000000-0000-0000-0000-000000000000");
        const text = await submitAndWaitForResponse(page);
        // UI must not crash; it must show something (error message or empty result).
        expect(text.length).toBeGreaterThan(0);
    });

    test("set attribute with non-existent object ID returns an error response", async ({ page }) => {
        await gotoAndWait(page, "/ui/attributes/set");
        await page.fill('input[placeholder="Enter object ID"]', "00000000-0000-0000-0000-000000000000");
        await selectOption(page, "attribute-name-select", "Child ID link");
        await page.fill('input[placeholder="Enter ID value"]', "00000000-0000-0000-0000-000000000001");
        const text = await submitAndWaitForResponse(page);
        // Should report an error (object not found).
        expect(text.length).toBeGreaterThan(0);
        expect(text.toLowerCase()).toMatch(/error|not found|failed/i);
    });
});
