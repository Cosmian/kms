/**
 * Covercrypt flow E2E tests.
 *
 * Covers:
 *   • Create a Covercrypt master key pair by supplying the specification as
 *     inline JSON text (avoids file-upload complexity in headless CI).
 *   • Create a Covercrypt user decryption key from the master private key ID.
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, selectOption, submitAndWaitForResponse } from "./helpers";

/** Minimal two-axis specification JSON used by both tests. */
const SPEC_JSON = JSON.stringify({
    "Security Level::<": ["Protected", "Confidential", "Top Secret::+"],
    // Keep values aligned with test_data/access_structure_specifications.json
    Department: ["RnD", "HR", "MKG", "FIN"],
});

test.describe("Covercrypt", () => {
    test("create master key pair via inline JSON specification", async ({ page }) => {
        await gotoAndWait(page, "/ui/cc/keys/create-master-key-pair");

        // Switch the spec-type select from "Upload JSON Specification File" to
        // "Enter JSON Specification" so we can type the spec without a file upload.
        await selectOption(page, "spec-type-select", "Enter JSON Specification");

        // Fill in the specification text area.
        const specTextarea = page.locator('[data-testid="spec-json-textarea"]');
        await specTextarea.waitFor({ state: "visible" });
        await specTextarea.fill(SPEC_JSON);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);
    });

    test("create master key pair then a user decryption key", async ({ page }) => {
        // ── Step 1: Create master key pair ────────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/create-master-key-pair");

        await selectOption(page, "spec-type-select", "Enter JSON Specification");
        const specTextarea = page.locator('[data-testid="spec-json-textarea"]');
        await specTextarea.waitFor({ state: "visible" });
        await specTextarea.fill(SPEC_JSON);

        const masterText = await submitAndWaitForResponse(page);
        expect(masterText).toMatch(/Key pair has been created/i);

        const masterPrivKeyId = masterText.match(/Private key Id:\s*([0-9a-f-]{36})/i)?.[1];
        expect(masterPrivKeyId).not.toBeUndefined();

        // ── Step 2: Create user decryption key ────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/create-user-key");

        // masterPrivateKeyId field (required, identified by Ant Design form id).
        await page.fill("#masterPrivateKeyId", masterPrivKeyId!);

        // Access-policy text area.
        await page.fill("#accessPolicy", "Department::HR && Security Level::Confidential");

        const userText = await submitAndWaitForResponse(page);
        expect(userText).toMatch(/has been created/i);
    });
});
