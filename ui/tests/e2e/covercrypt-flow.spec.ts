/**
 * Covercrypt flow E2E tests.
 *
 * Covers:
 *   • create master key pair (inline JSON spec)
 *   • create user decryption key
 *   • export master private key (json-ttlv download)
 *   • revoke and destroy user key
 *   • navigate: import, encrypt, decrypt pages
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, extractUuid, extractUuidAfterLabel, gotoAndWait, selectOption, submitAndWaitForDownload, submitAndWaitForResponse } from "./helpers";

/** Minimal two-axis specification JSON used by all tests. */
const SPEC_JSON = JSON.stringify({
    "Security Level::<": ["Protected", "Confidential", "Top Secret::+"],
    // Keep values aligned with test_data/access_structure_specifications.json
    Department: ["RnD", "HR", "MKG", "FIN"],
});

/** Create a Covercrypt master key pair and return { masterPrivKeyId, masterPubKeyId }. */
async function createMasterKeyPair(page: Parameters<typeof gotoAndWait>[0]) {
    await gotoAndWait(page, "/ui/cc/keys/create-master-key-pair");
    await selectOption(page, "spec-type-select", "Enter JSON Specification");
    const specTextarea = page.locator('[data-testid="spec-json-textarea"]');
    await specTextarea.waitFor({ state: "visible" });
    await specTextarea.fill(SPEC_JSON);
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const masterPrivKeyId = extractUuidAfterLabel(text, "Private key Id");
    const masterPubKeyId = extractUuidAfterLabel(text, "Public key Id");
    expect(masterPrivKeyId).not.toBeNull();
    expect(masterPubKeyId).not.toBeNull();
    return { masterPrivKeyId: masterPrivKeyId!, masterPubKeyId: masterPubKeyId! };
}

test.describe("Covercrypt", () => {
    test("create master key pair via inline JSON specification", async ({ page }) => {
        await gotoAndWait(page, "/ui/cc/keys/create-master-key-pair");

        await selectOption(page, "spec-type-select", "Enter JSON Specification");
        const specTextarea = page.locator('[data-testid="spec-json-textarea"]');
        await specTextarea.waitFor({ state: "visible" });
        await specTextarea.fill(SPEC_JSON);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Key pair has been created/i);
        expect(text).toMatch(/Private key Id:/i);
        expect(text).toMatch(/Public key Id:/i);
    });

    test("create master key pair then a user decryption key", async ({ page }) => {
        const { masterPrivKeyId } = await createMasterKeyPair(page);

        // ── Create user decryption key ────────────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/create-user-key");
        await page.fill("#masterPrivateKeyId", masterPrivKeyId);
        await page.fill("#accessPolicy", "Department::HR && Security Level::Confidential");

        const userText = await submitAndWaitForResponse(page);
        expect(userText).toMatch(/has been created/i);
    });

    test("export Covercrypt master private key", async ({ page }) => {
        const { masterPrivKeyId } = await createMasterKeyPair(page);

        await gotoAndWait(page, "/ui/cc/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', masterPrivKeyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("revoke and destroy Covercrypt user key", async ({ page }) => {
        const { masterPrivKeyId } = await createMasterKeyPair(page);

        // Create user key first ────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/create-user-key");
        await page.fill("#masterPrivateKeyId", masterPrivKeyId);
        await page.fill("#accessPolicy", "Department::HR && Security Level::Confidential");
        const userText = await submitAndWaitForResponse(page);
        const userKeyId = extractUuid(userText);
        expect(userKeyId).not.toBeNull();

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', userKeyId!);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/cc/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', userKeyId!);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("navigate to cc import page", async ({ page }) => {
        await gotoAndWait(page, "/ui/cc/keys/import");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to cc encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/cc/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to cc decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/cc/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
