/**
 * Google CMEK wrapping flow E2E tests.
 *
 * Covers:
 *   • import RSA public key with Encrypt+Wrap usage via PEM
 *   • create symmetric key with custom ID
 *   • export symmetric key in RAW format shows wrapping options (bug #1)
 *   • export symmetric key in JSON-TTLV wrapped with the imported RSA key (bug #2)
 */
import { fileURLToPath } from "url";
import path from "path";
import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    extractUuid,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// tests/e2e/ → ../../ → ui/ → ../ → repo root
const RSA_PEM_PATH = path.resolve(__dirname, "../../../test_data/google_cmek/Import_RSA_AES_WRAP.pem");

test.describe("Google CMEK wrapping flow", () => {
    const rsaTag = `e2e-rsa-wrap-${Date.now()}`;
    const symKeyId = `e2e-sym-${Date.now()}`;

    test("import RSA key with Encrypt and Wrap usage, create sym key, then export wrapped", async ({ page }) => {
        // ── Step 1: Import RSA public key with Encrypt + WrapKey usage ───────
        await gotoAndWait(page, "/ui/rsa/keys/import");
        await page.setInputFiles('input[type="file"]', RSA_PEM_PATH);
        await selectOptionById(page, "#keyFormat", "PEM (auto-detect format)");

        // Select Encrypt and Wrap usage via the multi-select dropdown
        for (const label of ["Encrypt", "Wrap"]) {
            const usageSelect = page.locator("#keyUsage");
            // Click the selector area inside the Ant Design component
            const selector = usageSelect.locator(".ant-select-selector");
            if (await selector.count()) {
                await selector.click({ force: true });
            } else {
                await usageSelect.click({ force: true });
            }
            const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
            await dropdown.first().waitFor({ state: "visible", timeout: 10_000 });
            const option = dropdown.locator(".ant-select-item-option", { hasText: label }).first();
            await option.waitFor({ state: "visible", timeout: 10_000 });
            try {
                await option.scrollIntoViewIfNeeded();
                await option.click({ force: true });
            } catch {
                await option.dispatchEvent("click");
            }
            // Small delay to let Ant Design update the selection
            await page.waitForTimeout(200);
        }

        // Add tag
        const tagsInput = page.locator("#tags");
        await tagsInput.click();
        await tagsInput.pressSequentially(rsaTag, { delay: 30 });
        await page.keyboard.press("Enter");

        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);

        // Extract RSA key ID
        const rsaKeyId = extractUuid(importText);
        expect(rsaKeyId).not.toBeNull();

        // ── Step 2: Create symmetric key with custom ID ──────────────────────
        await gotoAndWait(page, "/ui/sym/keys/create");
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
        await page.fill('input[placeholder="Enter key ID"]', symKeyId);
        const createText = await submitAndWaitForResponse(page);
        expect(createText).toMatch(/has been created/i);

        // ── Step 3: Verify wrapping options are visible in RAW export ────────
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', symKeyId);
        await selectOptionById(page, "#keyFormat", "Raw");
        // Wrapping options section should still be visible
        const wrapKeyInput = page.locator('input[placeholder="Enter wrap key ID"]');
        await expect(wrapKeyInput).toBeVisible({ timeout: UI_READY_TIMEOUT });

        // ── Step 4: Export JSON-TTLV wrapped with RSA AES Key Wrap ───────────
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', symKeyId);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        await page.fill('input[placeholder="Enter wrap key ID"]', rsaKeyId!);
        await selectOptionById(page, "#wrappingAlgorithm", "RSA AES Key Wrap");

        const { text: exportText } = await submitAndWaitForDownload(page);
        expect(exportText).toMatch(/File has been exported/i);
    });
});
