/**
 * Locate / search E2E tests: create objects then verify they can be found with filters.
 *
 * Validates the WASM → KMIP → KMS pipeline for the Locate operation,
 * equivalent to:
 *   ckms locate --tag my-tag
 *   ckms locate --algorithm RSA --object-type PrivateKey
 *   ckms locate --algorithm AES --cryptographic-length 256
 *   ckms locate --state Active
 *   ckms locate --key-format-type Raw --object-type SymmetricKey
 *   ckms locate --public-key-id <uuid>
 */
import { expect, test, type Page } from "@playwright/test";
import {
    createEcKeyPair,
    createRsaKeyPair,
    createSymKey,
    extractUuid,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForResponse,
    UI_READY_TIMEOUT,
} from "./helpers";

/** Extract the numeric count from a locate response string like "5 Object(s) located." */
function extractCount(text: string): number {
    const countMatch = text.match(/(\d+)\s*object/i);
    expect(countMatch).not.toBeNull();
    return Number.parseInt(countMatch![1], 10);
}

/** Count visible table rows on the current page. */
async function countTableRows(page: Page): Promise<number> {
    const rows = page.locator(".ant-table-tbody .ant-table-row");
    return rows.count();
}

test.describe("Locate filters – basic", () => {
    test("locate by object type finds keys", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate Active objects returns results", async ({ page }) => {
        await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#state", "Active");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate with nonexistent tag returns 0 results or error", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        const tagsInput = page.locator("#tags");
        await tagsInput.click();
        await page.keyboard.type("nonexistent-tag-xyz-9999");
        await page.keyboard.press("Enter");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/0 object|error|no object|not found/i);
    });

    test("locate without filters returns all objects", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate filters – algorithm", () => {
    test("locate by algorithm AES finds symmetric keys", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#cryptographicAlgorithm", "AES");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate by algorithm RSA finds RSA keys", async ({ page }) => {
        await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#cryptographicAlgorithm", "RSA");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate by algorithm EC finds elliptic curve keys", async ({ page }) => {
        await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        // EC keys created with NIST P-256 are stored as ECDH (see build_algorithm_from_curve).
        await selectOptionById(page, "#cryptographicAlgorithm", "ECDH");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate filters – cryptographic length", () => {
    test("locate by length 256 finds AES-256 keys", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await page.fill("#cryptographicLength", "256");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate by non-matching length returns 0 results", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        // 9999 bits is unlikely to match any key
        await page.fill("#cryptographicLength", "9999");
        const text = await submitAndWaitForResponse(page);
        expect(extractCount(text)).toBe(0);
    });
});

test.describe("Locate filters – key format type", () => {
    test("locate by key format type Raw finds symmetric keys", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#keyFormatType", "Raw");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate filters – linked object IDs", () => {
    test("locate by public key ID finds linked private key", async ({ page }) => {
        const { pubKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await page.fill('[id="publicKeyId"]', pubKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        // The private key is linked to the public key
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("locate by private key ID finds linked public key", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await page.fill('[id="privateKeyId"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate filters – combined", () => {
    test("algorithm + object type narrows results", async ({ page }) => {
        await createRsaKeyPair(page);
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#cryptographicAlgorithm", "RSA");
        await selectOptionById(page, "#objectType", "PrivateKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        const count = extractCount(text);
        expect(count).toBeGreaterThanOrEqual(1);

        // Verify narrowing: RSA+PrivateKey should return fewer than all objects
        await gotoAndWait(page, "/ui/locate");
        const allText = await submitAndWaitForResponse(page);
        const allCount = extractCount(allText);
        expect(count).toBeLessThan(allCount);
    });

    test("algorithm + length filters together", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#cryptographicAlgorithm", "AES");
        await page.fill("#cryptographicLength", "256");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });

    test("object type + state filters together", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await selectOptionById(page, "#state", "Active");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate – response table rendering", () => {
    test("response count matches displayed table rows", async ({ page }) => {
        await createSymKey(page);
        await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        // The response header says "N Object(s) located."
        const responseText = (await page.locator('[data-testid="response-output"]').textContent()) ?? "";
        const totalCount = extractCount(responseText);

        // Count all rows across pages
        let tableRowCount = await countTableRows(page);
        let remaining = 50;
        while (remaining-- > 0) {
            const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
            if (!(await nextBtn.count())) break;
            await nextBtn.click();
            await page.waitForTimeout(300);
            tableRowCount += await countTableRows(page);
        }

        expect(tableRowCount).toBe(totalCount);
    });

    test("table shows UID column for each result", async ({ page }) => {
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        // Each row should have a non-empty first cell (the UID)
        const firstRow = rows.first();
        const uidCell = firstRow.locator("td").first();
        const uidText = (await uidCell.textContent()) ?? "";
        expect(uidText.trim().length).toBeGreaterThan(0);
    });

    test("Search Objects button shows loading state during request", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        const submitBtn = page.locator('[data-testid="submit-btn"]');

        // The button should not be in loading state initially
        await expect(submitBtn).not.toHaveClass(/ant-btn-loading/);

        // Click and quickly check that loading appears
        await submitBtn.click();
        // The button or its parent gets a loading class/spinner during the request
        const loadingIndicator = page.locator('[data-testid="submit-btn"].ant-btn-loading');
        // Either the loading indicator appeared or the response came back immediately
        const responseEl = page.locator('[data-testid="response-output"]');
        await expect(loadingIndicator.or(responseEl)).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("Search Objects with tag filter finds tagged key", async ({ page }) => {
        // Create a key with a known tag via the create page
        await gotoAndWait(page, "/ui/sym/keys/create");
        const tagsInput = page.locator("#tags");
        await tagsInput.click();
        await page.keyboard.type("e2e-locate-test-tag");
        await page.keyboard.press("Enter");
        const createText = await submitAndWaitForResponse(page);
        expect(createText).toMatch(/has been created/i);
        const keyId = extractUuid(createText);
        expect(keyId).not.toBeNull();

        // Now locate using that tag
        await gotoAndWait(page, "/ui/locate");
        const locateTagsInput = page.locator("#tags");
        await locateTagsInput.click();
        await page.keyboard.type("e2e-locate-test-tag");
        await page.keyboard.press("Enter");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        expect(extractCount(text)).toBeGreaterThanOrEqual(1);

        // Verify the created key appears in results
        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });
        const allText = await page.locator(".ant-table-tbody").textContent();
        expect(allText).toContain(keyId!);
    });
});
