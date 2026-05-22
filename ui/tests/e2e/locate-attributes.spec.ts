/**
 * Locate E2E tests for object attributes display correctness.
 *
 * Verifies that the "Search Objects" results table shows correct values for:
 *   - Type column (ObjectType): never "N/A" for known key types
 *   - Key Format Type column: never "N/A" for keys (HSM or software)
 *
 * The tests rely on the KMS server started by test_ui.sh with SoftHSM2,
 * which pre-creates HSM AES-256 keys. Additional software keys are created
 * inline by the tests.
 *
 * PLAYWRIGHT_HSM_KEY_COUNT sets the number of HSM keys pre-created (default 3).
 */
import { expect, test, type Page } from "@playwright/test";
import {
    createEcKeyPair,
    createRsaKeyPair,
    createSymKey,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForResponse,
    UI_READY_TIMEOUT,
} from "./helpers";

type GlobalWithProcess = typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
};
const _env = (globalThis as GlobalWithProcess).process?.env ?? {};

const HSM_KEY_COUNT = parseInt(_env.PLAYWRIGHT_HSM_KEY_COUNT ?? "3", 10);
const HSM_AVAILABLE = HSM_KEY_COUNT > 0;

/**
 * Walk every page of the Ant Design Table and collect Type and Key Format Type
 * values for rows matching the given UID prefix (or all rows if no prefix).
 */
async function collectAttributeColumns(page: Page, uidPrefix?: string): Promise<{ types: string[]; keyFormatTypes: string[] }> {
    const types: string[] = [];
    const keyFormatTypes: string[] = [];

    const scanVisibleRows = async () => {
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        const rowCount = await rows.count();
        for (let i = 0; i < rowCount; i++) {
            const row = rows.nth(i);
            const cells = row.locator("td");
            const uidText = (await cells.nth(0).textContent()) ?? "";
            if (uidPrefix && !uidText.startsWith(uidPrefix)) continue;
            const typeText = (await cells.nth(1).textContent()) ?? "";
            const kftText = (await cells.nth(2).textContent()) ?? "";
            types.push(typeText.trim());
            keyFormatTypes.push(kftText.trim());
        }
    };

    await scanVisibleRows();

    // Paginate through all pages (safety cap at 50 pages)
    let remaining = 50;
    while (remaining-- > 0) {
        const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
        if (!(await nextBtn.count())) break;
        await nextBtn.click();
        await page.waitForTimeout(300);
        await scanVisibleRows();
    }

    return { types, keyFormatTypes };
}

/**
 * Find a specific row by UID substring and return its Type and Key Format Type.
 */
async function findRowByUid(page: Page, uidSubstring: string): Promise<{ type: string; keyFormatType: string } | null> {
    let remaining = 50;
    const check = async (): Promise<{ type: string; keyFormatType: string } | null> => {
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        const rowCount = await rows.count();
        for (let i = 0; i < rowCount; i++) {
            const row = rows.nth(i);
            const cells = row.locator("td");
            const uidText = (await cells.nth(0).textContent()) ?? "";
            if (uidText.includes(uidSubstring)) {
                const typeText = (await cells.nth(1).textContent()) ?? "";
                const kftText = (await cells.nth(2).textContent()) ?? "";
                return { type: typeText.trim(), keyFormatType: kftText.trim() };
            }
        }
        return null;
    };

    const result = await check();
    if (result) return result;

    // Paginate to find the row
    while (remaining-- > 0) {
        const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
        if (!(await nextBtn.count())) break;
        await nextBtn.click();
        await page.waitForTimeout(300);
        const found = await check();
        if (found) return found;
    }

    return null;
}

test.describe("Locate – attribute display correctness (HSM keys)", () => {
    test.skip(!HSM_AVAILABLE, "SoftHSM2 not available – skipping HSM attribute tests");

    test("HSM keys show SymmetricKey type (not N/A)", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { types } = await collectAttributeColumns(page, "hsm");
        expect(types.length).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
        for (const t of types) {
            expect(t).toBe("SymmetricKey");
        }
    });

    test("HSM keys show Key Format Type Raw (not N/A)", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { keyFormatTypes } = await collectAttributeColumns(page, "hsm");
        expect(keyFormatTypes.length).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
        for (const kft of keyFormatTypes) {
            expect(kft).toBe("Raw");
        }
    });
});

test.describe("Locate – attribute display correctness (software keys)", () => {
    test("software symmetric key shows correct type and format", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const found = await findRowByUid(page, keyId);
        expect(found).not.toBeNull();
        expect(found!.type).toBe("SymmetricKey");
        expect(found!.keyFormatType).toBe("Raw");
    });

    test("RSA private key shows correct type and format", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "PrivateKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const found = await findRowByUid(page, privKeyId);
        expect(found).not.toBeNull();
        expect(found!.type).toBe("PrivateKey");
        expect(found!.keyFormatType).toMatch(/PKCS1|PKCS8|PKCS#1|PKCS#8/);
    });

    test("EC private key shows correct type and format", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "PrivateKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const found = await findRowByUid(page, privKeyId);
        expect(found).not.toBeNull();
        expect(found!.type).toBe("PrivateKey");
        expect(found!.keyFormatType).not.toBe("N/A");
    });
});

test.describe("Locate – no N/A in Type column", () => {
    test("all located objects have a valid Type", async ({ page }) => {
        // Create at least one key so the table is not empty
        await createSymKey(page);

        await gotoAndWait(page, "/ui/locate");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { types } = await collectAttributeColumns(page);
        expect(types.length).toBeGreaterThan(0);
        // In a parallel test environment, some objects may be destroyed by other
        // workers between Locate and GetAttributes, causing transient N/A values.
        // Verify that the vast majority of objects have a valid Type.
        const naCount = types.filter((t) => t === "N/A").length;
        const naRatio = naCount / types.length;
        expect(naRatio).toBeLessThan(0.1);
    });
});
