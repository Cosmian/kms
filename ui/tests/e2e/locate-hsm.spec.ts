/**
 * Locate E2E tests for mixed HSM + software key scenarios.
 *
 * Covers:
 *   - HSM keys (hsm:: prefix) appear alongside software keys in Locate results
 *   - HSM keys always show Active state; no Unknown state appears
 *   - State filtering includes HSM keys correctly
 *
 * The tests require a KMS server backed by SoftHSM2 (always provided by
 * test_ui.sh, which errors out if softhsm2-util is not installed).
 * PLAYWRIGHT_HSM_KEY_COUNT sets the number of HSM keys created beforehand (default 2).
 *
 * Note: HSM keys do NOT support KMIP tags.  The HsmStore silently ignores tags
 * on creation and returns an empty set from retrieve_tags.  Therefore all HSM
 * tests use non-tag criteria (ObjectType, State) to Locate keys, and iterate
 * through all table pages to surface HSM keys that may sort far down.
 *
 * The test_ui.sh script:
 *   1. Errors out if softhsm2-util is not installed
 *   2. Starts a fresh KMS server backed by SoftHSM2 on http://127.0.0.1:9998
 *   3. Pre-creates HSM_KEY_COUNT HSM AES-256 keys
 *   4. Starts a Vite preview server on http://127.0.0.1:5173
 *   5. Runs all E2E specs
 */
import { expect, test, type Page } from "@playwright/test";
import { createSymKey, gotoAndWait, selectOptionById, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

type GlobalWithProcess = typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
};
const _env = (globalThis as GlobalWithProcess).process?.env ?? {};

const HSM_KEY_COUNT = parseInt(_env.PLAYWRIGHT_HSM_KEY_COUNT ?? "2", 10);

/**
 * Walk every page of the Ant Design Table and count HSM / Unknown rows.
 * Returns the number of hsm:: UIDs with Active state and the total entries
 * showing "Unknown" state.
 */
async function collectHsmKeysAcrossPages(page: Page): Promise<{ hsmActive: number; unknown: number }> {
    let hsmActive = 0;
    let unknown = 0;

    const scanVisibleRows = async () => {
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        const rowCount = await rows.count();
        for (let i = 0; i < rowCount; i++) {
            const row = rows.nth(i);
            const uidText = (await row.locator("td").first().textContent()) ?? "";
            const stateText = (await row.locator(".ant-tag").textContent()) ?? "";
            if (uidText.startsWith("hsm::") && stateText === "Active") hsmActive++;
            if (stateText === "Unknown") unknown++;
        }
    };

    // Scan the first page
    await scanVisibleRows();

    // Click "Next Page" until no more pages remain (safety cap at 50)
    let remaining = 50;
    while (remaining-- > 0) {
        const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
        if (!(await nextBtn.count())) break;
        await nextBtn.click();
        await page.waitForTimeout(300);
        await scanVisibleRows();
    }

    return { hsmActive, unknown };
}

test.describe("Locate – software keys alongside HSM keys", () => {
    test("locate with state Active finds software keys", async ({ page }) => {
        await createSymKey(page);
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#state", "Active");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        const countMatch = text.match(/(\d+)\s*object/i);
        expect(countMatch).not.toBeNull();
        expect(Number.parseInt(countMatch![1], 10)).toBeGreaterThanOrEqual(1);
    });
});

test.describe("Locate – HSM keys (real SoftHSM2)", () => {
    test("SymmetricKey Locate includes HSM keys with Active state", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { hsmActive, unknown } = await collectHsmKeysAcrossPages(page);
        expect(hsmActive).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
        expect(unknown).toBe(0);
    });

    test("Active state filter returns HSM keys", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#state", "Active");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { hsmActive } = await collectHsmKeysAcrossPages(page);
        expect(hsmActive).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
    });

    test("no-filter Locate includes HSM keys with Active state", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        const { hsmActive } = await collectHsmKeysAcrossPages(page);
        expect(hsmActive).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
    });
});
