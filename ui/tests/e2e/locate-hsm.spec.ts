/**
 * Locate E2E tests for mixed HSM + software key scenarios.
 *
 * Covers:
 *   - Software-only keys appear when no HSM is configured (regression baseline)
 *   - HSM keys (hsm:: prefix) appear alongside software keys in real Locate results
 *   - HSM keys always show Active state; no Unknown state appears
 *   - State filtering includes HSM keys correctly
 *   - No-criteria Locate includes HSM keys with Active state
 *
 * The HSM tests target a real KMS server backed by SoftHSM2 and require:
 *   PLAYWRIGHT_KMS_HAS_HSM=true   set by test_ui_hsm.sh
 *   PLAYWRIGHT_HSM_TEST_TAG       tag used for pre-created keys (default "_pw_hsm_locate")
 *   PLAYWRIGHT_HSM_KEY_COUNT      number of HSM keys created beforehand (default 2)
 *   PLAYWRIGHT_SW_KEY_COUNT       number of software keys created beforehand (default 2)
 *
 * The test_ui_hsm.sh script:
 *   1. Starts a fresh KMS server backed by SoftHSM2 on http://127.0.0.1:9998
 *   2. Pre-creates HSM_KEY_COUNT HSM AES-256 keys and SW_KEY_COUNT software AES-256 keys
 *      all tagged with PLAYWRIGHT_HSM_TEST_TAG
 *   3. Starts a Vite preview server on http://127.0.0.1:5173
 *   4. Runs this spec
 */
import { expect, Page, test } from "@playwright/test";
import { createSymKey, gotoAndWait, selectOptionById, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

type GlobalWithProcess = typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
};
const _env = (globalThis as GlobalWithProcess).process?.env ?? {};

const TEST_TAG = _env.PLAYWRIGHT_HSM_TEST_TAG ?? "_pw_hsm_locate";
const HSM_KEY_COUNT = parseInt(_env.PLAYWRIGHT_HSM_KEY_COUNT ?? "2", 10);
const SW_KEY_COUNT = parseInt(_env.PLAYWRIGHT_SW_KEY_COUNT ?? "2", 10);
const TOTAL_KEY_COUNT = HSM_KEY_COUNT + SW_KEY_COUNT;

/**
 * Type a value into the Ant Design tags-mode Select for the "Tags" form field
 * and confirm the entry with Enter. The resulting pill must appear before returning.
 */
async function enterLocateTag(page: Page, tag: string): Promise<void> {
    await page.locator('[id="tags"] .ant-select-selector').click();
    await page.keyboard.type(tag);
    await page.keyboard.press("Enter");
    await expect(page.locator(".ant-select-selection-item-content", { hasText: tag })).toBeVisible({ timeout: 5_000 });
}

test.describe("Locate – software keys only (no HSM)", () => {
    test("locate finds software keys and no hsm:: UIDs", async ({ page }) => {
        await createSymKey(page);
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);
        const countMatch = text.match(/(\d+)\s*object/i);
        expect(countMatch).not.toBeNull();
        expect(Number.parseInt(countMatch![1], 10)).toBeGreaterThanOrEqual(1);
        // The real server has no HSM configured, so no hsm:: UIDs should appear
        expect(text).not.toContain("hsm::");
    });

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

test.describe("Locate – mixed HSM + software keys (real SoftHSM2)", () => {
    test.beforeEach(() => {
        if (!_env.PLAYWRIGHT_KMS_HAS_HSM) {
            test.skip(true, "PLAYWRIGHT_KMS_HAS_HSM not set; skipping real SoftHSM2 HSM tests");
        }
    });

    test("locate by tag finds all pre-created HSM and software keys", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await enterLocateTag(page, TEST_TAG);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);

        // Wait for asynchronous state enrichment to finish
        await page.waitForLoadState("networkidle");

        const rows = page.locator(".ant-table-tbody .ant-table-row");
        const count = await rows.count();
        expect(count).toBeGreaterThanOrEqual(TOTAL_KEY_COUNT);
    });

    test("HSM keys show Active state and no key shows Unknown state", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await enterLocateTag(page, TEST_TAG);
        await submitAndWaitForResponse(page);

        // Wait for enrichment (supplementStateFromOwned) to finish
        await page.waitForLoadState("networkidle");

        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        let hsmActiveCount = 0;
        let unknownCount = 0;
        const rowCount = await rows.count();
        for (let i = 0; i < rowCount; i++) {
            const row = rows.nth(i);
            const uidText = (await row.locator("td").first().textContent()) ?? "";
            const stateText = (await row.locator(".ant-tag").textContent()) ?? "";
            if (uidText.startsWith("hsm::") && stateText === "Active") {
                hsmActiveCount++;
            }
            if (stateText === "Unknown") {
                unknownCount++;
            }
        }

        expect(hsmActiveCount).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
        expect(unknownCount).toBe(0);
    });

    test("Active state filter returns both HSM and software keys", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await enterLocateTag(page, TEST_TAG);
        await selectOptionById(page, "#state", "Active");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);

        await page.waitForLoadState("networkidle");

        const rows = page.locator(".ant-table-tbody .ant-table-row");
        const count = await rows.count();
        expect(count).toBeGreaterThanOrEqual(TOTAL_KEY_COUNT);
    });

    test("no-filter Locate includes HSM keys with Active state", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await submitAndWaitForResponse(page);

        // The no-criteria path calls supplementStateFromOwned asynchronously;
        // networkidle ensures the follow-up GET /access/owned round-trip is done.
        await page.waitForLoadState("networkidle");

        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        let hsmActiveCount = 0;
        const rowCount = await rows.count();
        for (let i = 0; i < rowCount; i++) {
            const row = rows.nth(i);
            const uidText = (await row.locator("td").first().textContent()) ?? "";
            const stateText = (await row.locator(".ant-tag").textContent()) ?? "";
            if (uidText.startsWith("hsm::") && stateText === "Active") {
                hsmActiveCount++;
            }
        }
        expect(hsmActiveCount).toBeGreaterThanOrEqual(HSM_KEY_COUNT);
    });
});
