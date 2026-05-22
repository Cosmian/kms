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
const HSM_AVAILABLE = HSM_KEY_COUNT > 0;
const HSM_SLOT_ID_1 = _env.PLAYWRIGHT_HSM_SLOT_ID_1 ?? "";
const HSM_SLOT_ID_2 = _env.PLAYWRIGHT_HSM_SLOT_ID_2 ?? "";
const HSM_SLOT_ID_3 = _env.PLAYWRIGHT_HSM_SLOT_ID_3 ?? "";
const HSM_MULTI_SLOT_AVAILABLE = HSM_AVAILABLE && HSM_SLOT_ID_1 !== "" && HSM_SLOT_ID_2 !== "" && HSM_SLOT_ID_3 !== "";

// mTLS certificate paths for access-control tests (set by test_ui.sh).
const CERT_DIR = _env.PLAYWRIGHT_CERT_DIR ?? "";
const KMS_URL = _env.PLAYWRIGHT_KMS_URL ?? "https://127.0.0.1:9998";
const MTLS_AVAILABLE = CERT_DIR !== "";

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
    test.skip(!HSM_AVAILABLE, "SoftHSM2 not available on this platform – skipping HSM tests");

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

test.describe("Locate – multi-HSM prefix routing (pw_locate_aes keys)", () => {
    test.skip(!HSM_MULTI_SLOT_AVAILABLE, "Multi-slot HSM env vars not set – skipping");

    test("pre-created HSM keys from all three slots appear in Locate results", async ({ page }) => {
        // Expected UID prefixes for the 3 pre-created keys (timestamp suffix is dynamic).
        const expectedPrefixes = [
            `hsm::${HSM_SLOT_ID_1}::pw_locate_aes1_`,
            `hsm::softhsm2::${HSM_SLOT_ID_2}::pw_locate_aes2_`,
            `hsm::softhsm2_1::${HSM_SLOT_ID_3}::pw_locate_aes3_`,
        ];

        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/object\(s\) located/i);

        await page.waitForLoadState("networkidle");
        const rows = page.locator(".ant-table-tbody .ant-table-row");
        await rows.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        // Collect all UIDs across all pages.
        const allUids: string[] = [];
        const collectUids = async () => {
            const visibleRows = page.locator(".ant-table-tbody .ant-table-row");
            const count = await visibleRows.count();
            for (let i = 0; i < count; i++) {
                const uid = (await visibleRows.nth(i).locator("td").first().textContent()) ?? "";
                allUids.push(uid);
            }
        };

        await collectUids();
        let remaining = 50;
        while (remaining-- > 0) {
            const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
            if (!(await nextBtn.count())) break;
            await nextBtn.click();
            await page.waitForTimeout(300);
            await collectUids();
        }

        // Assert each expected prefix is found in at least one UID.
        for (const prefix of expectedPrefixes) {
            const found = allUids.some((uid) => uid.startsWith(prefix));
            expect(found, `Expected UID starting with "${prefix}" in results`).toBe(true);
        }
    });
});

test.describe("Locate – HSM access control (mTLS user vs owner)", () => {
    test.skip(!HSM_MULTI_SLOT_AVAILABLE || !MTLS_AVAILABLE, "Multi-slot HSM or mTLS cert env vars not set – skipping");

    // Override the default client certificate to use the non-admin user cert.
    test.use({
        clientCertificates: [
            {
                origin: KMS_URL,
                certPath: `${CERT_DIR}/user/user.client.acme.com.crt`,
                keyPath: `${CERT_DIR}/user/user.client.acme.com.key`,
            },
        ],
        ignoreHTTPSErrors: true,
    });

    test("non-admin user cannot see HSM keys in Locate results", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await selectOptionById(page, "#objectType", "SymmetricKey");
        await submitAndWaitForResponse(page);

        await page.waitForLoadState("networkidle");

        // Collect all UIDs across all pages (if any results).
        const allUids: string[] = [];
        const tableBody = page.locator(".ant-table-tbody .ant-table-row");
        if ((await tableBody.count()) > 0) {
            const collectUids = async () => {
                const visibleRows = page.locator(".ant-table-tbody .ant-table-row");
                const count = await visibleRows.count();
                for (let i = 0; i < count; i++) {
                    const uid = (await visibleRows.nth(i).locator("td").first().textContent()) ?? "";
                    allUids.push(uid);
                }
            };

            await collectUids();
            let remaining = 50;
            while (remaining-- > 0) {
                const nextBtn = page.locator(".ant-pagination-next button:not([disabled])");
                if (!(await nextBtn.count())) break;
                await nextBtn.click();
                await page.waitForTimeout(300);
                await collectUids();
            }
        }

        // Non-admin user should NOT see any HSM keys (hsm:: prefix).
        const hsmKeys = allUids.filter((uid) => uid.startsWith("hsm::"));
        expect(hsmKeys, "Non-admin user should not see any HSM keys").toHaveLength(0);
    });
});
