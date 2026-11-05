/**
 * Symmetric-key flow E2E tests.
 *
 * Covers:
 *   • create  (AES-256, default settings)
 *   • export  (json-ttlv download)
 *   • import  (round-trip: export then import the same file)
 *   • activate (rejected when already Active; succeeds on a Pre-Active key)
 *   • activate from the Locate table (Pre-Active row)
 *   • revoke  (requires a live key)
 *   • destroy (requires a revoked key)
 *   • navigate: encrypt, decrypt pages
 */
import { type Page, expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    createSymKey,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

type TtlvNode = { tag?: string; value?: unknown };

/** Recursively overwrite the value of every `ActivationDate` TTLV node. */
function setActivationDate(node: TtlvNode, date: string, onRewrite: () => void): void {
    if (node.tag === "ActivationDate") {
        node.value = date;
        onRewrite();
    }
    if (Array.isArray(node.value)) {
        for (const child of node.value) setActivationDate(child as TtlvNode, date, onRewrite);
    }
}

/** Route KMIP Create requests so the server stores the new key Pre-Active; returns the rewrite counter. */
async function routeCreateAsPreActive(page: Page): Promise<() => number> {
    let rewritten = 0;
    await page.route("**/kmip/2_1", async (route) => {
        const body = route.request().postDataJSON() as TtlvNode | null;
        if (body?.tag !== "Create") {
            await route.continue();
            return;
        }
        setActivationDate(body, "2099-01-01T00:00:00Z", () => rewritten++);
        await route.continue({ postData: JSON.stringify(body) });
    });
    return () => rewritten;
}

test.describe("Symmetric key", () => {
    test("create AES-256 key with default settings", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/create");
        // The algorithm Select is populated by WASM; wait until it shows a value.
        await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create AES-256 key then export as json-ttlv", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("export then import sym key", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Export ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
    });

    test("revoke and destroy sym key", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Revoke ──────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Destroy ─────────────────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/keys/destroy");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const destroyText = await submitAndWaitForResponse(page);
        expect(destroyText).toMatch(/destroyed/i);
    });

    test("activate an already-active sym key is rejected", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/activate");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Wrong_Key_Lifecycle_State|already in Active/i);
    });

    test("activate a pre-active sym key", async ({ page }) => {
        // A future ActivationDate makes the server store the key Pre-Active.
        const rewritten = await routeCreateAsPreActive(page);
        const keyId = await createSymKey(page);
        await page.unroute("**/kmip/2_1");
        expect(rewritten(), "no ActivationDate node found in the Create request").toBeGreaterThan(0);

        await gotoAndWait(page, "/ui/sym/keys/activate");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        expect(await submitAndWaitForResponse(page)).toMatch(/has been activated/i);

        // Second activation must fail: proves the state really changed to Active.
        await gotoAndWait(page, "/ui/sym/keys/activate");
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        expect(await submitAndWaitForResponse(page)).toMatch(/Wrong_Key_Lifecycle_State|already in Active/i);
    });

    test("activate a pre-active sym key from the Locate table", async ({ page }) => {
        const tag = `e2e-locate-activate-${Date.now()}`;
        const rewritten = await routeCreateAsPreActive(page);

        await gotoAndWait(page, "/ui/sym/keys/create");
        await page.locator("#tags").click();
        await page.keyboard.type(tag);
        await page.keyboard.press("Enter");
        await expect(page.getByText(tag, { exact: true }).last()).toBeVisible({ timeout: UI_READY_TIMEOUT });
        const createText = await submitAndWaitForResponse(page);
        expect(createText).toMatch(/has been created/i);
        const keyId = createText.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i)![0];
        await page.unroute("**/kmip/2_1");
        expect(rewritten(), "no ActivationDate node found in the Create request").toBeGreaterThan(0);

        await gotoAndWait(page, "/ui/locate");
        await page.locator("#tags").click();
        await page.keyboard.type(tag);
        await page.keyboard.press("Enter");
        await expect(page.getByText(tag, { exact: true }).last()).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await submitAndWaitForResponse(page);

        const row = page.locator(".ant-table-tbody .ant-table-row", { hasText: keyId });
        const activateBtn = row.getByRole("button", { name: "Activate", exact: true });
        await expect(activateBtn).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await activateBtn.click();

        await expect(page.locator('[data-testid="response-output"]')).toContainText("Action completed.", {
            timeout: UI_READY_TIMEOUT,
        });
        await expect(activateBtn).toHaveCount(0, { timeout: UI_READY_TIMEOUT });
    });

    test("navigate to sym encrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/encrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("navigate to sym decrypt page", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/decrypt");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
