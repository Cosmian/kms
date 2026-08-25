/**
 * Role management E2E tests.
 *
 * Covers the Crypto Officer role-status page under Access Rights:
 *   • /ui/access-rights/crypto-officer — Crypto Officer Role status page
 *
 * The test KMS server runs in dev mode (VITE_DEV_MODE=true / no RBAC configured),
 * so the role reports "not configured". Tests verify:
 *   - Page navigation and heading visibility
 *   - Status load without HTTP errors
 *   - "Not configured" card shown when RBAC is absent
 *   - Disable button is absent when ceremony is not active
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";

test.describe("Role management", () => {
    // ── Crypto Officer role page ─────────────────────────────────────────────

    test("navigate to crypto officer role page", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await expect(page.getByRole("heading", { name: /crypto officer role/i })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("crypto officer status loads without error in dev mode", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");

        // Wait for the response-output card or the role-status-card to appear
        const output = page.locator('[data-testid="response-output"], [data-testid="role-status-card"]');
        await output.first().waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        // Verify no raw HTTP error text is shown
        const text = (await output.first().textContent()) ?? "";
        expect(text).not.toMatch(/error fetching/i);
        expect(text).not.toMatch(/5\d\d:/);
    });

    test("crypto officer role shows not-configured when RBAC disabled", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");

        // In dev mode, no role config is present → the "not configured" card must appear
        const notConfigured = page.locator('[data-testid="response-output"]');
        await notConfigured.waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });
        await expect(notConfigured).toContainText(/not configured/i);
    });

    test("crypto officer disable button absent when ceremony not active", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");

        // Wait for page to finish loading
        await page.locator('[data-testid="response-output"], [data-testid="role-status-card"]').first().waitFor({
            state: "visible",
            timeout: UI_READY_TIMEOUT,
        });

        // Disable button must not be present — no ceremony is active in dev mode
        await expect(page.locator('[data-testid="disable-btn"]')).toHaveCount(0);
    });

    test("crypto officer refresh button is visible", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await expect(page.locator('[data-testid="refresh-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    // ── Navigation via menu ──────────────────────────────────────────────────

    test("crypto officer appears under Access Rights menu", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");

        // Open the Access Rights menu group in the sidebar
        const menuGroup = page.locator('[data-menu-id*="access-rights"]').first();
        await menuGroup.waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });
        await menuGroup.click();

        // Crypto Officer entry must appear in the expanded menu
        await expect(page.locator('[data-menu-id*="access-rights/crypto-officer"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });
});
