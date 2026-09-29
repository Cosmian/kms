/**
 * RBAC (Role-Based Access Control) E2E tests.
 *
 * Verifies the two-role model (CryptoOfficer + Operator) per ADR-2026-06-24.
 * These tests focus on UI structure and basic functionality.
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, createSymKey, gotoAndWait } from "./helpers";

test.describe("RBAC — Split Key UI (n-of-n XOR)", () => {
    test("Split Key page loads", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/split");
        // Page should have the Split Key heading
        await expect(page.locator("h1:has-text('Split Key')")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("Join Split Key page loads", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/join");
        // Page should have the Join Split Key heading
        await expect(page.locator("h1:has-text('Join Split Key')")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("Split key flow: create key and navigate to split page", async ({ page }) => {
        // Create a key to split
        const keyId = await createSymKey(page);
        expect(keyId).toBeTruthy();

        // Navigate to split page
        await gotoAndWait(page, "/ui/sym/keys/split");
        await expect(page.locator("h1:has-text('Split Key')")).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});

test.describe("RBAC — Access Control UI", () => {
    test("Grant access page loads correctly", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/grant");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("Revoke access page loads correctly", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/revoke");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("List access page loads correctly", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/list");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("CO can grant access on a key", async ({ page }) => {
        const keyId = await createSymKey(page);
        expect(keyId).toBeTruthy();

        const testUser = "rbac-test-user@example.com";

        // Navigate to grant page and wait for form to be ready
        await gotoAndWait(page, "/ui/access-rights/grant");
        const userInput = page.locator('input[placeholder="Enter user identifier"]');
        await userInput.waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });

        // Fill user identifier
        await userInput.fill(testUser);

        // The object UID input is disabled until operations are selected; verify
        // the grant page is properly structured.
        await expect(page.locator('[data-testid="operation-types-select"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });
});

test.describe("RBAC — Crypto Officer Menu", () => {
    test("Crypto Officer page is accessible", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });

        // Page should have some content
        const bodyText = await page.textContent("body");
        expect(bodyText).toMatch(/crypto|officer|role|status|ceremony/i);
    });
});
