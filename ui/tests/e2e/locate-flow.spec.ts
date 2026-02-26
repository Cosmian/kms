/**
 * Locate flow E2E tests.
 *
 * Covers:
 *   • navigate to the Locate page and confirm the heading renders
 *   • submit an empty search (no filters) and verify a response appears
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForResponse } from "./helpers";

test.describe("Locate objects", () => {
    test("navigate to locate page", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });
    });

    test("submit locate with no filters returns a response", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: 15_000 });

        // Submit with no filters – the server will return all accessible objects
        // or an empty result; either way the response panel should appear.
        const text = await submitAndWaitForResponse(page);
        // Any non-empty response is acceptable ("0 Object(s) located.", list of UUIDs, etc.)
        expect(text.length).toBeGreaterThan(0);
    });
});
