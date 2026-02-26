/**
 * Google CSE flow E2E tests.
 *
 * Covers:
 *   • navigate to the Google CSE information page (/google-cse)
 *   • verify the heading renders (the page auto-loads CSE status on mount)
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait } from "./helpers";

test.describe("Google Client-Side Encryption (CSE)", () => {
    test("navigate to CSE information page", async ({ page }) => {
        await gotoAndWait(page, "/ui/google-cse");
        await expect(page.getByRole("heading", { name: /CSE Information/i })).toBeVisible({ timeout: 15_000 });
    });
});
