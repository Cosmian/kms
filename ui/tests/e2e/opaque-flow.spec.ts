/**
 * Opaque-object flow E2E tests.
 *
 * Covers:
 *   • Create an empty opaque object (no data value provided).
 *   • Create an opaque object with an explicit UTF-8 data string.
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForResponse } from "./helpers";

test.describe("Opaque object", () => {
    test("create empty opaque object", async ({ page }) => {
        await gotoAndWait(page, "/ui/opaque-object/create");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create opaque object with explicit data", async ({ page }) => {
        await gotoAndWait(page, "/ui/opaque-object/create");

        await page.fill('textarea[placeholder="Enter opaque data"]', "e2e-test-opaque-payload");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });
});
