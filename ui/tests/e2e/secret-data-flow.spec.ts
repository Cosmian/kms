/**
 * Secret-data flow E2E tests.
 *
 * Covers:
 *   • Create a random 32-byte seed (default, no value supplied).
 *   • Create a Password-type secret by providing a value and switching the
 *     secret-type selector.
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, selectOption, submitAndWaitForResponse } from "./helpers";

test.describe("Secret data", () => {
    test("create random 32-byte seed (default)", async ({ page }) => {
        await gotoAndWait(page, "/ui/secret-data/create");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });

    test("create Password secret with a value", async ({ page }) => {
        await gotoAndWait(page, "/ui/secret-data/create");

        // Fill the secret value textarea – this enables the type selector.
        await page.fill('textarea[placeholder="Enter secret value"]', "my-e2e-password");

        // Switch secret type to "Password" (the Select becomes enabled after a
        // value is entered).
        await selectOption(page, "secret-type-select", "Password");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/has been created/i);
    });
});
