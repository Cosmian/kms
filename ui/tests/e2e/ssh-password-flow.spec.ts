import { expect, test } from "@playwright/test";
import { gotoAndWait, UI_READY_TIMEOUT } from "./helpers";

test.describe("Password generation", () => {
    test("generates a 32-character password", async ({ page }) => {
        await gotoAndWait(page, "/ui/generate-password");
        await expect(page.getByTestId("generate-password")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await page.getByTestId("generate-password").click();
        await expect(page.getByTestId("generated-password")).toHaveValue(/^[A-Za-z0-9]{32}$/);
    });
});
