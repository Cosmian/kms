/**
 * SPIFFE JWT-SVID — Web UI browser login E2E test.
 *
 * Validates that a user can paste a SPIRE-issued JWT-SVID into the Web UI's
 * "SPIFFE JWT-SVID" login form (POST /ui/login_svid) and reach the
 * authenticated application, with the session identity resolved to the
 * SPIFFE ID carried by the token's `sub` claim.
 */
import { expect, test } from "@playwright/test";

const KMS_URL = process.env.PLAYWRIGHT_KMS_URL ?? "https://127.0.0.1:9998";
const JWT_SVID_TOKEN = process.env.TEST_JWT_SVID_TOKEN;
const EXPECTED_SPIFFE_ID = process.env.TEST_SPIFFE_ID ?? "spiffe://cosmian-test-a.local/webui-demo-user";

test.describe("SPIFFE JWT-SVID Web UI login", () => {
    test.skip(!JWT_SVID_TOKEN, "TEST_JWT_SVID_TOKEN environment variable not set");

    test("logs in via the SPIFFE JWT-SVID form and reaches the authenticated UI", async ({ page }) => {
        await page.goto(`${KMS_URL}/ui/login`, { waitUntil: "domcontentloaded" });

        // The SPIFFE method may be primary (form shown directly) or secondary
        // (behind a button or dropdown), depending on server auth_methods order.
        const spiffeForm = page.getByTestId("spiffe-login-form");
        const secondaryBtn = page.getByTestId("login-secondary-btn");
        const secondaryDropdown = page.getByTestId("login-secondary-dropdown");

        // Wait for at least one auth control to render
        await Promise.race([
            spiffeForm.waitFor({ state: "visible" }),
            secondaryBtn.waitFor({ state: "visible" }),
            secondaryDropdown.waitFor({ state: "visible" }),
        ]).catch(() => {});

        if (!(await spiffeForm.isVisible().catch(() => false))) {
            if (await secondaryBtn.isVisible().catch(() => false)) {
                await secondaryBtn.click();
            } else if (await secondaryDropdown.isVisible().catch(() => false)) {
                await secondaryDropdown.click();
                await page.getByRole("menuitem", { name: /SPIFFE/i }).click();
            }
        }

        await page.getByTestId("spiffe-svid-input").fill(JWT_SVID_TOKEN!);
        await page.getByTestId("spiffe-login-submit").click();

        await page.waitForURL(/\/ui\/locate/);
        await expect(page.getByTestId("session-user-tag")).toContainText(EXPECTED_SPIFFE_ID);
    });
});
