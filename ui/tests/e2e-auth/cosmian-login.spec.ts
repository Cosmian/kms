/**
 * Cosmian authentication server — Web UI login E2E tests (TRUE end-to-end).
 *
 * Covers the happy path and the most likely error scenarios from
 * `CHANGELOG/test_plan_cosmian-auth-ui-login.md` against a REAL, locally
 * running Cosmian authentication server (not mocked) and a REAL KMS server
 * configured with `[cosmian_auth]`.
 *
 * Prerequisites (see `.github/scripts/test/test_ui_auth.sh`):
 *   - Cosmian auth server running on https://localhost:8443 with the bundled
 *     dev seed (realm "_", super-admin `admin` / `change_me`).
 *   - KMS server running on http://localhost:9998, serving the UI itself
 *     (same-origin — required for the session cookie to work), built WITHOUT
 *     VITE_DEV_MODE so the login form actually renders.
 *
 * Deliberately NOT exhaustive (see manual test plan for the full matrix):
 * TOTP (TC3), ChangePassword next_step (TC5), and the missing-realm fallback
 * (TC10) are out of scope here — happy path + the two most likely failure
 * modes only.
 */
import { expect, test } from "@playwright/test";

const VALID_USERNAME = "admin";
const VALID_PASSWORD = "change_me";

test.describe("Cosmian auth server — Web UI login", () => {
    test("GET /ui/auth_method reports COSMIAN", async ({ request, baseURL }) => {
        const response = await request.get(`${baseURL}/ui/auth_method`);
        expect(response.ok()).toBeTruthy();
        await expect(response.json()).resolves.toEqual({ auth_method: "COSMIAN" });
    });

    test("TC1 — happy path login", async ({ page }) => {
        await page.goto("/ui/");

        // Lands on the login page with the Cosmian username/password form
        // (not the OIDC redirect button or the CERT "ACCESS KMS" button).
        const form = page.getByTestId("cosmian-login-form");
        await expect(form).toBeVisible();

        await page.getByTestId("cosmian-username-input").fill(VALID_USERNAME);
        await page.getByTestId("cosmian-password-input").fill(VALID_PASSWORD);
        await page.getByTestId("cosmian-login-submit").click();

        // Full page navigation to /ui/locate once authenticated.
        await page.waitForURL(/\/ui\/locate/, { timeout: 15_000 });
        await expect(page).toHaveURL(/\/ui\/locate/);

        // Header shows the session user + Logout button.
        await expect(page.getByTestId("session-user-tag")).toHaveText(VALID_USERNAME);
        await expect(page.getByTestId("logout-btn")).toBeVisible();
    });

    test("TC4 — bad credentials are rejected", async ({ page }) => {
        await page.goto("/ui/");

        await page.getByTestId("cosmian-username-input").fill(VALID_USERNAME);
        await page.getByTestId("cosmian-password-input").fill("not-the-right-password");
        await page.getByTestId("cosmian-login-submit").click();

        // Inline "Authentication failed" alert, form remains, no navigation.
        await expect(page.getByTestId("cosmian-login-error")).toBeVisible({ timeout: 15_000 });
        await expect(page).toHaveURL(/\/ui\/login/);
        await expect(page.getByTestId("cosmian-login-form")).toBeVisible();
    });

    test("TC8 — logout clears the session", async ({ page }) => {
        await page.goto("/ui/");
        await page.getByTestId("cosmian-username-input").fill(VALID_USERNAME);
        await page.getByTestId("cosmian-password-input").fill(VALID_PASSWORD);
        await page.getByTestId("cosmian-login-submit").click();
        await page.waitForURL(/\/ui\/locate/, { timeout: 15_000 });

        await page.getByTestId("logout-btn").click();
        await page.waitForURL(/\/ui\/login/, { timeout: 15_000 });

        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.status()).toBe(401);
    });
});
