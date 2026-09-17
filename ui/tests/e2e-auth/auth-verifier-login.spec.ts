/**
 * Auth Verifier server — Web UI login E2E tests (TRUE end-to-end).
 *
 * Covers the happy path and the most likely error scenarios from
 * `CHANGELOG/test_plan_auth-verifier-auth-ui-login.md` against a REAL, locally
 * running Auth Verifier authentication server (not mocked) and a REAL KMS server
 * configured with `[auth_verifier]`.
 *
 * Prerequisites (see `.github/scripts/test/test_ui_auth.sh`):
 *   - Auth Verifier server running on https://localhost:8443 with the bundled
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

test.describe("Auth Verifier server — Web UI login", () => {
    test("GET /ui/auth_method reports AUTH_VERIFIER", async ({ request, baseURL }) => {
        const response = await request.get(`${baseURL}/ui/auth_method`);
        expect(response.ok()).toBeTruthy();
        // `auth_method` is the primary (backward-compatible); `auth_methods` is the
        // ordered array of all configured methods (primary first).
        await expect(response.json()).resolves.toEqual({ auth_method: "AUTH_VERIFIER", auth_methods: ["AUTH_VERIFIER"] });
    });

    test("TC1 — happy path login", async ({ page }) => {
        await page.goto("/ui/");

        // Lands on the login page with the Auth Verifier username/password form
        // (not the OIDC redirect button or the CERT "ACCESS KMS" button).
        const form = page.getByTestId("auth-verifier-login-form");
        await expect(form).toBeVisible();

        await page.getByTestId("auth-verifier-username-input").fill(VALID_USERNAME);
        await page.getByTestId("auth-verifier-password-input").fill(VALID_PASSWORD);
        await page.getByTestId("auth-verifier-login-submit").click();

        // Full page navigation to /ui/locate once authenticated.
        await page.waitForURL(/\/ui\/locate/, { timeout: 15_000 });
        await expect(page).toHaveURL(/\/ui\/locate/);

        // Header shows the session user + Logout button.
        await expect(page.getByTestId("session-user-tag")).toHaveText(VALID_USERNAME);
        await expect(page.getByTestId("logout-btn")).toBeVisible();
    });

    test("TC4 — bad credentials are rejected", async ({ page }) => {
        await page.goto("/ui/");

        await page.getByTestId("auth-verifier-username-input").fill(VALID_USERNAME);
        await page.getByTestId("auth-verifier-password-input").fill("not-the-right-password");
        await page.getByTestId("auth-verifier-login-submit").click();

        // Inline "Authentication failed" alert, form remains, no navigation.
        await expect(page.getByTestId("auth-verifier-login-error")).toBeVisible({ timeout: 15_000 });
        await expect(page).toHaveURL(/\/ui\/login/);
        await expect(page.getByTestId("auth-verifier-login-form")).toBeVisible();
    });

    test("TC8 — logout clears the session", async ({ page }) => {
        await page.goto("/ui/");
        await page.getByTestId("auth-verifier-username-input").fill(VALID_USERNAME);
        await page.getByTestId("auth-verifier-password-input").fill(VALID_PASSWORD);
        await page.getByTestId("auth-verifier-login-submit").click();
        await page.waitForURL(/\/ui\/locate/, { timeout: 15_000 });

        await page.getByTestId("logout-btn").click();
        await page.waitForURL(/\/ui\/login/, { timeout: 15_000 });

        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.status()).toBe(401);
    });
});
