/// <reference types="node" />
/**
 * OIDC (Auth0) — Web UI login E2E tests (TRUE end-to-end).
 *
 * Covers the happy path plus the major scenarios from
 * `CHANGELOG/test_plan_oidc-session-auth.md` against the REAL Auth0 IdP
 * configured in `test_data/configs/server/test/auth_ui.toml`
 * (demo-kms.eu.auth0.com). Not exhaustive: focuses on login, the security
 * guarantee (no token in the browser), session persistence and logout.
 *
 * Requires real credentials via env (see `.github/scripts/test/test_ui_oidc.sh`):
 *   - OIDC_TEST_USERNAME / OIDC_TEST_PASSWORD (a user with a verified `email`).
 * When absent, every test in this file is skipped.
 *
 * Prerequisites (harness): UI built WITHOUT VITE_DEV_MODE, served same-origin
 * by a KMS at http://127.0.0.1:9998 configured for OIDC (client id/secret,
 * issuer, session salt) — the redirect URI is pre-registered with Auth0.
 */
import { expect, Page, test } from "@playwright/test";

const OIDC_USERNAME = process.env.OIDC_TEST_USERNAME;
const OIDC_PASSWORD = process.env.OIDC_TEST_PASSWORD;

/**
 * Drive the Auth0 Universal Login page. Handles both single-page (username +
 * password together) and identifier-first (username, Continue, then password)
 * templates. Selectors are intentionally broad because the hosted page markup
 * varies by tenant template.
 */
async function completeAuth0Login(page: Page, username: string, password: string): Promise<void> {
    await page.waitForURL(/auth0\.com/, { timeout: 45_000 });

    const userField = page.locator('input[name="username"], input[name="email"], input#username, input[type="email"]').first();
    await userField.waitFor({ state: "visible", timeout: 30_000 });
    await userField.fill(username);

    const passField = page.locator('input[name="password"], input#password, input[type="password"]').first();
    if (!(await passField.isVisible().catch(() => false))) {
        // Identifier-first flow: advance to the password step.
        await page.locator('button[type="submit"]').first().click();
        await passField.waitFor({ state: "visible", timeout: 30_000 });
    }
    await passField.fill(password);
    await page.locator('button[type="submit"]').first().click();
}

/** Perform a full login and wait until the app is authenticated. */
async function loginViaOidc(page: Page): Promise<void> {
    await page.goto("/ui/");
    await page.getByTestId("oidc-login-btn").click();
    await completeAuth0Login(page, OIDC_USERNAME as string, OIDC_PASSWORD as string);
    // Back on the app, authenticated: the header Logout button is present.
    await expect(page.getByTestId("logout-btn")).toBeVisible({ timeout: 45_000 });
}

test.describe("OIDC (Auth0) — Web UI login", () => {
    test.skip(!OIDC_USERNAME || !OIDC_PASSWORD, "OIDC_TEST_USERNAME/OIDC_TEST_PASSWORD not set");

    test("GET /ui/auth_method reports JWT", async ({ request, baseURL }) => {
        const response = await request.get(`${baseURL}/ui/auth_method`);
        expect(response.ok()).toBeTruthy();
        await expect(response.json()).resolves.toEqual({ auth_method: "JWT" });
    });

    test("TC1 — happy path login", async ({ page }) => {
        await loginViaOidc(page);
        await expect(page.getByTestId("session-user-tag")).toBeVisible();
        await expect(page).toHaveURL(/\/ui\//);
    });

    test("TC2 — no token ever reaches the browser (security)", async ({ page }) => {
        await loginViaOidc(page);

        // /ui/whoami returns only { user_id } — no id_token / token fields.
        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.ok()).toBeTruthy();
        const body = (await whoami.json()) as Record<string, unknown>;
        expect(Object.keys(body)).toEqual(["user_id"]);
        expect(typeof body.user_id).toBe("string");

        // No JWT / id_token / bearer token in client-side storage.
        const storage = await page.evaluate(() => ({
            local: JSON.stringify(window.localStorage),
            session: JSON.stringify(window.sessionStorage),
            cookies: document.cookie,
        }));
        const jwtLike = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
        expect(storage.local).not.toMatch(/id_token|bearer/i);
        expect(storage.session).not.toMatch(/id_token|bearer/i);
        expect(storage.local).not.toMatch(jwtLike);
        expect(storage.session).not.toMatch(jwtLike);
        // The session cookie is HttpOnly, so it must not be readable from JS.
        expect(storage.cookies).not.toMatch(jwtLike);
    });

    test("TC5/TC6 — session persists across reload, then logout clears it", async ({ page }) => {
        await loginViaOidc(page);

        // Reload: still authenticated, not bounced to the login form.
        await page.reload();
        await expect(page.getByTestId("logout-btn")).toBeVisible({ timeout: 30_000 });

        // Logout: clears the session (Auth0 logout may bounce via the IdP).
        await page.getByTestId("logout-btn").click();
        await page.waitForURL(/\/ui\/login/, { timeout: 45_000 });

        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.status()).toBe(401);
    });
});
