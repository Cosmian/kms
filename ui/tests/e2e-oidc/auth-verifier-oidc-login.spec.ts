/// <reference types="node" />
/**
 * On-Premise OIDC (auth-verifier) — Web UI login E2E tests (TRUE end-to-end).
 *
 * Covers the happy path and the key security scenarios against a real,
 * locally-running auth-verifier OIDC Provider and a KMS configured with
 * `[auth_verifier]` + OIDC client fields.
 *
 * Unlike the Auth0 OIDC tests (`oidc-login.spec.ts`), the login page served by
 * the auth-verifier is a known, self-hosted page — selectors are stable.
 *
 * Prerequisites (started by `.mise/scripts/test/test_ui_auth_oidc.sh`):
 *   - Auth-verifier on `AUTH_VERIFIER_URL` with the dev seed realm (`_`).
 *   - A registered OIDC client with `redirect_uris` including the KMS callback.
 *   - KMS on `PLAYWRIGHT_BASE_URL` with `auth_verifier_oidc_client_id` set.
 *   - UI built WITHOUT `VITE_DEV_MODE` (so `authMethod` is fetched live).
 *
 * Required env vars (skips all tests if unset):
 *   - `AUTH_VERIFIER_OIDC_TEST_USERNAME`
 *   - `AUTH_VERIFIER_OIDC_TEST_PASSWORD`
 *
 * Optional env vars:
 *   - `AUTH_VERIFIER_URL` (default: `https://localhost:8443`)
 */
import { expect, Page, test } from "@playwright/test";

const OIDC_USERNAME = process.env.AUTH_VERIFIER_OIDC_TEST_USERNAME;
const OIDC_PASSWORD = process.env.AUTH_VERIFIER_OIDC_TEST_PASSWORD;

/**
 * Drive the auth-verifier OIDC login page.
 *
 * The auth-verifier renders a standard username + password form at `/oidc/authorize`.
 * Selectors target the generic `<input>` elements; adjust if the auth-verifier
 * UI template changes.
 */
async function completeAuthVerifierOidcLogin(page: Page, username: string, password: string): Promise<void> {
    // Wait to land on the auth-verifier authorize page.
    await page.waitForURL(/\/oidc\/authorize/, { timeout: 30_000 });

    const userField = page.locator('input[name="username"], input[name="email"], input[type="text"], input#username').first();
    await userField.waitFor({ state: "visible", timeout: 20_000 });
    await userField.fill(username);

    const passField = page.locator('input[name="password"], input[type="password"], input#password').first();
    await passField.fill(password);

    await page.locator('button[type="submit"]').first().click();
}

/** Perform a full OIDC login via the auth-verifier and wait until authenticated. */
async function loginViaAuthVerifierOidc(page: Page): Promise<void> {
    await page.goto("/ui/");
    // Click the OIDC login button (same test-id as for other OIDC IdPs).
    await page.getByTestId("oidc-login-btn").click();
    await completeAuthVerifierOidcLogin(page, OIDC_USERNAME as string, OIDC_PASSWORD as string);
    // Back on the KMS app — the header Logout button confirms authentication.
    await expect(page.getByTestId("logout-btn")).toBeVisible({ timeout: 30_000 });
}

test.describe("On-Premise OIDC (auth-verifier) — Web UI login", () => {
    test.skip(!OIDC_USERNAME || !OIDC_PASSWORD, "AUTH_VERIFIER_OIDC_TEST_USERNAME / AUTH_VERIFIER_OIDC_TEST_PASSWORD not set");

    test("GET /ui/auth_method reports JWT", async ({ request, baseURL }) => {
        // The OIDC flow uses the standard JWT auth method (not AUTH_VERIFIER).
        const response = await request.get(`${baseURL}/ui/auth_method`);
        expect(response.ok()).toBeTruthy();
        await expect(response.json()).resolves.toEqual({ auth_method: "JWT" });
    });

    test("TC1 — happy path login via auth-verifier OIDC", async ({ page }) => {
        await loginViaAuthVerifierOidc(page);

        // Authenticated: session user tag is visible.
        await expect(page.getByTestId("session-user-tag")).toBeVisible();
        await expect(page).toHaveURL(/\/ui\//);
    });

    test("TC2 — no token ever reaches the browser (security)", async ({ page }) => {
        await loginViaAuthVerifierOidc(page);

        // /ui/whoami returns only { user_id } — no token fields.
        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.ok()).toBeTruthy();
        const body = (await whoami.json()) as Record<string, unknown>;
        expect(Object.keys(body)).toEqual(["user_id"]);
        expect(typeof body.user_id).toBe("string");

        // No JWT / access_token in client-side storage.
        const storage = await page.evaluate(() => ({
            local: JSON.stringify(window.localStorage),
            session: JSON.stringify(window.sessionStorage),
            cookies: document.cookie,
        }));
        const jwtLike = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
        expect(storage.local).not.toMatch(/access_token|id_token|bearer/i);
        expect(storage.session).not.toMatch(/access_token|id_token|bearer/i);
        expect(storage.local).not.toMatch(jwtLike);
        expect(storage.session).not.toMatch(jwtLike);
        // HttpOnly session cookie must not be readable from JS.
        expect(storage.cookies).not.toMatch(jwtLike);
    });

    test("TC3 — session persists across reload, then logout clears it", async ({ page }) => {
        await loginViaAuthVerifierOidc(page);

        // Reload: still authenticated.
        await page.reload();
        await expect(page.getByTestId("logout-btn")).toBeVisible({ timeout: 20_000 });

        // Logout: session cleared.
        await page.getByTestId("logout-btn").click();
        await page.waitForURL(/\/ui\/login/, { timeout: 30_000 });

        const whoami = await page.request.get("/ui/whoami");
        expect(whoami.status()).toBe(401);
    });
});
