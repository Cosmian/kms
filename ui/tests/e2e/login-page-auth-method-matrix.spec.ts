/**
 * Login-page auth-method matrix — Playwright E2E tests.
 *
 * These tests verify that `LoginPage` renders the correct UI for every
 * combination of authentication methods that the KMS server can report.
 * They work by intercepting `GET /ui/auth_method` (and `GET /ui/whoami`)
 * so they run against the Vite dev/preview server with NO live KMS required.
 *
 * Combinations tested (8 total):
 *   1. ["AUTH_VERIFIER"]               — username/password form, no secondary
 *   2. ["JWT"]                         — OIDC button, no secondary
 *   3. ["CERT"]                        — certificate button, no secondary
 *   4. ["JWT", "AUTH_VERIFIER"]        — OIDC primary, AUTH_VERIFIER secondary button
 *   5. ["JWT", "CERT"]                 — OIDC primary, CERT secondary button
 *   6. ["AUTH_VERIFIER", "CERT"]       — form primary, CERT secondary button
 *   7. ["JWT", "AUTH_VERIFIER", "CERT"]— OIDC primary, secondary dropdown (2 entries)
 *   8. []  (no auth)                   — no login form shown; no-auth banner in app
 *
 * Each test mocks:
 *   GET /ui/auth_method  → { auth_method: <primary>, auth_methods: [...] }
 *   GET /ui/whoami       → 401 (not authenticated, so login page is shown)
 *   GET /kmip/2_1        → ignored (not called during login page render)
 *
 * data-testid selectors (from LoginPage.tsx):
 *   auth-verifier-login-form    — the username/password form
 *   auth-verifier-username-input
 *   auth-verifier-password-input
 *   oidc-login-btn              — OIDC / JWT redirect button
 *   cert-login-btn              — client certificate probe button
 *   login-secondary-btn         — single secondary action button
 *   login-secondary-dropdown    — dropdown when ≥ 2 secondary methods
 *   no-browser-auth-notice      — shown when no browser-compatible method exists
 */

import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT } from "./helpers";

// ── Helpers ───────────────────────────────────────────────────────────────────

type AuthMethods = Array<"JWT" | "AUTH_VERIFIER" | "CERT">;

/**
 * Mock `/ui/auth_method` to return the given ordered list of methods.
 * Also mock `/ui/whoami` to return 401 so the app shows the login page
 * (not the already-authenticated redirect).
 */
async function mockAuthMethods(page: import("@playwright/test").Page, methods: AuthMethods) {
    const primary = methods[0] ?? "None";
    await page.route("**/ui/auth_method", (route) =>
        route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ auth_method: primary, auth_methods: methods }),
        }),
    );
    // 401 so the bootstrap code doesn't consider the user already logged in.
    await page.route("**/ui/whoami", (route) => route.fulfill({ status: 401, body: "Unauthorized" }));
    // Silence the KMIP vendor-id query; it's a fire-and-forget call.
    await page.route("**/kmip/2_1", (route) => route.fulfill({ status: 401, body: "" }));
}

/** Navigate to /ui/login and wait until the login card is visible. */
async function gotoLogin(page: import("@playwright/test").Page) {
    await page.goto("/ui/login");
    await page.waitForLoadState("networkidle");
}

// ── Matrix tests ──────────────────────────────────────────────────────────────

// These tests mock GET /ui/auth_method and GET /ui/whoami at the browser
// level. They are purely UI-rendering tests and do NOT require a live KMS.
//
// Skip when a Playwright client certificate directory is configured
// (PLAYWRIGHT_CERT_DIR is set). In mTLS CI runs, the browser TLS handshake
// authenticates the user before our route mocks can intercept the
// /ui/auth_method call, causing the app to redirect to /locate instead of
// rendering the login page.
//
// These tests run correctly in standalone mode (against Vite preview without KMS):
//   CI=true pnpm run test:e2e --grep "Login page auth-method matrix"
const hasMtlsCert = typeof process !== "undefined" && Boolean(process.env?.PLAYWRIGHT_CERT_DIR);

test.describe("Login page auth-method matrix", () => {
    test.skip(
        hasMtlsCert,
        "Skipped when mTLS client cert is configured (PLAYWRIGHT_CERT_DIR is set); cert auto-auth intercepts before route mocks take effect",
    );

    // ── 1. AUTH_VERIFIER only ─────────────────────────────────────────────────
    test('["AUTH_VERIFIER"] — shows username/password form, no secondary', async ({ page }) => {
        await mockAuthMethods(page, ["AUTH_VERIFIER"]);
        await gotoLogin(page);

        await expect(page.getByTestId("auth-verifier-login-form")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("auth-verifier-username-input")).toBeVisible();
        await expect(page.getByTestId("auth-verifier-password-input")).toBeVisible();
        await expect(page.getByTestId("oidc-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-btn")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 2. JWT only ───────────────────────────────────────────────────────────
    test('["JWT"] — shows OIDC redirect button, no secondary', async ({ page }) => {
        await mockAuthMethods(page, ["JWT"]);
        await gotoLogin(page);

        await expect(page.getByTestId("oidc-login-btn")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-btn")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 3. CERT only ──────────────────────────────────────────────────────────
    test('["CERT"] — shows certificate button, no secondary', async ({ page }) => {
        await mockAuthMethods(page, ["CERT"]);
        await gotoLogin(page);

        await expect(page.getByTestId("cert-login-btn")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("oidc-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-btn")).not.toBeVisible();
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 4. JWT + AUTH_VERIFIER ────────────────────────────────────────────────
    test('["JWT", "AUTH_VERIFIER"] — OIDC primary, AUTH_VERIFIER secondary button', async ({ page }) => {
        await mockAuthMethods(page, ["JWT", "AUTH_VERIFIER"]);
        await gotoLogin(page);

        await expect(page.getByTestId("oidc-login-btn")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();

        // Single secondary: a plain button labelled with the method name
        const secondary = page.getByTestId("login-secondary-btn");
        await expect(secondary).toBeVisible();
        await expect(secondary).toContainText(/auth.*verifier|username.*password|sign.*in/i);
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 5. JWT + CERT ─────────────────────────────────────────────────────────
    test('["JWT", "CERT"] — OIDC primary, CERT secondary button', async ({ page }) => {
        await mockAuthMethods(page, ["JWT", "CERT"]);
        await gotoLogin(page);

        await expect(page.getByTestId("oidc-login-btn")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();

        const secondary = page.getByTestId("login-secondary-btn");
        await expect(secondary).toBeVisible();
        await expect(secondary).toContainText(/certificate|cert/i);
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 6. AUTH_VERIFIER + CERT ───────────────────────────────────────────────
    test('["AUTH_VERIFIER", "CERT"] — form primary, CERT secondary button', async ({ page }) => {
        await mockAuthMethods(page, ["AUTH_VERIFIER", "CERT"]);
        await gotoLogin(page);

        await expect(page.getByTestId("auth-verifier-login-form")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("oidc-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();

        const secondary = page.getByTestId("login-secondary-btn");
        await expect(secondary).toBeVisible();
        await expect(secondary).toContainText(/certificate|cert/i);
        await expect(page.getByTestId("login-secondary-dropdown")).not.toBeVisible();
    });

    // ── 7. JWT + AUTH_VERIFIER + CERT ─────────────────────────────────────────
    test('["JWT", "AUTH_VERIFIER", "CERT"] — OIDC primary, secondary dropdown with 2 entries', async ({ page }) => {
        await mockAuthMethods(page, ["JWT", "AUTH_VERIFIER", "CERT"]);
        await gotoLogin(page);

        await expect(page.getByTestId("oidc-login-btn")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();

        // Two secondaries → dropdown control instead of a single button
        await expect(page.getByTestId("login-secondary-dropdown")).toBeVisible();
        await expect(page.getByTestId("login-secondary-btn")).not.toBeVisible();
    });

    // ── 8. No auth methods ────────────────────────────────────────────────────
    test("[] (no methods) — main layout shown directly, authentication disabled notice visible", async ({ page }) => {
        await mockAuthMethods(page, []);
        // Silence sidebar requests that MainLayout fires once authenticated.
        await page.route("**/access/create", (route) => route.fulfill({ status: 200, body: '{"has_create_permission":false}' }));
        await page.route("**/access/privileged", (route) => route.fulfill({ status: 200, body: '{"has_privileged_access":false}' }));
        await page.route("**/version", (route) => route.fulfill({ status: 200, body: '"5.x.0"' }));
        await page.route("**/ui/me", (route) => route.fulfill({ status: 200, body: '"default_user"' }));

        // When auth_methods = [], App shows the main layout immediately
        // (route guard is false) and /login redirects to /locate.
        await page.goto("/ui/login");
        await page.waitForURL(/\/ui\/locate/, { timeout: UI_READY_TIMEOUT });

        // MainLayout renders the "authentication disabled" banner (i18n key authDisabledTitle).
        await expect(page.getByText(/Authentication is disabled on this KMS server/i)).toBeVisible({ timeout: UI_READY_TIMEOUT });

        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
        await expect(page.getByTestId("oidc-login-btn")).not.toBeVisible();
        await expect(page.getByTestId("cert-login-btn")).not.toBeVisible();
    });

    // ── 9. Switching methods via secondary button ─────────────────────────────
    test("clicking secondary CERT button immediately fires the cert probe and navigates on success", async ({ page }) => {
        await mockAuthMethods(page, ["AUTH_VERIFIER", "CERT"]);
        // Probe: 200 means a valid client cert was presented → user is authenticated.
        await page.route("**/access/create", (route) => route.fulfill({ status: 200, body: '{"has_create_permission":false}' }));
        // Silence MainLayout bootstrap calls after cert auth succeeds.
        await page.route("**/access/privileged", (route) => route.fulfill({ status: 200, body: '{"has_privileged_access":false}' }));
        await page.route("**/version", (route) => route.fulfill({ status: 200, body: '"5.x.0"' }));
        await page.route("**/ui/me", (route) => route.fulfill({ status: 200, body: '"cert_user"' }));
        await gotoLogin(page);

        // Initially: AUTH_VERIFIER form is shown
        await expect(page.getByTestId("auth-verifier-login-form")).toBeVisible({ timeout: UI_READY_TIMEOUT });

        // Click the secondary "Client certificate" button.
        // `selectMethod("CERT")` fires handleAccessKms() immediately — it does NOT
        // change the visible form first; it probes /access/create and, on success,
        // calls onCertAuthenticated() which triggers App.tsx to show the main layout.
        await page.getByTestId("login-secondary-btn").click();

        // After a successful cert probe the app navigates to the main authenticated layout.
        await page.waitForURL(/\/ui\/locate/, { timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("auth-verifier-login-form")).not.toBeVisible();
    });

    // ── 10. /ui/auth_method returns auth_methods order is preserved ───────────
    test("GET /ui/auth_method — auth_methods array is returned in configured order", async ({ request, baseURL }) => {
        // Validate the endpoint contract (does NOT mock: verifies the dev server
        // responds with the expected JSON shape for whatever is configured).
        const resp = await request.get(`${baseURL}/ui/auth_method`);
        expect(resp.ok()).toBe(true);
        const body = await resp.json();
        expect(body).toHaveProperty("auth_method");
        expect(body).toHaveProperty("auth_methods");
        expect(Array.isArray(body.auth_methods)).toBe(true);
        // The singular field must equal the first element of the array (or "None")
        const expectedPrimary = (body.auth_methods as string[])[0] ?? "None";
        expect(body.auth_method).toBe(expectedPrimary);
    });
});
