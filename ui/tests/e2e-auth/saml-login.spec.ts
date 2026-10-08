/**
 * Auth Verifier SAML single sign-on — Web UI E2E tests.
 *
 * The IdP round trip (KMS -> Auth Verifier /saml -> IdP -> ACS) needs a SAML identity
 * provider and a same-origin reverse proxy; it is covered by the Auth Verifier SAML E2E
 * suite and the KMS server unit tests. Here the KMS UI endpoints are mocked to check the
 * UI side of the contract: the login button starts at `/ui/login_saml`, and a session
 * resolved by `/ui/whoami` after the redirect back is shown with a Logout button.
 *
 * Requires a UI built WITHOUT `VITE_DEV_MODE` (see playwright.auth.config.ts).
 */
import { expect, test, type Page } from "@playwright/test";

const SAML_USER = "alice@example.com";

const mockAuthMethods = (page: Page, methods: string[]) =>
    page.route("**/ui/auth_method", (route) =>
        route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ auth_method: methods[0], auth_methods: methods }),
        }),
    );

test.describe("Auth Verifier SAML single sign-on — Web UI", () => {
    test("SSO button starts the SAML login at /ui/login_saml", async ({ page }) => {
        await mockAuthMethods(page, ["AUTH_VERIFIER_SAML", "AUTH_VERIFIER"]);
        await page.route("**/ui/whoami", (route) => route.fulfill({ status: 401, contentType: "application/json", body: "{}" }));
        await page.route("**/ui/login_saml", (route) =>
            route.fulfill({ status: 200, contentType: "text/html", body: "<p>redirected</p>" }),
        );

        await page.goto("/ui/");
        await expect(page.getByTestId("saml-login-btn")).toBeVisible();
        await expect(page.getByTestId("login-secondary-btn")).toBeVisible();

        await page.getByTestId("saml-login-btn").click();
        await page.waitForURL(/\/ui\/login_saml$/);
    });

    test("session established by SAML is shown with a Logout button", async ({ page }) => {
        await mockAuthMethods(page, ["AUTH_VERIFIER_SAML"]);
        await page.route("**/ui/whoami", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ user_id: SAML_USER }) }),
        );
        await page.route("**/version", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify("5.0.0") }),
        );

        await page.goto("/ui/locate");
        await expect(page.getByTestId("session-user-tag")).toHaveText(SAML_USER);
        await expect(page.getByTestId("logout-btn")).toBeVisible();
    });
});
