import { defineConfig, devices } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: {
        env?: Record<string, string | undefined>;
    };
};

const env = (globalThis as GlobalWithProcess).process?.env ?? {};

/**
 * Playwright configuration for the SAML single sign-on E2E suite (`tests/e2e-saml/`).
 *
 * Separate from `playwright.auth.config.ts` because it needs a different stack that the
 * `test:ui-auth` harness does not start: Keycloak (SAML IdP) + Auth Verifier (SAML build) +
 * an HTTPS reverse proxy serving both and the KMS on ONE origin
 * (`.mise/scripts/test/saml_sso/stack.sh`, driven by `.mise/scripts/test/test_ui_saml.sh`).
 *
 * The origin is `https://localhost:8443` with throw-away self-signed certificates, hence
 * `ignoreHTTPSErrors`.
 */
export default defineConfig({
    testDir: "./tests/e2e-saml",
    timeout: 90_000,
    // No retries: a retry would hide a flaky SSO round trip behind a green run.
    retries: 0,
    // Sequential: one KMS/Auth Verifier/Keycloak stack, and the tests assert on session state.
    workers: 1,
    use: {
        baseURL: env.PLAYWRIGHT_BASE_URL ?? "https://localhost:8443",
        ignoreHTTPSErrors: true,
        headless: true,
        actionTimeout: 30_000,
        navigationTimeout: 30_000,
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
    },
    projects: [
        {
            name: "chromium",
            use: { ...devices["Desktop Chrome"] },
        },
    ],
});
