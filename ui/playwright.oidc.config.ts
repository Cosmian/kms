import { defineConfig, devices } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
};

const env = (globalThis as GlobalWithProcess).process?.env ?? {};

/**
 * Playwright configuration for the OIDC (Auth0) Web UI login E2E suite
 * (`tests/e2e-oidc/`).
 *
 * Separate config (like `playwright.auth.config.ts`) because the suite needs
 * a UI built WITHOUT `VITE_DEV_MODE` (so the login form renders) and a KMS
 * configured for the OIDC/JWT auth method — incompatible with both the
 * default dev-mode functional suite and the Cosmian-auth suite.
 *
 * This is a TRUE end-to-end suite: it drives a real browser through the real
 * Auth0 hosted login page configured in
 * `test_data/configs/server/test/auth_ui.toml` (demo-kms.eu.auth0.com). It
 * therefore requires network access, a valid client secret (server-side) and
 * real test-user credentials (`OIDC_TEST_USERNAME` / `OIDC_TEST_PASSWORD`).
 * The specs skip themselves when those credentials are absent.
 *
 * The redirect URI is pre-registered with the Auth0 application, so the KMS
 * MUST be reachable at the fixed origin http://127.0.0.1:9998 (no dynamic
 * ports). The harness `.github/scripts/test/test_ui_oidc.sh` builds and starts
 * everything, then sets `PLAYWRIGHT_BASE_URL` accordingly.
 */
export default defineConfig({
    testDir: "./tests/e2e-oidc",
    // External IdP round-trips are slower than local flows.
    timeout: 120_000,
    retries: env.CI ? 1 : 0,
    // Sequential: shared KMS + external IdP session/rate-limits make parallel
    // logins flaky and unsafe.
    workers: 1,
    use: {
        baseURL: env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:9998",
        headless: true,
        actionTimeout: 30_000,
        navigationTimeout: 45_000,
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
