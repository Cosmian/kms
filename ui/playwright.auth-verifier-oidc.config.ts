import { defineConfig, devices } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: {
        env?: Record<string, string | undefined>;
    };
};

const env = (globalThis as GlobalWithProcess).process?.env ?? {};

/**
 * Playwright configuration for the on-premise OIDC (auth-verifier) login
 * E2E suite (`tests/e2e-oidc/auth-verifier-oidc-login.spec.ts`).
 *
 * Requires the KMS to be configured with `[auth_verifier]` + OIDC client
 * fields and the auth-verifier to expose the OIDC OP endpoints.
 *
 * Environment variables:
 *   - `PLAYWRIGHT_BASE_URL`               — KMS server URL (default: http://localhost:9998)
 *   - `AUTH_VERIFIER_OIDC_TEST_USERNAME`  — test user username
 *   - `AUTH_VERIFIER_OIDC_TEST_PASSWORD`  — test user password
 *
 * The harness `.mise/scripts/test/test_ui_auth_oidc.sh` sets all of these.
 */
export default defineConfig({
    testDir: "./tests/e2e-oidc",
    testMatch: "**/auth-verifier-oidc-login.spec.ts",
    timeout: 60_000,
    retries: env.CI ? 1 : 0,
    workers: 1,
    use: {
        baseURL: env.PLAYWRIGHT_BASE_URL ?? "http://localhost:9998",
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
