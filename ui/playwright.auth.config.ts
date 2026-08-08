import { defineConfig, devices } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: {
        env?: Record<string, string | undefined>;
    };
};

const env = (globalThis as GlobalWithProcess).process?.env ?? {};

/**
 * Playwright configuration for the Auth-Verifier-server Web UI login
 * E2E suite (`tests/e2e-auth/`).
 *
 * This is intentionally a SEPARATE config from `playwright.config.ts` because
 * the two suites require mutually incompatible UI builds:
 *
 *   - The regular E2E suite (`playwright.config.ts`) runs against a UI built
 *     with `VITE_DEV_MODE=true`, which makes the app treat every visitor as
 *     already authenticated (`fetchAuthMethod()` short-circuits to "None") —
 *     the login form never renders.
 *   - This suite requires a UI built WITHOUT `VITE_DEV_MODE`/`VITE_KMS_URL` so
 *     `authMethod` is fetched from the real `GET /ui/auth_method` endpoint and
 *     the Auth Verifier username/password login form actually renders.
 *
 * It also targets a different stack: a real Auth Verifier authentication server
 * (`https://localhost:8443` by default, from the sibling `authentication`
 * repo) plus a KMS server configured with `[auth_verifier]` and serving the UI
 * itself on the SAME origin (so the session cookie set by `/ui/login_as`
 * works without cross-origin cookie complications).
 *
 * The harness responsible for building/starting everything is
 * `.github/scripts/test/test_ui_auth.sh`. For CI, that script sets `CI=true`
 * and `PLAYWRIGHT_BASE_URL` after both servers are confirmed ready.
 */
export default defineConfig({
    testDir: "./tests/e2e-auth",
    timeout: 60_000,
    retries: env.CI ? 1 : 0,
    // Sequential: these tests share one KMS/auth-server pair and assert on
    // session/cookie state, which is not safe to parallelize.
    workers: 1,
    use: {
        baseURL: env.PLAYWRIGHT_BASE_URL ?? "http://localhost:9998",
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
