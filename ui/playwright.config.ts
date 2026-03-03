import { defineConfig, devices } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: {
        env?: Record<string, string | undefined>;
    };
};

const env = (globalThis as GlobalWithProcess).process?.env ?? {};

/**
 * Playwright configuration for KMS UI E2E tests.
 *
 * The test suite exercises real browser flows against a locally running KMS
 * server (port 9998) and a Vite preview server (port 5173).
 *
 * For CI the CI script (test_ui.sh / test_ui.ps1) is responsible for:
 *   1. Building the WASM package with the non-fips feature.
 *   2. Building the UI with VITE_KMS_URL=http://127.0.0.1:9998.
 *   3. Starting the KMS server and the Vite preview server.
 *   4. Running `pnpm run test:e2e` (CI=true → webServer is skipped).
 *
 * For local development, set VITE_KMS_URL and build the UI first:
 *   VITE_KMS_URL=http://127.0.0.1:9998 pnpm run build
 * Then either start `pnpm preview` manually or let Playwright start it
 * via the webServer config below (reuseExistingServer: true).
 */
export default defineConfig({
    testDir: "./tests/e2e",
    timeout: 90_000,
    retries: env.CI ? 1 : 0,
    // Run tests serially – they share the same KMS server state.
    workers: 1,
    use: {
        baseURL: env.PLAYWRIGHT_BASE_URL ?? "http://localhost:5173",
        headless: true,
        actionTimeout: 30_000,
        navigationTimeout: 30_000,
        // Capture screenshot on failure for debugging.
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
    },
    projects: [
        {
            name: "chromium",
            use: { ...devices["Desktop Chrome"] },
        },
    ],
    // In CI the preview server is started by the CI script; do not start a
    // second preview instance from Playwright.
    webServer: env.CI
        ? undefined
        : {
              command: "pnpm preview --port 5173 --host 127.0.0.1 --strictPort",
              url: "http://localhost:5173/ui/",
              reuseExistingServer: true,
              timeout: 60_000,
          },
});
