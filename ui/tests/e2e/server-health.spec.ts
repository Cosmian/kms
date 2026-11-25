/**
 * Server Health page E2E tests.
 *
 * The page shows `GET /health` (status and dependencies) and `GET /cluster/status` (live nodes).
 * The first test runs against the real server; the others mock `/health` to reach states a healthy
 * test server cannot produce (DEGRADED, DOWN, a proxy's own 503, hostile server text).
 *
 * Mocks are installed before navigating: the footer fetches `/health` on page load. The glob
 * `**\/health` does not match the document URL `/ui/server-health`.
 */
import { expect, test, type Page } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait, selectOption } from "./helpers";

const UP_DEPENDENCY = { name: "sqlite", status: "UP", latency_ms: 1 };

async function mockHealth(page: Page, status: number, json: unknown): Promise<void> {
    await page.route("**/health", (route) => route.fulfill({ status, json }));
}

test.describe("Server Health page", () => {
    test("shows the real server health and its cluster nodes", async ({ page }) => {
        await gotoAndWait(page, "/ui/server-health");
        // The e2e server runs with SoftHSM, so UP and DEGRADED are both possible.
        await expect(page.getByTestId("health-status")).toHaveText(/^(UP|DEGRADED)$/, { timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("health-dependencies")).toContainText("Database");
        // A node publishes its heartbeat every few seconds: refresh until the list is filled.
        await expect(async () => {
            await page.getByTestId("submit-btn").click();
            await expect(page.getByTestId("cluster-node-id").first()).toBeVisible({ timeout: 2_000 });
        }).toPass({ timeout: UI_READY_TIMEOUT });
    });

    test("shows a DEGRADED node with the failing dependencies", async ({ page }) => {
        await mockHealth(page, 200, {
            status: "DEGRADED",
            latency_ms: 2,
            dependencies: {
                database: UP_DEPENDENCY,
                hsm: [{ name: "hsm", status: "DOWN", latency_ms: 2000, message: "slot 1: no answer within 2000 ms" }],
                kmip: {
                    name: "kmip",
                    status: "DOWN",
                    latency_ms: 0,
                    message: "the KMIP socket server is not running (details in the server log)",
                },
            },
        });
        await gotoAndWait(page, "/ui/server-health");
        await expect(page.getByTestId("health-status")).toHaveText("DEGRADED", { timeout: UI_READY_TIMEOUT });
        await expect(page.getByTestId("health-dependencies")).toContainText("no answer within 2000 ms");
        await expect(page.getByTestId("health-dependencies")).toContainText("the KMIP socket server is not running");
        await expect(page.getByTestId("footer-health")).toContainText("🟡");
    });

    test("shows a DOWN node (HTTP 503) and keeps the server version in the footer", async ({ page }) => {
        await mockHealth(page, 503, {
            status: "DOWN",
            latency_ms: 1,
            dependencies: {
                database: { ...UP_DEPENDENCY, status: "DOWN", message: "database check failed (details in the server log)" },
            },
        });
        await gotoAndWait(page, "/ui/server-health");
        await expect(page.getByTestId("health-status")).toHaveText("DOWN", { timeout: UI_READY_TIMEOUT });
        const footerHealth = page.getByTestId("footer-health");
        await expect(footerHealth).toContainText("🔴");
        await expect(footerHealth).toContainText("DOWN");
        // Regression: a failing /health used to replace the version by "Unavailable".
        await expect(page.getByText(/KMS Server Version:/)).toContainText(/KMS Server Version: \d+\.\d+\.\d+/);
    });

    test("auto-refresh polls /health at the chosen period until set back to manual", async ({ page }) => {
        let calls = 0;
        await page.route("**/health", (route) => {
            calls += 1;
            return route.fulfill({ status: 200, json: { status: "UP", latency_ms: 1, dependencies: { database: UP_DEPENDENCY } } });
        });
        await page.clock.install();
        await gotoAndWait(page, "/ui/server-health");
        await expect(page.getByTestId("health-status")).toHaveText("UP", { timeout: UI_READY_TIMEOUT });

        await page.clock.runFor(30_000);
        const idle = calls;

        await selectOption(page, "auto-refresh", "Every 5 s");
        await page.clock.runFor(5_000);
        await expect.poll(() => calls).toBeGreaterThan(idle);

        await selectOption(page, "auto-refresh", "Manual");
        const stopped = calls;
        await page.clock.runFor(60_000);
        expect(calls).toBe(stopped);
    });

    test("the chosen auto-refresh period is remembered after a reload", async ({ page }) => {
        await gotoAndWait(page, "/ui/server-health");
        await expect(page.getByTestId("health-status")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await selectOption(page, "auto-refresh", "Every 30 s");

        await page.reload();
        await expect(page.getByTestId("auto-refresh").locator(".ant-select-selection-item")).toHaveText("Every 30 s", {
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("refreshing the page also updates the footer marker", async ({ page }) => {
        let status = "UP";
        await page.route("**/health", (route) =>
            route.fulfill({ status: 200, json: { status, latency_ms: 1, dependencies: { database: UP_DEPENDENCY } } }),
        );
        await gotoAndWait(page, "/ui/server-health");
        await expect(page.getByTestId("footer-health")).toContainText("🟢", { timeout: UI_READY_TIMEOUT });

        status = "DEGRADED";
        await page.getByTestId("submit-btn").click();
        await expect(page.getByTestId("health-status")).toHaveText("DEGRADED");
        await expect(page.getByTestId("footer-health")).toContainText("🟡");
    });

    test("the footer health marker links to the page", async ({ page }) => {
        await gotoAndWait(page, "/ui/locate");
        await page.getByTestId("footer-health").click({ timeout: UI_READY_TIMEOUT });
        await expect(page).toHaveURL(/\/ui\/server-health$/);
        await expect(page.getByRole("heading", { name: "Server Health" })).toBeVisible();
    });

    test("renders hostile server text as inert text", async ({ page }) => {
        const hostileName = '<img src=x onerror="window.__xss=1">';
        const hostileMessage = "<script>window.__xss=1</script>";
        await mockHealth(page, 200, {
            status: "DEGRADED",
            latency_ms: 2,
            dependencies: {
                database: UP_DEPENDENCY,
                hsm: [{ name: hostileName, status: "DOWN", latency_ms: 2000, message: hostileMessage }],
            },
        });
        await gotoAndWait(page, "/ui/server-health");
        const dependencies = page.getByTestId("health-dependencies");
        await expect(dependencies).toContainText(hostileName, { timeout: UI_READY_TIMEOUT });
        await expect(dependencies).toContainText(hostileMessage);
        expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
        await expect(page.locator('img[src="x"]')).toHaveCount(0);
    });

    test("a proxy's own 503 body shows the marker as unavailable and the layout still renders", async ({ page }) => {
        await mockHealth(page, 503, { error: "upstream down" });
        await gotoAndWait(page, "/ui/locate");
        await expect(page.getByTestId("footer-health")).toContainText("🔴", { timeout: UI_READY_TIMEOUT });
        await expect(page.getByText(/KMS Server Version:/)).toContainText(/KMS Server Version: \d+\.\d+\.\d+/);
        await expect(page.getByTestId("submit-btn").first()).toBeVisible();
    });
});
