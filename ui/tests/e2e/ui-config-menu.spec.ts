import { expect, test, type Page } from "@playwright/test";
import { gotoAndWait } from "./helpers";

const optionalSections = ["kv-secrets", "hsm-status", "google-cse", "access-rights/crypto-officer"];
const flags = { kv: false, hsm: false, google_cse: false, crypto_officer: false };

async function mockUiConfig(page: Page, config?: typeof flags) {
    await page.route("**/ui/config", async (route) => {
        const origin = route.request().headers().origin;
        const headers = origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : undefined;
        await route.fulfill(config ? { headers, json: config } : { headers, status: 404 });
    });
}

async function expandOptionalGroups(page: Page) {
    for (const group of ["access-rights", "hyperscalers"]) {
        await page.getByTestId(`menu-${group}`).click();
    }
}

test("disabled sections stay out of the menu and cannot be opened by URL", async ({ page }) => {
    await mockUiConfig(page, flags);
    for (const section of optionalSections) {
        await gotoAndWait(page, `/ui/${section}`);
        await expect(page).toHaveURL(/\/ui\/locate$/);
    }
    await expandOptionalGroups(page);
    for (const section of optionalSections) {
        await expect(page.getByTestId(`menu-${section}`)).toHaveCount(0);
    }

    await gotoAndWait(page, "/ui/certificates/certs/generate-csr");
    await page.getByTestId("csr-key-source-generate").click();
    await expect(page.getByTestId("csr-algorithm-select")).toBeVisible();
    await expect(page.getByTestId("csr-in-hsm")).toHaveCount(0);
});

test("enabled sections appear and a bookmarked page stays open", async ({ page }) => {
    await mockUiConfig(page, { kv: true, hsm: true, google_cse: true, crypto_officer: true });
    await gotoAndWait(page, "/ui/kv-secrets");
    await expect(page.getByTestId("kv-mount")).toBeVisible();
    await expect(page).toHaveURL(/\/ui\/kv-secrets$/);
    for (const [section, parent] of [
        ["kv-secrets", undefined],
        ["hsm-status", undefined],
        ["access-rights/crypto-officer", "access-rights"],
        ["google-cse", "hyperscalers"],
    ]) {
        if (parent) await page.getByTestId(`menu-${parent}`).click();
        await expect(page.getByTestId(`menu-${section}`)).toBeVisible();
    }
});

test("missing config keeps the existing menu and explains the dev fallback", async ({ page }) => {
    await mockUiConfig(page);
    await gotoAndWait(page, "/ui/kv-secrets");
    await expect(page.getByTestId("kv-mount")).toBeVisible();
    await expect(page.getByTestId("menu-kv-secrets")).toBeVisible();
    await page.getByTestId("dev-mode-banner").hover();
    await expect(page.getByRole("tooltip")).toContainText(/default menu is shown/i);
});
