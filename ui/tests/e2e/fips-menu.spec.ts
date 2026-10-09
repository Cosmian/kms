/**
 * FIPS-mode UI gating E2E tests.
 *
 * Features that do not exist in a FIPS build (OpenPGP, PQC, MAC, FPE, Anonymize,
 * Covercrypt) must neither appear in the sidebar nor be reachable by typing their URL.
 *
 * The server reports its mode through `/server-info`; the response is overridden here
 * so the same assertions run against any server variant.
 */
import { expect, test, type Page } from "@playwright/test";
import { UI_READY_TIMEOUT, gotoAndWait } from "./helpers";

/** Top-level sidebar keys that are not available in FIPS mode. */
const NON_FIPS_MENUS = ["pgp", "pqc", "mac", "fpe", "tokenize", "cc"];

async function forceFipsMode(page: Page, fipsMode: boolean): Promise<void> {
    await page.route("**/server-info", async (route) => {
        const response = await route.fetch();
        const info = (await response.json()) as Record<string, unknown>;
        await route.fulfill({ response, json: { ...info, fips_mode: fipsMode } });
    });
}

const topMenu = (page: Page, key: string) => page.locator(`[data-menu-id$="-${key}"]`);

test.describe("FIPS mode UI gating", () => {
    test("non-FIPS menus are hidden in the sidebar when the server is in FIPS mode", async ({ page }) => {
        await forceFipsMode(page, true);
        await gotoAndWait(page, "/ui/locate");
        // Wait for the menu to be rendered before asserting absences.
        await expect(topMenu(page, "sym")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        for (const key of NON_FIPS_MENUS) {
            await expect(topMenu(page, key), `menu "${key}" must be hidden in FIPS mode`).toHaveCount(0);
        }
    });

    test("non-FIPS pages are not reachable by URL when the server is in FIPS mode", async ({ page }) => {
        await forceFipsMode(page, true);
        for (const path of ["pgp/encrypt", "pgp/keys/create", "pqc/keys/create", "mac/compute", "fpe/encrypt", "tokenize/hash"]) {
            await gotoAndWait(page, `/ui/${path}`);
            await expect(page).toHaveURL(/\/ui\/locate$/, { timeout: UI_READY_TIMEOUT });
        }
    });

    test("OpenPGP menu is shown when the server is not in FIPS mode", async ({ page }) => {
        await forceFipsMode(page, false);
        await gotoAndWait(page, "/ui/locate");
        await expect(topMenu(page, "pgp")).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await gotoAndWait(page, "/ui/pgp/encrypt");
        await expect(page).toHaveURL(/\/ui\/pgp\/encrypt$/);
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });
});
