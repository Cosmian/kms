/**
 * Secrets (KV) flow E2E tests.
 *
 * Requires the KMS to run with `[kv] kv_enabled = true` (set by `test_ui.sh` / `test_ui.ps1`).
 *
 * Covers:
 *   • put then get, values masked until revealed
 *   • get of a previous version
 *   • list: folder navigation and opening a secret in the Get tab
 *   • list of an unknown prefix
 *   • soft delete of the latest version, then destroy of all versions
 *   • put from a JSON file (value types kept)
 *   • invalid file, duplicate keys, unknown mount
 */
import { expect, test, type Page } from "@playwright/test";
import { gotoAndWait, UI_READY_TIMEOUT, uploadFile, writeTempFile } from "./helpers";

const tid = (id: string) => `[data-testid="${id}"]`;

/** Antd keeps visited inactive tab panes in the DOM (hidden); `getByRole` only matches the visible one. */
const pane = (page: Page) => page.getByRole("tabpanel");

/** Unique per call: workers share one server and tests are retried. */
const uniq = () => `e2e-kv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

async function openKv(page: Page): Promise<void> {
    await gotoAndWait(page, "/ui/kv-secrets");
    await expect(page.locator(tid("kv-mount"))).toBeVisible({ timeout: UI_READY_TIMEOUT });
}

async function openTab(page: Page, key: "put" | "get" | "list" | "delete"): Promise<void> {
    await page.locator(tid(`kv-tab-${key}`)).click();
}

async function putSecret(page: Page, path: string, pairs: [string, string][], expectedVersion = 1): Promise<void> {
    await openKv(page);
    await page.locator(tid("kv-put-path")).fill(path);
    for (const [i, [key, value]] of pairs.entries()) {
        if (i > 0) await page.locator(tid("kv-put-add")).click();
        await page.locator(tid(`kv-put-key-${i}`)).fill(key);
        await page.locator(tid(`kv-put-value-${i}`)).fill(value);
    }
    await pane(page).locator(tid("submit-btn")).click();
    await expect(page.locator(tid("kv-put-result"))).toHaveText(new RegExp(`Secret written \\(version ${expectedVersion}\\)`));
}

async function getSecret(page: Page, path: string, version?: number): Promise<void> {
    await openTab(page, "get");
    await page.locator(tid("kv-get-path")).fill(path);
    await page.locator(tid("kv-get-version")).fill(version ? String(version) : "");
    await pane(page).locator(tid("submit-btn")).click();
}

async function revealed(page: Page) {
    const out = pane(page).locator(tid("response-output"));
    await expect(out).toBeVisible();
    await pane(page).locator(tid("kv-reveal")).click();
    return out;
}

test.describe("Secrets (KV)", () => {
    test("put then get masks values until revealed", async ({ page }) => {
        const p = `${uniq()}/db`;
        const pw = `pw-${uniq()}`;
        await putSecret(page, p, [
            ["username", "admin"],
            ["password", pw],
        ]);
        await getSecret(page, p);
        const out = pane(page).locator(tid("response-output"));
        await expect(out).toBeVisible();
        await expect(out).toContainText("••••••••");
        await expect(out).not.toContainText(pw);
        await pane(page).locator(tid("kv-reveal")).click();
        await expect(out).toContainText(pw);
        await expect(out).toContainText("admin");
        await expect(pane(page).locator(tid("kv-reveal"))).toHaveText(/Hide values/);
    });

    test("get a previous version", async ({ page }) => {
        const p = uniq();
        await putSecret(page, p, [["k", "v1"]]);
        await putSecret(page, p, [["k", "v2"]], 2);
        await getSecret(page, p, 1);
        const old = await revealed(page);
        await expect(old).toContainText("v1");
        await expect(old).not.toContainText("v2");
        await getSecret(page, p);
        await expect(await revealed(page)).toContainText("v2");
    });

    test("list navigates folders and opens a secret in Get", async ({ page }) => {
        const base = uniq();
        for (const leaf of ["app/db", "app/api", "top"]) {
            await putSecret(page, `${base}/${leaf}`, [["k", "v"]]);
        }
        await openTab(page, "list");
        await page.locator(tid("kv-list-prefix")).fill(base);
        await pane(page).locator(tid("submit-btn")).click();
        await expect(page.locator(tid("kv-key-app/"))).toBeVisible();
        await expect(page.locator(tid("kv-key-top"))).toBeVisible();
        await page.locator(tid("kv-key-app/")).click();
        await expect(page.locator(tid("kv-list-prefix"))).toHaveValue(`${base}/app/`);
        await expect(page.locator(tid("kv-key-db"))).toBeVisible();
        await expect(page.locator(tid("kv-key-api"))).toBeVisible();
        await page.locator(tid("kv-key-db")).click();
        await expect(page.locator(tid("kv-get-path"))).toHaveValue(`${base}/app/db`);
        await expect(pane(page).locator(tid("response-output"))).toBeVisible();
    });

    test("list of an unknown prefix shows no keys", async ({ page }) => {
        // Put first: the UI maps any LIST 404 (also an unregistered KV route) to "No keys found".
        const base = uniq();
        await putSecret(page, `${base}/x`, [["k", "v"]]);
        await openTab(page, "list");
        await page.locator(tid("kv-list-prefix")).fill(`${base}/missing`);
        await pane(page).locator(tid("submit-btn")).click();
        await expect(pane(page).locator(tid("response-output"))).toContainText("No keys found");
    });

    test("soft delete hides latest version; destroy removes all", async ({ page }) => {
        const p = uniq();
        await putSecret(page, p, [["k", "v1"]]);
        await putSecret(page, p, [["k", "v2"]], 2);
        await openTab(page, "delete");
        await page.locator(tid("kv-delete-path")).fill(p);
        await page.locator(tid("kv-delete-soft")).click();
        await page.locator(tid("kv-confirm-ok")).click();
        await expect(page.getByText("Latest version deleted")).toBeVisible();
        await getSecret(page, p);
        await expect(page.locator(tid("kv-error"))).toHaveText(/404/);
        await getSecret(page, p, 1);
        await expect(pane(page).locator(tid("response-output"))).toBeVisible();
        await openTab(page, "delete");
        await page.locator(tid("kv-delete-path")).fill(p);
        await page.locator(tid("kv-delete-destroy")).click();
        await page.locator(tid("kv-confirm-ok")).click();
        await expect(page.getByText("All versions destroyed")).toBeVisible();
        await getSecret(page, p, 1);
        // A destroyed path answers 403, like an unknown one: the server does not reveal which paths exist.
        await expect(page.locator(tid("kv-error"))).toHaveText(/403/);
    });

    test("put from a JSON file keeps value types", async ({ page }) => {
        const file = writeTempFile(`${uniq()}.json`, JSON.stringify({ port: 5432, enabled: true, name: "db" }));
        const p = uniq();
        await openKv(page);
        await uploadFile(page, file);
        await expect(page.locator(tid("kv-put-file-loaded"))).toHaveText(/3 key\(s\) loaded from/);
        await expect(page.locator(tid("kv-put-key-0"))).toHaveCount(0);
        await page.locator(tid("kv-put-path")).fill(p);
        await pane(page).locator(tid("submit-btn")).click();
        await expect(page.locator(tid("kv-put-result"))).toHaveText(/version 1/);
        await getSecret(page, p);
        const out = await revealed(page);
        await expect(out).toContainText("5432");
        await expect(out).toContainText("true");
    });

    test("rejects an invalid JSON file and duplicate keys", async ({ page }) => {
        await openKv(page);
        await uploadFile(page, writeTempFile(`${uniq()}.json`, "[1,2]"));
        await expect(page.locator(tid("kv-error"))).toHaveText("The file must contain a non-empty JSON object.");

        await openKv(page);
        await page.locator(tid("kv-put-path")).fill(uniq());
        await page.locator(tid("kv-put-key-0")).fill("a");
        await page.locator(tid("kv-put-value-0")).fill("1");
        await page.locator(tid("kv-put-add")).click();
        await page.locator(tid("kv-put-key-1")).fill("a");
        await page.locator(tid("kv-put-value-1")).fill("2");
        await pane(page).locator(tid("submit-btn")).click();
        await expect(page.locator(tid("kv-error"))).toHaveText("The key a is given more than once.");
        await expect(page.locator(tid("kv-put-result"))).toHaveCount(0);
    });

    test("unknown mount reports an error", async ({ page }) => {
        await openKv(page);
        await page.locator(tid("kv-mount")).fill("nomount-e2e");
        await getSecret(page, uniq());
        // An unregistered route may surface as 404 or a CORS "Failed to fetch".
        await expect(page.locator(tid("kv-error"))).toBeVisible();
    });
});
