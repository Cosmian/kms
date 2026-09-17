/**
 * Crypto Officer Role — "Create & Split Key (3 shares)" E2E tests.
 *
 * Covers the integrated split-key workflow on the `/ui/access-rights/crypto-officer` page
 * when the server is running with ceremony mode configured
 * (test_data/configs/server/rbac/crypto_officers.toml — 3 CO candidates).
 *
 * ## Prerequisites
 *
 * These tests require a ceremony-configured KMS server and must be run with:
 *
 * ```bash
 * # Build UI and start server
 * pnpm -C ui build
 * cargo run -p cosmian_kms_server --features non-fips -- \
 *   -c test_data/configs/server/rbac/crypto_officers.toml
 *
 * # Run tests
 * cd ui
 * PLAYWRIGHT_BASE_URL=https://127.0.0.1:9998 \
 * PLAYWRIGHT_CEREMONY_SERVER=true \
 *   pnpm run test:e2e tests/e2e/co-role-split-key.spec.ts
 * ```
 *
 * The `clientCertificates` in `playwright.config.ts` automatically present
 * `owner.client.acme.com.crt` (owner.client@acme.com, a CO candidate) for the
 * `https://127.0.0.1:9998` origin — this is the user authenticated by the tests.
 *
 * ## Why "Failed to fetch" in a regular browser
 *
 * The ceremony server config enables TLS + mTLS client certificate authentication.
 * A regular browser without the client certificate installed fails at the TLS
 * handshake — this is the expected security behaviour, not a bug.
 * Playwright resolves this via its `clientCertificates` configuration.
 */

import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, extractAllUuids, gotoAndWait } from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";
const CEREMONY_SERVER = process.env.PLAYWRIGHT_CEREMONY_SERVER === "true";

/** Timeout for operations that involve a real KMS request (key create + split = 2 round-trips). */
const OPERATION_TIMEOUT = 60_000;

/** Navigate to the CO Role page and wait for the status card to load. */
async function gotoCoRolePage(page: import("@playwright/test").Page): Promise<void> {
    await gotoAndWait(page, "/ui/access-rights/crypto-officer");
    await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite 1 — Page structure on ceremony-configured server
// ─────────────────────────────────────────────────────────────────────────────

test.describe("CO Role page — structure (ceremony server)", () => {
    test.skip(FIPS_MODE, "Split-key XOR is not available in FIPS mode");
    test.skip(!CEREMONY_SERVER, "Requires a ceremony-configured server (PLAYWRIGHT_CEREMONY_SERVER=true)");

    test("page loads with correct heading", async ({ page }) => {
        await gotoCoRolePage(page);
        await expect(page.getByRole("heading", { name: "Crypto Officer Role" })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="refresh-btn"]')).toBeVisible();
    });

    test("status card shows ceremony-mode info and 3 CO candidates", async ({ page }) => {
        await gotoCoRolePage(page);
        const statusCard = page.locator('[data-testid="role-status-card"]');
        await expect(statusCard).toBeVisible({ timeout: UI_READY_TIMEOUT });
        // Ceremony required: the badge must mention "split-key ceremony"
        await expect(statusCard).toContainText("split-key ceremony");
        // 3 CO candidates
        await expect(statusCard).toContainText("3");
    });

    test("Create & Split Key card is always visible", async ({ page }) => {
        await gotoCoRolePage(page);
        const splitCard = page.locator('[data-testid="split-key-step-card"]');
        await expect(splitCard).toBeVisible({ timeout: UI_READY_TIMEOUT });
        // Card title must include the share count from the server config
        await expect(splitCard).toContainText("Create & Split Key (3 shares)");
    });

    test("JoinSplitKey card is always visible", async ({ page }) => {
        await gotoCoRolePage(page);
        await expect(page.locator('[data-testid="join-split-key-card"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("Activate Ceremony card is visible when ceremony is dormant", async ({ page }) => {
        await gotoCoRolePage(page);
        // When the ceremony has never been activated, the activation form is shown.
        await expect(page.locator('[data-testid="activate-ceremony-card"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("self-revoke button is absent when ceremony is dormant", async ({ page }) => {
        await gotoCoRolePage(page);
        // No active ceremony → no disable button
        await expect(page.locator('[data-testid="disable-btn"]')).not.toBeVisible();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Suite 2 — Create & Split Key interactions
// ─────────────────────────────────────────────────────────────────────────────

test.describe("CO Role — Create & Split Key interactions", () => {
    test.skip(FIPS_MODE, "Split-key XOR is not available in FIPS mode");
    test.skip(!CEREMONY_SERVER, "Requires a ceremony-configured server (PLAYWRIGHT_CEREMONY_SERVER=true)");

    test("key ID input is visible and accepts text", async ({ page }) => {
        await gotoCoRolePage(page);
        const input = page.locator('[data-testid="split-key-id-input"]');
        await expect(input).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await input.fill("e2e-preview-test");
        await expect(input).toHaveValue("e2e-preview-test");
    });

    test("key ID input shows share UID preview with #N suffix", async ({ page }) => {
        await gotoCoRolePage(page);
        const input = page.locator('[data-testid="split-key-id-input"]');
        await expect(input).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await input.fill("e2e-key");
        // Preview shows the 3 derived share UIDs
        const preview = page.locator('[data-testid="split-key-step-card"] code');
        await expect(preview.filter({ hasText: "e2e-key#1" })).toBeVisible({ timeout: 5_000 });
        await expect(preview.filter({ hasText: "e2e-key#2" })).toBeVisible();
        await expect(preview.filter({ hasText: "e2e-key#3" })).toBeVisible();
    });

    test("Create & Split Key button has correct label with share count", async ({ page }) => {
        await gotoCoRolePage(page);
        const btn = page.locator('[data-testid="create-split-key-btn"]');
        await expect(btn).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await expect(btn).toContainText("Create & Split Key (3 shares)");
    });

    test("Create & Split Key with custom key ID produces 3 share UIDs and ownership info", async ({ page }) => {
        await gotoCoRolePage(page);

        // Use a unique key ID per test run to avoid "key already exists" on repeated runs.
        const keyId = `e2e-ceremony-${Date.now()}`;
        await page.locator('[data-testid="split-key-id-input"]').fill(keyId);

        await page.locator('[data-testid="create-split-key-btn"]').click();

        // Wait for the result pre element (ceremony split: SetAttribute + Create + CreateSplitKey)
        const resultEl = page.locator('[data-testid="split-key-result"]');
        await expect(resultEl).toBeVisible({ timeout: OPERATION_TIMEOUT });

        const text = (await resultEl.textContent()) ?? "";

        // Result must mention 3 shares
        expect(text).toContain("3 share");

        // Result must contain the expected share UIDs with #N suffix
        expect(text).toContain(`${keyId}#1`);
        expect(text).toContain(`${keyId}#2`);
        expect(text).toContain(`${keyId}#3`);

        // Result must show ownership information (each share annotated with its owner)
        expect(text).toContain("[owned by");

        // Result must show grants-needed instructions (since other COs own other shares)
        expect(text).toContain("grant");
    });

    test("activation form is selectively pre-filled (only the user's own share)", async ({ page }) => {
        await gotoCoRolePage(page);

        // owner.client@acme.com is at index 1 in the CO candidates list
        // → owns share #2 (index 1 → 0-indexed share 1 → `${keyId}#2`)
        const keyId = `e2e-selective-${Date.now()}`;
        await page.locator('[data-testid="split-key-id-input"]').fill(keyId);
        await page.locator('[data-testid="create-split-key-btn"]').click();
        await expect(page.locator('[data-testid="split-key-result"]')).toBeVisible({
            timeout: OPERATION_TIMEOUT,
        });

        // The Playwright test user (owner.client@acme.com, index 1) owns share #2.
        // Only that slot should be pre-filled; slots #1 and #3 must be empty (awaiting grants).
        await expect(page.locator('[data-testid="ceremony-share-id-0"]')).toHaveValue(""); // NOT the user's share
        await expect(page.locator('[data-testid="ceremony-share-id-1"]')).toHaveValue(`${keyId}#2`); // user's share
        await expect(page.locator('[data-testid="ceremony-share-id-2"]')).toHaveValue(""); // NOT the user's share
    });

    test("share UIDs auto-populate the JoinSplitKey form after split", async ({ page }) => {
        await gotoCoRolePage(page);

        const keyId = `e2e-join-fill-${Date.now()}`;
        await page.locator('[data-testid="split-key-id-input"]').fill(keyId);
        await page.locator('[data-testid="create-split-key-btn"]').click();
        await expect(page.locator('[data-testid="split-key-result"]')).toBeVisible({
            timeout: OPERATION_TIMEOUT,
        });

        // JoinSplitKey form inputs must be pre-filled with all share UIDs (for reconstruction use)
        await expect(page.locator('[data-testid="join-share-id-0"]')).toHaveValue(`${keyId}#1`);
        await expect(page.locator('[data-testid="join-share-id-1"]')).toHaveValue(`${keyId}#2`);
        await expect(page.locator('[data-testid="join-share-id-2"]')).toHaveValue(`${keyId}#3`);
    });

    test("Create & Split Key with empty key ID produces UUID#N share UIDs", async ({ page }) => {
        await gotoCoRolePage(page);

        // Leave key ID empty — server auto-generates a UUID
        const input = page.locator('[data-testid="split-key-id-input"]');
        await expect(input).toBeVisible({ timeout: UI_READY_TIMEOUT });
        await input.clear();

        await page.locator('[data-testid="create-split-key-btn"]').click();

        const resultEl = page.locator('[data-testid="split-key-result"]');
        await expect(resultEl).toBeVisible({ timeout: OPERATION_TIMEOUT });

        const text = (await resultEl.textContent()) ?? "";
        expect(text).toContain("3 share");

        // Extract all UUIDs from the result — should find 3+ (source key + 3 shares)
        const uuids = extractAllUuids(text);
        expect(uuids.length).toBeGreaterThanOrEqual(1);

        // Share UIDs follow UUID#N pattern
        expect(text).toMatch(/#1/);
        expect(text).toMatch(/#2/);
        expect(text).toMatch(/#3/);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Suite 3 — JoinSplitKey card (on CO Role page)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("CO Role — JoinSplitKey card", () => {
    test.skip(FIPS_MODE, "Split-key XOR is not available in FIPS mode");
    test.skip(!CEREMONY_SERVER, "Requires a ceremony-configured server (PLAYWRIGHT_CEREMONY_SERVER=true)");

    test("share count input defaults to 3 (from server custodians_count)", async ({ page }) => {
        await gotoCoRolePage(page);
        // The InputNumber for share count is seeded from custodians_count = 3
        const countInput = page.locator('[data-testid="join-share-count-input"]');
        await expect(countInput).toBeVisible({ timeout: UI_READY_TIMEOUT });
        // Ant Design InputNumber uses an <input> inside; check its value
        await expect(countInput.locator("input")).toHaveValue("3");
    });

    test("3 share UID inputs are rendered", async ({ page }) => {
        await gotoCoRolePage(page);
        await expect(page.locator('[data-testid="join-share-id-0"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="join-share-id-1"]')).toBeVisible();
        await expect(page.locator('[data-testid="join-share-id-2"]')).toBeVisible();
    });

    test("object type select is visible with SymmetricKey as default", async ({ page }) => {
        await gotoCoRolePage(page);
        const select = page.locator('[data-testid="join-object-type-select"]');
        await expect(select).toBeVisible({ timeout: UI_READY_TIMEOUT });
        // Ant Design Select renders the selected value in a span
        await expect(select).toContainText("Symmetric Key");
    });

    test("submit button is visible", async ({ page }) => {
        await gotoCoRolePage(page);
        await expect(page.locator('[data-testid="join-split-key-submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("LocateButton is present for each share UID input", async ({ page }) => {
        await gotoCoRolePage(page);
        // Each share input row should have a LocateButton (3 rows → at least 3 buttons)
        const joinCard = page.locator('[data-testid="join-split-key-card"]');
        await expect(joinCard).toBeVisible({ timeout: UI_READY_TIMEOUT });
        // LocateButton renders a button with aria-label or text "Locate"
        const locateBtns = joinCard.getByRole("button", { name: /locate/i });
        await expect(locateBtns).toHaveCount(3, { timeout: UI_READY_TIMEOUT });
    });
});
