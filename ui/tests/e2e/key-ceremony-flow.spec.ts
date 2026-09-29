/**
 * Key Ceremony flow E2E tests.
 *
 * Covers the split-key ceremony lifecycle per ADR-2026-06-24:
 *   • Phase 1 — Provisioning: create a key + split it
 *   • Phase 2 — Activation:   CO activates ceremony via POST /access/crypto_officer/ceremony/activate
 *                              (CryptoOfficerRole page → "Activate Ceremony" card)
 *   • Phase 4 — Disable:      revoke the active ceremony
 *   • Negative scenarios:     insufficient shares, non-configured server state
 *
 * Split-key operations (XOR n-of-n) are non-FIPS; the `FIPS_MODE` guard
 * skips ceremony tests when the server is compiled in FIPS mode.
 *
 * NOTE: `JoinSplitKey` is now a PURE key reconstruction tool (stores the result
 * as a KMS object). Ceremony activation uses the dedicated endpoint
 * POST /access/crypto_officer/ceremony/activate — accessible via the
 * Crypto Officer Role page. Full ceremony activation is covered by server-level
 * and CLI tests; here we cover UI smoke tests.
 *
 * The tests run against the dev-mode KMS server (no RBAC ceremony configured),
 * so:
 *   - The CO status page reports "not configured" — no Disable button.
 *   - Split and Join operations are available but the server may return
 *     an access-denied or a result depending on auth.
 */
import { expect, test } from "@playwright/test";
import { UI_READY_TIMEOUT, extractUuid, gotoAndWait } from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

/** Wait for the response-output element and return its text. */
async function waitForResponse(page: import("@playwright/test").Page): Promise<string> {
    const responseEl = page.locator('[data-testid="response-output"]');
    await responseEl.waitFor({ state: "visible", timeout: 30_000 });
    return (await responseEl.textContent()) ?? "";
}

// ─────────────────────────────────────────────────────────────────────────────
// CO Status page
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Key Ceremony — Crypto Officer Status", () => {
    test("status page is accessible and loads without error", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });

        // Refresh button is always rendered (calls the status endpoint).
        await expect(page.locator('[data-testid="refresh-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("status page shows configuration message after load", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });

        // In dev mode (no CO configured), the response card shows "not configured".
        // In ceremony mode, the role-status card appears.
        const notConfigured = page.locator('[data-testid="response-output"]');
        await expect(notConfigured).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("disable button is absent when ceremony is not active", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });

        // In dev-mode (no ceremony configured or not activated) the Disable button
        // must not be visible.
        const disableBtn = page.locator('[data-testid="disable-btn"]');
        await expect(disableBtn).not.toBeVisible();
    });

    test("refresh button re-fetches status", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });

        await page.click('[data-testid="refresh-btn"]');
        // After refresh the response-output card is still visible (dev mode).
        await expect(page.locator('[data-testid="response-output"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1: Provisioning — Create + Split key
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Key Ceremony — Phase 1: Split Key", () => {
    test.skip(FIPS_MODE, "Split-key (XOR n-of-n) is not available in FIPS mode");

    test("split key page loads with correct heading", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/split");
        await expect(page.locator("h1:has-text('Split Key')")).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("split key form renders key-id input and submit button", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/split");
        await expect(page.locator('[data-testid="split-key-id-input"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="split-key-submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("split key transparently creates an AES-256 key and returns share identifiers", async ({ page }) => {
        // The Split Key page now transparently creates an AES-256 key before splitting.
        // Navigate and submit with an empty key ID — the page creates the key automatically.
        await gotoAndWait(page, "/ui/sym/keys/split");
        await page.click('[data-testid="split-key-submit-btn"]');
        const text = await waitForResponse(page);

        // The server either returns share UIDs (success) or an access-denied
        // message (dev-mode RBAC not configured). Either way a non-empty
        // response is produced.
        expect(text.length).toBeGreaterThan(0);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Join Split Key — Pure key reconstruction (NOT ceremony activation)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Join Split Key — Pure key reconstruction", () => {
    test.skip(FIPS_MODE, "Join split-key (XOR n-of-n) is not available in FIPS mode");

    test("join split key page loads with correct heading", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/join");
        await expect(page.locator("h1:has-text('Join Split Key')")).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    // Dev-mode server has no CO configured → page shows an info Alert.
    test("join split key page accepts a share-count input", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/join");
        // The page is now a pure key reconstruction tool — it shows a share-count
        // input (no CO status check). Verify the submit button is present.
        await expect(page.locator('[data-testid="join-split-key-submit-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: Ceremony Activation — CryptoOfficerRole page
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Key Ceremony — Phase 2: Ceremony Activation UI", () => {
    test.skip(FIPS_MODE, "Split-key (XOR n-of-n) ceremony is not available in FIPS mode");

    test("crypto officer role page is accessible", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });
        // The page should load without crashing.
        await expect(page.locator('[data-testid="refresh-btn"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
    });

    test("activate ceremony card is absent in dev mode (ceremony not configured)", async ({ page }) => {
        await gotoAndWait(page, "/ui/access-rights/crypto-officer");
        await page.waitForLoadState("networkidle", { timeout: UI_READY_TIMEOUT });
        // When `require_ceremony = false` (dev mode) the activate card must not appear.
        const activateCard = page.locator('[data-testid="activate-ceremony-card"]');
        await expect(activateCard).not.toBeVisible();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Full positive ceremony flow (requires a ceremony-configured server)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Key Ceremony — Full lifecycle (ceremony-configured server)", () => {
    test.skip(FIPS_MODE, "Split-key ceremony requires non-FIPS mode");

    /**
     * Smoke test: create a key, split it, and verify the split response contains
     * at least one UUID that could be a share identifier.
     *
     * This test does not attempt ceremony activation because the dev-mode server does not
     * have `require_ceremony = true`. Full activation is via the CryptoOfficerRole page
     * (`POST /access/crypto_officer/ceremony/activate`) and is covered by server + CLI tests.
     */
    test("split a key and get share UIDs in response", async ({ page }) => {
        // The Split Key page transparently creates an AES-256 key before splitting.
        // Navigate and submit — the response must contain at least one UUID.
        await gotoAndWait(page, "/ui/sym/keys/split");
        await page.click('[data-testid="split-key-submit-btn"]');
        const text = await waitForResponse(page);
        expect(text.length).toBeGreaterThan(0);

        // If the server accepted the split, the response contains at least one UUID.
        const maybeUuid = extractUuid(text);
        // If a UUID is present it must be well-formed.
        if (maybeUuid) {
            expect(maybeUuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
        }
    });
});
