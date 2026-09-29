/**
 * ObjectsReKey generic component — E2E tests.
 *
 * Covers all four key-type variants served by the single generic component:
 *   • symmetric  — /ui/sym/keys/rekey
 *   • rsa        — /ui/rsa/keys/rekey
 *   • ec         — /ui/ec/keys/rekey
 *   • pqc        — /ui/pqc/keys/rekey  (skipped in FIPS mode)
 *
 * For each variant the tests verify:
 *   1. Page renders (heading + submit button visible)
 *   2. Successful re-key operation produces a new unique identifier
 */
import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    createEcKeyPair,
    createPqcKeyPair,
    createRsaKeyPair,
    createSymKey,
    extractAllUuids,
    extractUuidAfterLabel,
    gotoAndWait,
    submitAndWaitForResponse,
} from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

// ── Symmetric key ────────────────────────────────────────────────────────────

test.describe("ObjectsReKey — symmetric", () => {
    test("renders the re-key form", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/rekey");
        await expect(page.getByRole("heading", { name: /Re-Key a symmetric key/i })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("re-keys an AES symmetric key and returns a new key ID", async ({ page }) => {
        const originalKeyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/rekey");
        await page.locator('[data-testid="rekey-key-id"]').fill(originalKeyId);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/successfully refreshed/i);
        const uuids = extractAllUuids(text);
        expect(uuids.length).toBeGreaterThanOrEqual(1);
        const newKeyId = uuids[0];
        // The returned identifier must be a distinct UUID (the server creates a new object)
        expect(newKeyId).not.toEqual(originalKeyId);
    });
});

// ── RSA key pair ─────────────────────────────────────────────────────────────

test.describe("ObjectsReKey — RSA", () => {
    test("renders the RSA re-key form", async ({ page }) => {
        await gotoAndWait(page, "/ui/rsa/keys/rekey");
        await expect(page.getByRole("heading", { name: /Re-Key an RSA key pair/i })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("re-keys an RSA key pair and returns two new key IDs", async ({ page }) => {
        const { privKeyId: originalPrivId, pubKeyId: originalPubId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rsa/keys/rekey");
        await page.locator('[data-testid="rekey-key-id"]').fill(originalPrivId);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/successfully rotated/i);
        expect(text).toMatch(/New private key:/i);
        expect(text).toMatch(/New public key:/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toEqual(originalPrivId);
        expect(newPubId).not.toEqual(originalPubId);
        expect(newPrivId).not.toEqual(newPubId);
    });
});

// ── EC key pair ───────────────────────────────────────────────────────────────

test.describe("ObjectsReKey — EC", () => {
    test("renders the EC re-key form", async ({ page }) => {
        await gotoAndWait(page, "/ui/ec/keys/rekey");
        await expect(page.getByRole("heading", { name: /Re-Key an Elliptic Curve key pair/i })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("re-keys a NIST P-256 EC key pair and returns two new key IDs", async ({ page }) => {
        const { privKeyId: originalPrivId, pubKeyId: originalPubId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/ec/keys/rekey");
        await page.locator('[data-testid="rekey-key-id"]').fill(originalPrivId);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/successfully rotated/i);
        expect(text).toMatch(/New private key:/i);
        expect(text).toMatch(/New public key:/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toEqual(originalPrivId);
        expect(newPubId).not.toEqual(originalPubId);
        expect(newPrivId).not.toEqual(newPubId);
    });
});

// ── PQC key pair (non-FIPS only) ─────────────────────────────────────────────

test.describe("ObjectsReKey — PQC", () => {
    test.skip(FIPS_MODE, "Post-quantum algorithms are not available in FIPS mode");

    test("renders the PQC re-key form", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/keys/rekey");
        await expect(page.getByRole("heading", { name: /Re-Key a Post-Quantum key pair/i })).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({ timeout: UI_READY_TIMEOUT });
    });

    test("re-keys an ML-KEM-512 key pair and returns two new key IDs", async ({ page }) => {
        const { privKeyId: originalPrivId, pubKeyId: originalPubId } = await createPqcKeyPair(page, "ML-KEM-512");

        await gotoAndWait(page, "/ui/pqc/keys/rekey");
        await page.locator('[data-testid="rekey-key-id"]').fill(originalPrivId);
        const text = await submitAndWaitForResponse(page);

        expect(text).toMatch(/successfully rotated/i);
        expect(text).toMatch(/New private key:/i);
        expect(text).toMatch(/New public key:/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toEqual(originalPrivId);
        expect(newPubId).not.toEqual(originalPubId);
        expect(newPrivId).not.toEqual(newPubId);
    });
});
