/**
 * Key rotation policy E2E tests.
 *
 * Covers per-key-type (symmetric, RSA, EC, PQC):
 *   • set-rotation-policy  – configure interval, offset and keyset name
 *   • get-rotation-policy  – retrieve and verify the configured values
 *   • get-rotation-policy  – returns "no policy" for fresh (unconfigured) keys
 *   • rekey                – rotate the key and verify a new UID is returned
 *
 * Also covers certificate renewal via the KMIP ReCertify operation (Option 3
 * on the Certificate Issuance page):
 *   • re-certify self-signed RSA certificate → new UID ≠ original UID
 *   • re-certify self-signed EC P-256 certificate → new UID ≠ original UID
 *   • re-certify PQC ML-DSA-44 certificate (skip FIPS) → new UID ≠ original UID
 *
 * PQC tests are skipped when running in FIPS mode because ML-DSA / ML-KEM are
 * not FIPS-approved algorithms.
 */

import { expect, test } from "@playwright/test";
import {
    UI_READY_TIMEOUT,
    createCertificate,
    createEcKeyPair,
    createPqcKeyPair,
    createRsaKeyPair,
    createSymKey,
    extractUuid,
    extractUuidAfterLabel,
    gotoAndWait,
    submitAndWaitForResponse,
} from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

// ---------------------------------------------------------------------------
// Symmetric key rotation
// ---------------------------------------------------------------------------

test.describe("Symmetric key rotation policy", () => {
    test("set rotation policy on AES key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/rotation-policy/sym/set");
        await page.fill('[data-testid="rotation-key-id"]', keyId);
        // AntD v5 InputNumber passes data-testid to the <input> itself (via rc-input-number inputProps).
        await page.locator('[data-testid="rotation-interval"]').fill("86400");
        await page.locator('[data-testid="rotation-offset"]').fill("3600");
        await page.fill('[data-testid="rotation-name"]', "sym-keyset");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy set successfully/i);
    });

    test("get rotation policy shows configured values", async ({ page }) => {
        const keyId = await createSymKey(page);

        // First set a policy.
        await gotoAndWait(page, "/ui/rotation-policy/sym/set");
        await page.fill('[data-testid="rotation-key-id"]', keyId);
        await page.locator('[data-testid="rotation-interval"]').fill("86400");
        await page.fill('[data-testid="rotation-name"]', "sym-get-test");
        await submitAndWaitForResponse(page);

        // Then retrieve it.
        await gotoAndWait(page, "/ui/rotation-policy/sym/get");
        await page.fill('[data-testid="get-rotation-key-id"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy retrieved successfully/i);

        // The details card should appear because interval is set.
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        // The card must contain the interval value we set.
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toContainText("86400");
    });

    test("get rotation policy returns no-policy message for fresh key", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/rotation-policy/sym/get");
        await page.fill('[data-testid="get-rotation-key-id"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/no rotation policy configured/i);
    });

    test("re-key symmetric key returns a different UID", async ({ page }) => {
        const keyId = await createSymKey(page);

        await gotoAndWait(page, "/ui/sym/keys/rekey");
        await page.fill('[data-testid="rekey-key-id"]', keyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/successfully refreshed/i);
        expect(text).toMatch(/New key:/i);

        // The response must contain a valid UUID different from the original.
        const newId = extractUuid(text);
        expect(newId).not.toBeNull();
        expect(newId).not.toBe(keyId);
    });
});

// ---------------------------------------------------------------------------
// RSA key rotation
// ---------------------------------------------------------------------------

test.describe("RSA key rotation policy", () => {
    test("set rotation policy on RSA key pair", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/rsa/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("604800");
        await page.fill('[data-testid="rotation-name"]', "rsa-keyset");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy set successfully/i);
    });

    test("get rotation policy shows configured values for RSA key", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/rsa/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("604800");
        await page.fill('[data-testid="rotation-name"]', "rsa-get-test");
        await submitAndWaitForResponse(page);

        await gotoAndWait(page, "/ui/rotation-policy/rsa/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy retrieved successfully/i);

        await expect(page.locator('[data-testid="rotation-policy-details"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toContainText("604800");
    });

    test("get rotation policy returns no-policy message for fresh RSA key", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/rsa/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/no rotation policy configured/i);
    });

    test("re-key RSA key pair returns new private and public key UIDs", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        await gotoAndWait(page, "/ui/rsa/keys/rekey");
        await page.fill('[data-testid="rekey-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/RSA key pair was successfully rotated/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toBe(privKeyId);
    });
});

// ---------------------------------------------------------------------------
// EC key rotation
// ---------------------------------------------------------------------------

test.describe("EC key rotation policy", () => {
    test("set rotation policy on EC key pair", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/ec/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("2592000");
        await page.fill('[data-testid="rotation-name"]', "ec-keyset");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy set successfully/i);
    });

    test("get rotation policy shows configured values for EC key", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/ec/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("2592000");
        await page.fill('[data-testid="rotation-name"]', "ec-get-test");
        await submitAndWaitForResponse(page);

        await gotoAndWait(page, "/ui/rotation-policy/ec/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy retrieved successfully/i);

        await expect(page.locator('[data-testid="rotation-policy-details"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toContainText("2592000");
    });

    test("get rotation policy returns no-policy message for fresh EC key", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/rotation-policy/ec/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/no rotation policy configured/i);
    });

    test("re-key EC key pair returns new private and public key UIDs", async ({ page }) => {
        const { privKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/ec/keys/rekey");
        await page.fill('[data-testid="rekey-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/EC key pair was successfully rotated/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toBe(privKeyId);
    });
});

// ---------------------------------------------------------------------------
// PQC key rotation (ML-DSA-44; skipped in FIPS mode)
// ---------------------------------------------------------------------------

test.describe("PQC key rotation policy", () => {
    test.skip(FIPS_MODE, "PQC algorithms are not available in FIPS mode");

    test("set rotation policy on PQC key pair", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        await gotoAndWait(page, "/ui/rotation-policy/pqc/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("86400");
        await page.fill('[data-testid="rotation-name"]', "pqc-keyset");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy set successfully/i);
    });

    test("get rotation policy shows configured values for PQC key", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        await gotoAndWait(page, "/ui/rotation-policy/pqc/set");
        await page.fill('[data-testid="rotation-key-id"]', privKeyId);
        await page.locator('[data-testid="rotation-interval"]').fill("86400");
        await page.fill('[data-testid="rotation-name"]', "pqc-get-test");
        await submitAndWaitForResponse(page);

        await gotoAndWait(page, "/ui/rotation-policy/pqc/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy retrieved successfully/i);

        await expect(page.locator('[data-testid="rotation-policy-details"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toContainText("86400");
    });

    test("get rotation policy returns no-policy message for fresh PQC key", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        await gotoAndWait(page, "/ui/rotation-policy/pqc/get");
        await page.fill('[data-testid="get-rotation-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/no rotation policy configured/i);
    });

    test("re-key PQC key pair returns new private and public key UIDs", async ({ page }) => {
        const { privKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        await gotoAndWait(page, "/ui/pqc/keys/rekey");
        await page.fill('[data-testid="rekey-key-id"]', privKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/post-quantum key pair was successfully rotated/i);

        const newPrivId = extractUuidAfterLabel(text, "New private key");
        const newPubId = extractUuidAfterLabel(text, "New public key");
        expect(newPrivId).not.toBeNull();
        expect(newPubId).not.toBeNull();
        expect(newPrivId).not.toBe(privKeyId);
    });
});

// ---------------------------------------------------------------------------
// Certificate renewal (KMIP ReCertify operation)
// ---------------------------------------------------------------------------

test.describe("Certificate renewal (ReCertify)", () => {
    test("re-certify self-signed RSA certificate returns a new distinct UID", async ({ page }) => {
        // Create a base self-signed certificate (generates a key pair internally).
        const originalId = await createCertificate(page, "RSA 2048");

        // Re-certify it via Option 3 — this must call the dedicated KMIP ReCertify
        // operation, which creates a brand-new certificate with a fresh UID and links
        // the old and new certs via ReplacedObjectLink / ReplacementObjectLink.
        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("3. Certificate ID to Re-certify").click();
        await page.fill('input[placeholder="Enter certificate ID to re-certify"]', originalId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully re-certified/i);

        // The new UID must be present and differ from the original.
        const newId = extractUuid(text);
        expect(newId).not.toBeNull();
        expect(newId).not.toBe(originalId);
    });

    test("re-certify self-signed EC P-256 certificate returns a new distinct UID", async ({ page }) => {
        const originalId = await createCertificate(page, "NIST P-256");

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("3. Certificate ID to Re-certify").click();
        await page.fill('input[placeholder="Enter certificate ID to re-certify"]', originalId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully re-certified/i);

        const newId = extractUuid(text);
        expect(newId).not.toBeNull();
        expect(newId).not.toBe(originalId);
    });

    test("re-certify PQC ML-DSA-44 certificate returns a new distinct UID", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC algorithms are not available in FIPS mode");

        const originalId = await createCertificate(page, "ML-DSA-44 (PQC)");

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("3. Certificate ID to Re-certify").click();
        await page.fill('input[placeholder="Enter certificate ID to re-certify"]', originalId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully re-certified/i);

        const newId = extractUuid(text);
        expect(newId).not.toBeNull();
        expect(newId).not.toBe(originalId);
    });
});
