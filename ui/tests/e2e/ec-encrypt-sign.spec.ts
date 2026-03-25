/**
 * EC encrypt/decrypt and sign/verify E2E roundtrip tests.
 *
 * Validates the full WASM → KMIP → KMS pipeline for Elliptic Curve operations,
 * equivalent to:
 *   ckms ec keys create --curve nist-p256
 *   ckms ec encrypt -k <pub_id> plain.txt -o plain.txt.enc
 *   ckms ec decrypt -k <priv_id> plain.txt.enc -o plain.txt
 *   ckms ec sign -k <priv_id> plain.txt -o plain.txt.sig
 *   ckms ec verify -k <pub_id> plain.txt plain.txt.sig
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import {
    createEcKeyPair,
    gotoAndWait,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
    uploadFile,
    uploadFileNth,
    writeTempFile,
} from "./helpers";

const PLAINTEXT = "Hello Cosmian KMS – EC E2E roundtrip test!";

test.describe("EC encrypt → decrypt roundtrip", () => {
    test("ECIES encrypt then decrypt preserves plaintext", async ({ page }) => {
        // ECIES uses a non-FIPS-approved KDF; the FIPS OpenSSL provider
        // returns an error for these operations.
        test.skip(process.env.PLAYWRIGHT_FIPS_MODE === "true", "ECIES is not available in FIPS mode");
        const { privKeyId, pubKeyId } = await createEcKeyPair(page);

        // ── Encrypt with public key ─────────────────────────────────────
        const plainFile = writeTempFile("ec-plain.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const { text: encText, download: encDownload } = await submitAndWaitForDownload(page);
        expect(encText).toMatch(/encrypted/i);
        const encPath = await encDownload.path();
        expect(encPath).not.toBeNull();

        // EC ciphertext should be larger than plaintext (ephemeral key + tag overhead)
        const encBytes = fs.readFileSync(encPath!);
        expect(encBytes.length).toBeGreaterThan(PLAINTEXT.length);

        // ── Decrypt with private key ────────────────────────────────────
        await gotoAndWait(page, "/ui/ec/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { text: decText, download: decDownload } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decrypted/i);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("encrypt with wrong public key then decrypt fails", async ({ page }) => {
        // ECIES uses a non-FIPS-approved KDF; the FIPS OpenSSL provider
        // returns an error for these operations.
        test.skip(process.env.PLAYWRIGHT_FIPS_MODE === "true", "ECIES is not available in FIPS mode");
        const { pubKeyId: pub1 } = await createEcKeyPair(page);
        const { privKeyId: priv2 } = await createEcKeyPair(page);

        const plainFile = writeTempFile("ec-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pub1);
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        // Decrypt with the OTHER pair's private key → should fail
        await gotoAndWait(page, "/ui/ec/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', priv2);
        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/error/i);
    });

    test("encrypt without key ID shows error", async ({ page }) => {
        const plainFile = writeTempFile("ec-nokey.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/encrypt");
        await uploadFile(page, plainFile);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/missing|error|key/i);
    });
});

test.describe("EC sign → verify roundtrip", () => {
    test("sign then verify with correct key returns Valid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createEcKeyPair(page);

        // ── Sign with private key ───────────────────────────────────────
        const dataFile = writeTempFile("ec-sign-data.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { text: signText, download: sigDownload } = await submitAndWaitForDownload(page);
        expect(signText).toMatch(/signature created/i);
        const sigPath = await sigDownload.path();
        expect(sigPath).not.toBeNull();

        // EC signature is typically 64-72 bytes for P-256
        const sigBytes = fs.readFileSync(sigPath!);
        expect(sigBytes.length).toBeGreaterThan(50);
        expect(sigBytes.length).toBeLessThan(200);

        // ── Verify with public key ──────────────────────────────────────
        await gotoAndWait(page, "/ui/ec/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/valid/i);
        expect(verifyText.toLowerCase()).not.toContain("invalid");
    });

    test("verify with wrong key returns error or invalid", async ({ page }) => {
        const { privKeyId: priv1 } = await createEcKeyPair(page);
        const { pubKeyId: pub2 } = await createEcKeyPair(page);

        const dataFile = writeTempFile("ec-verify-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', priv1);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with a DIFFERENT key pair's public key
        await gotoAndWait(page, "/ui/ec/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pub2);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/invalid|error/i);
    });

    test("verify with tampered data returns invalid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createEcKeyPair(page);

        const dataFile = writeTempFile("ec-tamper-orig.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/ec/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with tampered data
        const tamperedFile = writeTempFile("ec-tamper-bad.txt", PLAINTEXT + " TAMPERED");
        await gotoAndWait(page, "/ui/ec/verify");
        await uploadFileNth(page, tamperedFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/invalid|error/i);
    });
});
