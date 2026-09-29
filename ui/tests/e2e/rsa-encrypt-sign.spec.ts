/**
 * RSA encrypt/decrypt and sign/verify E2E roundtrip tests.
 *
 * Validates the full WASM → KMIP → KMS pipeline for RSA operations,
 * equivalent to:
 *   ckms rsa keys create --size-in-bits 4096
 *   ckms rsa encrypt -k <pub_id> plain.txt -o plain.txt.enc
 *   ckms rsa decrypt -k <priv_id> plain.txt.enc -o plain.txt
 *   ckms rsa sign -k <priv_id> plain.txt -o plain.txt.sig
 *   ckms rsa verify -k <priv_id> plain.txt plain.txt.sig
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import {
    createRsaKeyPair,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
    uploadFile,
    uploadFileNth,
    writeTempFile,
} from "./helpers";

const PLAINTEXT = "Hello Cosmian KMS – RSA E2E roundtrip test!";

test.describe("RSA encrypt → decrypt roundtrip", () => {
    test("RSA OAEP SHA-256 encrypt then decrypt preserves plaintext", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

        // ── Encrypt with public key ─────────────────────────────────────
        const plainFile = writeTempFile("rsa-plain.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        // Default: OAEP + SHA-256
        const { text: encText, download: encDownload } = await submitAndWaitForDownload(page);
        expect(encText).toMatch(/encrypted/i);
        const encPath = await encDownload.path();
        expect(encPath).not.toBeNull();

        // RSA-4096 ciphertext should be 512 bytes
        const encBytes = fs.readFileSync(encPath!);
        expect(encBytes.length).toBe(512);

        // ── Decrypt with private key ────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        // Same algorithm defaults
        const { text: decText, download: decDownload } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decrypted/i);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("RSA OAEP SHA-384 encrypt then decrypt", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

        const plainFile = writeTempFile("rsa-plain-384.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        await selectOptionById(page, "#hashingAlgorithm", "SHA-384");
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        await gotoAndWait(page, "/ui/rsa/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await selectOptionById(page, "#hashingAlgorithm", "SHA-384");
        const { download: decDownload } = await submitAndWaitForDownload(page);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("RSA AES Key Wrap encrypt then decrypt", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

        const plainFile = writeTempFile("rsa-plain-wrap.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        await selectOptionById(page, "#encryptionAlgorithm", "RSA AES Key Wrap");
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        await gotoAndWait(page, "/ui/rsa/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await selectOptionById(page, "#encryptionAlgorithm", "RSA AES Key Wrap");
        const { download: decDownload } = await submitAndWaitForDownload(page);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("encrypt with wrong public key then decrypt fails", async ({ page }) => {
        const { pubKeyId: pub1 } = await createRsaKeyPair(page);
        const { privKeyId: priv2 } = await createRsaKeyPair(page);

        const plainFile = writeTempFile("rsa-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', pub1);
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        // Decrypt with the OTHER key pair's private key → should fail
        await gotoAndWait(page, "/ui/rsa/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', priv2);
        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/error/i);
    });
});

test.describe("RSA sign → verify roundtrip", () => {
    test("sign then verify with same key returns Valid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

        // ── Sign with private key ───────────────────────────────────────
        const dataFile = writeTempFile("rsa-sign-data.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { text: signText, download: sigDownload } = await submitAndWaitForDownload(page);
        expect(signText).toMatch(/signature created/i);
        const sigPath = await sigDownload.path();
        expect(sigPath).not.toBeNull();

        // Signature should be 512 bytes for RSA-4096
        const sigBytes = fs.readFileSync(sigPath!);
        expect(sigBytes.length).toBe(512);

        // ── Verify with public key ──────────────────────────────────────
        await gotoAndWait(page, "/ui/rsa/verify");
        // Upload data file (first uploader) and signature file (second uploader)
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/valid/i);
        // Should not contain "invalid"
        expect(verifyText.toLowerCase()).not.toContain("invalid");
    });

    test("verify with wrong key returns error", async ({ page }) => {
        const { privKeyId: priv1 } = await createRsaKeyPair(page);
        const { pubKeyId: pub2 } = await createRsaKeyPair(page);

        // Sign with key1
        const dataFile = writeTempFile("rsa-verify-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', priv1);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with key2's public key → should fail
        await gotoAndWait(page, "/ui/rsa/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pub2);
        const verifyText = await submitAndWaitForResponse(page);
        // Either "Invalid" validity or an error message
        expect(verifyText).toMatch(/invalid|error/i);
    });

    test("verify with tampered data returns invalid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

        // Sign original data
        const dataFile = writeTempFile("rsa-tamper-orig.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/rsa/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with tampered data
        const tamperedFile = writeTempFile("rsa-tamper-bad.txt", PLAINTEXT + " TAMPERED");
        await gotoAndWait(page, "/ui/rsa/verify");
        await uploadFileNth(page, tamperedFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/invalid|error/i);
    });
});
