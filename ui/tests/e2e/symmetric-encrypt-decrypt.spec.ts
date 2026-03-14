/**
 * Symmetric encrypt / decrypt E2E roundtrip tests.
 *
 * These tests prove that the UI can:
 *   1. Create a symmetric key
 *   2. Encrypt a file with that key (server-side, AES-GCM)
 *   3. Decrypt the encrypted file back to the original plaintext
 *
 * This validates the full WASM → KMIP → KMS pipeline for symmetric
 * cryptographic operations, equivalent to:
 *   ckms sym keys create
 *   ckms sym encrypt -k <id> plain.txt -o plain.txt.enc
 *   ckms sym decrypt -k <id> plain.txt.enc -o plain.txt
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import {
    createSymKey,
    gotoAndWait,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
    uploadFile,
    writeTempFile,
} from "./helpers";

const PLAINTEXT = "Hello Cosmian KMS – Symmetric E2E roundtrip test!";

test.describe("Symmetric encrypt → decrypt roundtrip", () => {
    test("AES-GCM encrypt then decrypt preserves plaintext", async ({ page }) => {
        // ── 1. Create key ────────────────────────────────────────────────
        const keyId = await createSymKey(page);

        // ── 2. Encrypt ──────────────────────────────────────────────────
        const plainFile = writeTempFile("sym-plain.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        // Default algorithm is AES-GCM
        const { text: encText, download: encDownload } = await submitAndWaitForDownload(page);
        expect(encText).toMatch(/encrypted/i);
        const encPath = await encDownload.path();
        expect(encPath).not.toBeNull();

        // Encrypted file should be larger than plaintext (has IV + tag)
        const encBytes = fs.readFileSync(encPath!);
        expect(encBytes.length).toBeGreaterThan(PLAINTEXT.length);

        // ── 3. Decrypt ──────────────────────────────────────────────────
        await gotoAndWait(page, "/ui/sym/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { text: decText, download: decDownload } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decrypted/i);

        // ── 4. Verify roundtrip ─────────────────────────────────────────
        const decPath = await decDownload.path();
        expect(decPath).not.toBeNull();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("AES-GCM encrypt large file then decrypt", async ({ page }) => {
        const keyId = await createSymKey(page);

        // Create a ~10KB file to test non-trivial data
        const largeContent = "A".repeat(10_000) + "\nEnd of file.\n";
        const plainFile = writeTempFile("sym-large.bin", largeContent);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        await gotoAndWait(page, "/ui/sym/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', keyId);
        const { download: decDownload } = await submitAndWaitForDownload(page);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(largeContent);
    });

    test("encrypt with nonexistent key ID shows error", async ({ page }) => {
        const plainFile = writeTempFile("sym-plain-err.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', "00000000-0000-0000-0000-000000000000");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/error/i);
    });

    test("decrypt with mismatched key fails", async ({ page }) => {
        const keyId1 = await createSymKey(page);
        const keyId2 = await createSymKey(page);

        // Encrypt with key1
        const plainFile = writeTempFile("sym-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', keyId1);
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        // Try to decrypt with key2 → should error
        await gotoAndWait(page, "/ui/sym/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter key ID"]', keyId2);
        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/error/i);
    });

    test("encrypt without key ID shows error", async ({ page }) => {
        const plainFile = writeTempFile("sym-nokey.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        // Do not fill key ID
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/missing key identifier/i);
    });
});
