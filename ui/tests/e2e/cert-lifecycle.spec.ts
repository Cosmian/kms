/**
 * Certificate lifecycle E2E tests: certify, validate, encrypt, decrypt.
 *
 * Validates the full WASM → KMIP → KMS pipeline for certificate operations,
 * equivalent to:
 *   ckms certificates certify --generate-key-pair --subject-name "CN=test" --algorithm rsa4096
 *   ckms certificates validate --certificate <cert_id>
 *   ckms certificates encrypt -c <cert_id> plain.txt -o plain.txt.enc
 *   ckms certificates decrypt -k <priv_id> plain.txt.enc -o plain.txt
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import { createRsaKeyPair, gotoAndWait, submitAndWaitForDownload, submitAndWaitForResponse, uploadFile, writeTempFile } from "./helpers";

const PLAINTEXT = "Hello Cosmian KMS – Certificate E2E roundtrip test!";

/**
 * Create a self-signed certificate with a generated key pair.
 * Returns the certificate ID and the private key ID (for decryption).
 */
async function createSelfSignedCert(
    page: import("@playwright/test").Page,
    subjectName = "CN=E2E Test,O=Cosmian",
): Promise<{ certId: string; privKeyId: string }> {
    // First create an RSA key pair to get both IDs
    const { privKeyId, pubKeyId } = await createRsaKeyPair(page);

    // Certify the public key
    await gotoAndWait(page, "/ui/certificates/certs/certify");
    await page.getByText("2. Public Key ID to Certify").click();
    await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
    await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', subjectName);

    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/certificate successfully created/i);

    const certIdMatch = text.match(/ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:_[a-z]+)?)/i);
    expect(certIdMatch).not.toBeNull();
    const certId = certIdMatch![1];

    return { certId, privKeyId };
}

test.describe("Certificate certify + validate", () => {
    test("create self-signed certificate and validate it", async ({ page }) => {
        const { certId } = await createSelfSignedCert(page);

        // ── Validate the certificate ────────────────────────────────────
        await gotoAndWait(page, "/ui/certificates/certs/validate");
        await page.fill('input[placeholder="Enter certificate ID"]', certId);
        const valText = await submitAndWaitForResponse(page);
        expect(valText).toMatch(/valid/i);
    });

    test("validate nonexistent certificate returns error", async ({ page }) => {
        await gotoAndWait(page, "/ui/certificates/certs/validate");
        await page.fill('input[placeholder="Enter certificate ID"]', "00000000-0000-0000-0000-000000000000");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/error|not found/i);
    });
});

test.describe("Certificate encrypt → decrypt roundtrip", () => {
    test("encrypt with certificate then decrypt with private key", async ({ page }) => {
        const { certId, privKeyId } = await createSelfSignedCert(page);

        // ── Encrypt with certificate ────────────────────────────────────
        const plainFile = writeTempFile("cert-plain.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/certificates/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter certificate ID"]', certId);
        // Default: OAEP
        const { text: encText, download: encDownload } = await submitAndWaitForDownload(page);
        expect(encText).toMatch(/encrypted/i);
        const encPath = await encDownload.path();
        expect(encPath).not.toBeNull();

        // Ciphertext should be non-empty
        const encBytes = fs.readFileSync(encPath!);
        expect(encBytes.length).toBeGreaterThan(0);

        // ── Decrypt with private key ────────────────────────────────────
        await gotoAndWait(page, "/ui/certificates/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { text: decText, download: decDownload } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decrypted/i);

        const decPath = await decDownload.path();
        const recovered = fs.readFileSync(decPath!);
        expect(recovered.toString("utf-8")).toBe(PLAINTEXT);
    });

    test("decrypt with wrong key fails", async ({ page }) => {
        const { certId } = await createSelfSignedCert(page, "CN=Key1");
        const { privKeyId: otherPriv } = await createSelfSignedCert(page, "CN=Key2");

        const plainFile = writeTempFile("cert-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/certificates/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter certificate ID"]', certId);
        const { download: encDownload } = await submitAndWaitForDownload(page);
        const encPath = await encDownload.path();

        // Decrypt with different private key → should fail
        await gotoAndWait(page, "/ui/certificates/decrypt");
        await uploadFile(page, encPath!);
        await page.fill('input[placeholder="Enter private key ID"]', otherPriv);
        const decText = await submitAndWaitForResponse(page);
        expect(decText).toMatch(/error/i);
    });
});
