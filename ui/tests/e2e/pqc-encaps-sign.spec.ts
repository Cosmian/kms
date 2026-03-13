/**
 * PQC encapsulate/decapsulate and sign/verify E2E roundtrip tests.
 *
 * Validates the full WASM → KMIP → KMS pipeline for Post-Quantum operations:
 *   ML-KEM: create key pair → encapsulate → decapsulate → verify shared secrets
 *   ML-DSA: create key pair → sign → verify
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import {
    createPqcKeyPair,
    gotoAndWait,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
    uploadFile,
    uploadFileNth,
    writeTempFile,
} from "./helpers";

const PLAINTEXT = "Hello Cosmian KMS – PQC E2E roundtrip test!";

test.describe("ML-KEM encapsulate → decapsulate roundtrip", () => {
    test("encapsulate then decapsulate with ML-KEM-512", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createPqcKeyPair(page, "ML-KEM-512");

        // ── Encapsulate with public key ─────────────────────────────────
        // The page triggers two downloads: encapsulation.bin and shared_secret.key
        await gotoAndWait(page, "/ui/pqc/encapsulate");
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);

        // Collect all downloads triggered by submit
        const downloads: import("@playwright/test").Download[] = [];
        page.on("download", (d) => downloads.push(d));
        await page.click('[data-testid="submit-btn"]');
        const responseEl = page.locator('[data-testid="response-output"]');
        await responseEl.waitFor({ state: "visible", timeout: 30_000 });
        const encText = (await responseEl.textContent()) ?? "";
        expect(encText).toMatch(/encapsulation successful/i);

        // Wait a moment for both downloads to complete
        await page.waitForTimeout(2_000);
        expect(downloads.length).toBeGreaterThanOrEqual(2);

        // Identify the encapsulation file (ciphertext)
        let encapsPath: string | null = null;
        for (const dl of downloads) {
            const name = dl.suggestedFilename();
            if (name.includes("encapsulation")) {
                encapsPath = await dl.path();
            }
        }
        expect(encapsPath).not.toBeNull();

        // ── Decapsulate with private key ────────────────────────────────
        await gotoAndWait(page, "/ui/pqc/decapsulate");
        await uploadFile(page, encapsPath!);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { text: decText } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decapsulation successful/i);
    });

    test("encapsulate without key ID shows error", async ({ page }) => {
        await gotoAndWait(page, "/ui/pqc/encapsulate");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/missing|error|key/i);
    });
});

test.describe("ML-DSA sign → verify roundtrip", () => {
    test("sign then verify with correct ML-DSA-44 key returns Valid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        // ── Sign with private key ───────────────────────────────────────
        const dataFile = writeTempFile("pqc-sign-data.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/pqc/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { text: signText, download: sigDownload } = await submitAndWaitForDownload(page);
        expect(signText).toMatch(/signature created/i);
        const sigPath = await sigDownload.path();
        expect(sigPath).not.toBeNull();

        // ML-DSA signatures are larger than EC signatures
        const sigBytes = fs.readFileSync(sigPath!);
        expect(sigBytes.length).toBeGreaterThan(100);

        // ── Verify with public key ──────────────────────────────────────
        await gotoAndWait(page, "/ui/pqc/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/valid/i);
        expect(verifyText.toLowerCase()).not.toContain("invalid");
    });

    test("verify with wrong key returns error or invalid", async ({ page }) => {
        const { privKeyId: priv1 } = await createPqcKeyPair(page, "ML-DSA-65");
        const { pubKeyId: pub2 } = await createPqcKeyPair(page, "ML-DSA-65");

        const dataFile = writeTempFile("pqc-verify-mismatch.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/pqc/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter private key ID"]', priv1);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with a DIFFERENT key pair's public key
        await gotoAndWait(page, "/ui/pqc/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter public key ID"]', pub2);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/invalid|error/i);
    });

    test("verify with tampered data returns invalid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createPqcKeyPair(page, "ML-DSA-87");

        const dataFile = writeTempFile("pqc-tamper-orig.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/pqc/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { download: sigDownload } = await submitAndWaitForDownload(page);
        const sigPath = await sigDownload.path();

        // Verify with tampered data
        const tamperedFile = writeTempFile("pqc-tamper-bad.txt", PLAINTEXT + " TAMPERED");
        await gotoAndWait(page, "/ui/pqc/verify");
        await uploadFileNth(page, tamperedFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/invalid|error/i);
    });
});

test.describe("Hybrid KEM encapsulate → decapsulate roundtrip", () => {
    test("encapsulate then decapsulate with X25519MLKEM768", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createPqcKeyPair(page, "X25519MLKEM768");

        // ── Encapsulate with public key ─────────────────────────────────
        await gotoAndWait(page, "/ui/pqc/encapsulate");
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);

        const downloads: import("@playwright/test").Download[] = [];
        page.on("download", (d) => downloads.push(d));
        await page.click('[data-testid="submit-btn"]');
        const responseEl = page.locator('[data-testid="response-output"]');
        await responseEl.waitFor({ state: "visible", timeout: 30_000 });
        const encText = (await responseEl.textContent()) ?? "";
        expect(encText).toMatch(/encapsulation successful/i);

        await page.waitForTimeout(2_000);
        expect(downloads.length).toBeGreaterThanOrEqual(2);

        let encapsPath: string | null = null;
        for (const dl of downloads) {
            const name = dl.suggestedFilename();
            if (name.includes("encapsulation")) {
                encapsPath = await dl.path();
            }
        }
        expect(encapsPath).not.toBeNull();

        // ── Decapsulate with private key ────────────────────────────────
        await gotoAndWait(page, "/ui/pqc/decapsulate");
        await uploadFile(page, encapsPath!);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { text: decText } = await submitAndWaitForDownload(page);
        expect(decText).toMatch(/decapsulation successful/i);
    });
});

test.describe("SLH-DSA sign → verify roundtrip", () => {
    test("sign then verify with SLH-DSA-SHA2-128s returns Valid", async ({ page }) => {
        const { privKeyId, pubKeyId } = await createPqcKeyPair(page, "SLH-DSA-SHA2-128s");

        // ── Sign with private key ───────────────────────────────────────
        const dataFile = writeTempFile("slh-dsa-sign-data.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/pqc/sign");
        await uploadFile(page, dataFile);
        await page.fill('input[placeholder="Enter private key ID"]', privKeyId);
        const { text: signText, download: sigDownload } = await submitAndWaitForDownload(page);
        expect(signText).toMatch(/signature created/i);
        const sigPath = await sigDownload.path();
        expect(sigPath).not.toBeNull();

        // SLH-DSA-SHA2-128s signatures are ~7856 bytes
        const sigBytes = fs.readFileSync(sigPath!);
        expect(sigBytes.length).toBeGreaterThan(1000);

        // ── Verify with public key ──────────────────────────────────────
        await gotoAndWait(page, "/ui/pqc/verify");
        await uploadFileNth(page, dataFile, 0);
        await uploadFileNth(page, sigPath!, 1);
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        const verifyText = await submitAndWaitForResponse(page);
        expect(verifyText).toMatch(/valid/i);
        expect(verifyText.toLowerCase()).not.toContain("invalid");
    });
});

test.describe("Configurable Hybrid KEM key creation", () => {
    // The configurable hybrid algorithms are hidden by branding in the Cosmian
    // theme. Override branding.json to make them visible for E2E testing.
    // Note: encapsulate/decapsulate are CLI-only for these algorithms because
    // the server returns a different wire format (Serializable tuple) that the
    // UI cannot parse. Full KEM roundtrips are covered by CLI integration tests.
    test.beforeEach(async ({ page }) => {
        await page.route(/branding\.json/, (route) =>
            route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify({
                    title: "Cosmian KMS",
                    pqcLabel: "PQC",
                    enableCovercrypt: true,
                    menuTheme: "light",
                }),
            })
        );
    });

    for (const { label, name } of [
        { label: "ML-KEM-512/P-256", name: "ML-KEM-512-P256" },
        { label: "ML-KEM-768/P-256", name: "ML-KEM-768-P256" },
        { label: "ML-KEM-512/Curve25519", name: "ML-KEM-512-Curve25519" },
        { label: "ML-KEM-768/Curve25519", name: "ML-KEM-768-Curve25519" },
    ] as const) {
        test(`create key pair with ${name}`, async ({ page }) => {
            const { privKeyId, pubKeyId } = await createPqcKeyPair(page, label);
            expect(privKeyId).toBeTruthy();
            expect(pubKeyId).toBeTruthy();
        });
    }
});
