/**
 * Certificate Certify E2E tests — X.509 generation for all algorithms.
 *
 * Covers the "Certificate Issuance and Renewal" page at
 * /ui/certificates/certs/certify using all four certification methods:
 *
 *  Method 1 — CSR upload                (existing keys test)
 *  Method 2 — Public Key ID to Certify  (provide an existing pub key)
 *  Method 3 — Re-certify                (renew an existing certificate)
 *  Method 4 — Generate New Keypair      (self-signed for each algorithm)
 *
 * PQC algorithms are skipped automatically in FIPS mode.
 *
 * Equivalent CLI operations:
 *   ckms certificates certify --generate-key-pair \
 *       --subject-name "CN=E2E,O=Cosmian" \
 *       --algorithm <algo>
 */
import { expect, test } from "@playwright/test";
import {
    createCertificate,
    createEcKeyPair,
    createPqcKeyPair,
    extractUuid,
    gotoAndWait,
    selectOption,
    submitAndWaitForResponse,
} from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

// ---------------------------------------------------------------------------
// Method 4 — Generate New Keypair (self-signed)
// ---------------------------------------------------------------------------

test.describe("Certificate certify – generate key pair (self-signed)", () => {
    // ── Classical / FIPS-approved algorithms ──────────────────────────────

    test("self-signed RSA-2048", async ({ page }) => {
        const id = await createCertificate(page, "RSA 2048");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed RSA-4096", async ({ page }) => {
        const id = await createCertificate(page, "RSA 4096");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed NIST P-256", async ({ page }) => {
        const id = await createCertificate(page, "NIST P-256");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed NIST P-384", async ({ page }) => {
        const id = await createCertificate(page, "NIST P-384");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed NIST P-521", async ({ page }) => {
        const id = await createCertificate(page, "NIST P-521");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed Ed25519", async ({ page }) => {
        const id = await createCertificate(page, "Ed25519");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    // ── ML-DSA (PQC signing) ───────────────────────────────────────────────

    test("self-signed ML-DSA-44 (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "ML-DSA-44 (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed ML-DSA-65 (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "ML-DSA-65 (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed ML-DSA-87 (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "ML-DSA-87 (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    // ── SLH-DSA SHA2 family ────────────────────────────────────────────────

    test("self-signed SLH-DSA-SHA2-128s (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHA2-128s (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed SLH-DSA-SHA2-128f (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHA2-128f (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed SLH-DSA-SHA2-192s (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHA2-192s (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed SLH-DSA-SHA2-256s (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHA2-256s (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    // ── SLH-DSA SHAKE family ───────────────────────────────────────────────

    test("self-signed SLH-DSA-SHAKE-128s (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHAKE-128s (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    test("self-signed SLH-DSA-SHAKE-256s (PQC)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const id = await createCertificate(page, "SLH-DSA-SHAKE-256s (PQC)");
        expect(id).toMatch(/[0-9a-f-]{36}/i);
    });

    // ── KEM algorithms — must be rejected (KEM keys cannot self-sign) ──────

    test("self-signed ML-KEM-512 is rejected with error", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("4. Generate New Keypair").click();
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=KEM Self-Signed,O=Cosmian");
        await selectOption(page, "cert-algorithm-select", "ML-KEM-512 (KEM)");
        const text = await submitAndWaitForResponse(page);
        // Server must reject KEM self-signed with a clear error message
        expect(text).toMatch(/error/i);
    });
});

// ---------------------------------------------------------------------------
// Method 2 — certify an existing public key
// ---------------------------------------------------------------------------

test.describe("Certificate certify – existing public key", () => {
    test("certify EC P-256 public key (self-signed)", async ({ page }) => {
        // Create an EC key pair first
        const { pubKeyId } = await createEcKeyPair(page);

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=EC PubKey Test,O=Cosmian");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });

    test("certify PQC ML-DSA-44 public key (self-signed)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const { pubKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=ML-DSA PubKey Test,O=Cosmian");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });
});

// ---------------------------------------------------------------------------
// Method 3 — Re-certify an existing certificate
// ---------------------------------------------------------------------------

test.describe("Certificate certify – re-certify", () => {
    test("re-certify an existing certificate renews it", async ({ page }) => {
        // Create a base certificate first
        const originalId = await createCertificate(page, "NIST P-256");

        // Re-certify it
        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("3. Certificate ID to Re-certify").click();
        await page.fill('input[placeholder="Enter certificate ID to re-certify"]', originalId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const newId = extractUuid(text);
        expect(newId).not.toBeNull();
    });
});

// ---------------------------------------------------------------------------
// CA-signed certificates (issuer private key + certificate provided)
// ---------------------------------------------------------------------------

test.describe("Certificate certify – CA-issued", () => {
    /**
     * Create an ML-DSA-44 CA certificate and return the CA private key ID + cert ID.
     *
     * Strategy: create an ML-DSA-44 key pair (which returns both key IDs), then
     * certify the public key (method 2) to produce the CA certificate.
     * The parse_certify_ttlv_response only returns the certificate ID, so we
     * must obtain the private key ID from the key-pair creation step.
     */
    async function createMlDsaCa(page: import("@playwright/test").Page): Promise<{ caPrivKeyId: string; caCertId: string }> {
        // Step 1: create ML-DSA-44 key pair
        const { privKeyId: caPrivKeyId, pubKeyId: caPubKeyId } = await createPqcKeyPair(page, "ML-DSA-44");

        // Step 2: certify the public key (self-signed)
        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', caPubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=ML-DSA CA,O=Cosmian");
        const caText = await submitAndWaitForResponse(page);
        expect(caText).toMatch(/certificate successfully created/i);
        const caCertId = extractUuid(caText);
        expect(caCertId).not.toBeNull();

        return { caPrivKeyId, caCertId: caCertId! };
    }

    test("ML-KEM-512 certificate issued by ML-DSA-44 CA", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const { caPrivKeyId, caCertId } = await createMlDsaCa(page);

        // Generate a leaf ML-KEM-512 key pair
        const { pubKeyId } = await createPqcKeyPair(page, "ML-KEM-512");

        // Certify the leaf using the CA
        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=ML-KEM-512 Leaf,O=Cosmian");
        // Issuer information
        await page.fill('input[placeholder="Enter issuer private key ID"]', caPrivKeyId);
        await page.fill('input[placeholder="Enter issuer certificate ID"]', caCertId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });

    test("ML-KEM-768 certificate issued by ML-DSA-44 CA", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const { caPrivKeyId, caCertId } = await createMlDsaCa(page);

        const { pubKeyId } = await createPqcKeyPair(page, "ML-KEM-768");

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=ML-KEM-768 Leaf,O=Cosmian");
        await page.fill('input[placeholder="Enter issuer private key ID"]', caPrivKeyId);
        await page.fill('input[placeholder="Enter issuer certificate ID"]', caCertId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });

    test("ML-KEM-1024 certificate issued by ML-DSA-44 CA", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const { caPrivKeyId, caCertId } = await createMlDsaCa(page);

        const { pubKeyId } = await createPqcKeyPair(page, "ML-KEM-1024");

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("2. Public Key ID to Certify").click();
        await page.fill('input[placeholder="Enter public key ID"]', pubKeyId);
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=ML-KEM-1024 Leaf,O=Cosmian");
        await page.fill('input[placeholder="Enter issuer private key ID"]', caPrivKeyId);
        await page.fill('input[placeholder="Enter issuer certificate ID"]', caCertId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });

    test("RSA-4096 certificate issued by ML-DSA-44 CA (cross-algorithm)", async ({ page }) => {
        test.skip(FIPS_MODE, "PQC not available in FIPS mode");
        const { caPrivKeyId, caCertId } = await createMlDsaCa(page);

        await gotoAndWait(page, "/ui/certificates/certs/certify");
        await page.getByText("4. Generate New Keypair").click();
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=RSA Leaf,O=Cosmian");
        await selectOption(page, "cert-algorithm-select", "RSA 4096");
        await page.fill('input[placeholder="Enter issuer private key ID"]', caPrivKeyId);
        await page.fill('input[placeholder="Enter issuer certificate ID"]', caCertId);

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const certId = extractUuid(text);
        expect(certId).not.toBeNull();
    });
});

// ---------------------------------------------------------------------------
// Optional certificate ID
// ---------------------------------------------------------------------------

test.describe("Certificate certify – optional certificate ID", () => {
    test("certificate is created with a provided ID", async ({ page }) => {
        const customId =
            "00000000-0000-4000-8000-" +
            Math.floor(Math.random() * 0xffffffffffff)
                .toString(16)
                .padStart(12, "0");

        await gotoAndWait(page, "/ui/certificates/certs/certify");

        // Set optional certificate ID before switching method
        await page.fill('input[placeholder="Enter certificate ID"]', customId);

        await page.getByText("4. Generate New Keypair").click();
        await page.fill('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]', "CN=Custom ID Cert,O=Cosmian");
        await selectOption(page, "cert-algorithm-select", "NIST P-256");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/certificate successfully created/i);
        const returnedId = extractUuid(text);
        expect(returnedId).toBe(customId);
    });
});
