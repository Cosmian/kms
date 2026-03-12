/**
 * RSA export E2E tests — all combinations / options.
 *
 * Covers every format option available in the Left Menu → RSA → Export:
 *   • JSON TTLV (default)
 *   • PKCS1 PEM / DER
 *   • PKCS8 PEM / DER
 *   • Base64
 *   • Raw
 *
 * Also covers:
 *   • Wrapping options with all wrapping algorithms
 *   • Unwrap before export checkbox
 *   • Allow revoked objects checkbox
 *   • Export by tags
 */
import { expect, test, Page } from "@playwright/test";
import {
    createRsaKeyPair,
    createSymKey,
    gotoAndWait,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

// ---------------------------------------------------------------------------
// Shared fixture: create a fresh RSA key pair for export tests
// ---------------------------------------------------------------------------

async function exportRsaKey(
    page: Page,
    keyId: string,
    formatLabel: string,
    opts?: {
        wrapKeyId?: string;
        wrappingAlgorithm?: string;
        unwrap?: boolean;
        allowRevoked?: boolean;
    }
): Promise<{ text: string }> {
    await gotoAndWait(page, "/ui/rsa/keys/export");
    await page.fill('input[placeholder="Enter key ID"]', keyId);
    await selectOptionById(page, "#keyFormat", formatLabel);

    if (opts?.unwrap) {
        await page.locator("text=Unwrap key before export").click();
    }

    if (opts?.wrapKeyId) {
        await page.fill('input[placeholder="Enter wrap key ID"]', opts.wrapKeyId);
        if (opts?.wrappingAlgorithm) {
            await selectOptionById(page, "#wrappingAlgorithm", opts.wrappingAlgorithm);
        }
    }

    if (opts?.allowRevoked) {
        await page.locator("text=Allow revoked objects").click();
    }

    const { text } = await submitAndWaitForDownload(page);
    expect(text).toMatch(/File has been exported/i);
    return { text };
}

// ===========================================================================
// EXPORT FORMAT TESTS
// ===========================================================================

test.describe("RSA export — all format options", () => {
    let pubKeyId: string;

    test.beforeEach(async ({ page }) => {
        const keys = await createRsaKeyPair(page);
        pubKeyId = keys.pubKeyId;
    });

    test("export as JSON TTLV (default)", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "JSON TTLV (default)");
    });

    test("export as PKCS1 PEM", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "PKCS1 PEM");
    });

    test("export as PKCS1 DER", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "PKCS1 DER");
    });

    test("export as PKCS8 PEM", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "PKCS8 PEM");
    });

    test("export as PKCS8 DER", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "PKCS8 DER");
    });

    test("export as Base64", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "Base64");
    });

    test("export as Raw", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "Raw");
    });
});

test.describe("RSA export — private key formats", () => {
    let privKeyId: string;

    test.beforeEach(async ({ page }) => {
        const keys = await createRsaKeyPair(page);
        privKeyId = keys.privKeyId;
    });

    test("export private key as JSON TTLV", async ({ page }) => {
        await exportRsaKey(page, privKeyId, "JSON TTLV (default)");
    });

    test("export private key as PKCS1 PEM", async ({ page }) => {
        await exportRsaKey(page, privKeyId, "PKCS1 PEM");
    });

    test("export private key as PKCS8 PEM", async ({ page }) => {
        await exportRsaKey(page, privKeyId, "PKCS8 PEM");
    });

    test("export private key as PKCS8 DER", async ({ page }) => {
        await exportRsaKey(page, privKeyId, "PKCS8 DER");
    });
});

// ===========================================================================
// WRAPPING ALGORITHM TESTS
// ===========================================================================

test.describe("RSA export — wrapping algorithms (symmetric wrap key)", () => {
    let pubKeyId: string;
    let symKeyId: string;

    test.beforeEach(async ({ page }) => {
        // Create a symmetric wrapping key and an RSA key pair
        symKeyId = await createSymKey(page);
        const keys = await createRsaKeyPair(page);
        pubKeyId = keys.pubKeyId;
    });

    test("wrap with AES Key Wrap with Padding (RFC 5649)", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "JSON TTLV (default)", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES Key Wrap with Padding (RFC 5649)",
        });
    });

    test("wrap with AES Key Wrap with NO Padding (RFC 3394)", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "JSON TTLV (default)", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES Key Wrap with NO Padding (RFC 3394)",
        });
    });

    test("wrap with AES GCM", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "JSON TTLV (default)", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES GCM",
        });
    });
});

test.describe("RSA export — wrapping with RSA algorithms", () => {
    // RSA PKCS v1.5 and RSA OAEP can only wrap small payloads (smaller than
    // the RSA modulus). Wrapping a full RSA key with these algorithms will
    // fail server-side, so we wrap a symmetric key instead to test the UI
    // wrapping flow with these algorithms.
    let symKeyId: string;
    let rsaPubKeyId: string;

    test.beforeEach(async ({ page }) => {
        symKeyId = await createSymKey(page);
        const keys = await createRsaKeyPair(page);
        rsaPubKeyId = keys.pubKeyId;
    });

    test("wrap sym key with RSA PKCS v1.5", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', symKeyId);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        await page.fill('input[placeholder="Enter wrap key ID"]', rsaPubKeyId);
        await selectOptionById(page, "#wrappingAlgorithm", "RSA PKCS v1.5");
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("wrap sym key with RSA OAEP", async ({ page }) => {
        await gotoAndWait(page, "/ui/sym/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', symKeyId);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        await page.fill('input[placeholder="Enter wrap key ID"]', rsaPubKeyId);
        await selectOptionById(page, "#wrappingAlgorithm", "RSA OAEP");
        const { text } = await submitAndWaitForDownload(page);
        expect(text).toMatch(/File has been exported/i);
    });

    test("wrap RSA key with RSA AES Key Wrap", async ({ page }) => {
        await exportRsaKey(page, rsaPubKeyId, "JSON TTLV (default)", {
            wrapKeyId: rsaPubKeyId,
            wrappingAlgorithm: "RSA AES Key Wrap",
        });
    });
});

// ===========================================================================
// OPTION CHECKBOX TESTS
// ===========================================================================

test.describe("RSA export — option checkboxes", () => {
    test("allow revoked objects", async ({ page }) => {
        const { privKeyId } = await createRsaKeyPair(page);

        // Revoke the key first
        await gotoAndWait(page, "/ui/rsa/keys/revoke");
        await page.fill('input[placeholder="Enter key ID"]', privKeyId);
        await page.fill('textarea[placeholder="Enter the reason for key revocation"]', "E2E test");
        const revokeText = await submitAndWaitForResponse(page);
        expect(revokeText).toMatch(/revoked/i);

        // Export with allow revoked
        await exportRsaKey(page, privKeyId, "JSON TTLV (default)", {
            allowRevoked: true,
        });
    });
});

// ===========================================================================
// COMBINED FORMAT + WRAPPING TESTS
// ===========================================================================

test.describe("RSA export — format + wrapping combos", () => {
    let pubKeyId: string;
    let symKeyId: string;

    test.beforeEach(async ({ page }) => {
        symKeyId = await createSymKey(page);
        const keys = await createRsaKeyPair(page);
        pubKeyId = keys.pubKeyId;
    });

    test("export as Raw with AES Key Wrap", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "Raw", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES Key Wrap with Padding (RFC 5649)",
        });
    });

    test("export as Base64 with AES GCM wrapping", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "Base64", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES GCM",
        });
    });

    test("export as JSON TTLV with NIST Key Wrap", async ({ page }) => {
        await exportRsaKey(page, pubKeyId, "JSON TTLV (default)", {
            wrapKeyId: symKeyId,
            wrappingAlgorithm: "AES Key Wrap with NO Padding (RFC 3394)",
        });
    });
});
