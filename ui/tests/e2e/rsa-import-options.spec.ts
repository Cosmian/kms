/**
 * RSA import E2E tests — all combinations / options.
 *
 * Covers every format option available in the Left Menu → RSA → Import:
 *   • PEM (auto-detect) — private and public
 *   • PKCS#1 DER — private and public
 *   • PKCS#8 DER — private and public
 *   • JSON-TTLV (round-trip: create → export → import)
 *
 * Also covers:
 *   • All key usage combinations (Sign, Verify, Encrypt, Decrypt, Wrap, Unwrap)
 *   • Tags
 *   • Replace existing
 *   • Custom key ID
 */
import { fileURLToPath } from "url";
import path from "path";
import { expect, test } from "@playwright/test";
import {
    createRsaKeyPair,
    extractUuid,
    gotoAndWait,
    selectMultipleOptions,
    selectOptionById,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
} from "./helpers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const KEY_DIR = path.resolve(__dirname, "../../../test_data/key_encodings");

// ── PEM files (auto-detect) ──────────────────────────────────────────────────
const PEM_FILES = {
    pkcs1_priv: path.join(KEY_DIR, "rsa_private_key_pkcs1.pem"),
    pkcs8_priv: path.join(KEY_DIR, "rsa_private_key_pkcs8.pem"),
    pkcs1_pub: path.join(KEY_DIR, "rsa_public_key_pkcs1.pem"),
    spki_pub: path.join(KEY_DIR, "rsa_public_key_spki.pem"),
};

// ── DER files ────────────────────────────────────────────────────────────────
const DER_FILES = {
    pkcs1_priv: path.join(KEY_DIR, "rsa_private_key_pkcs1.der"),
    pkcs1_pub: path.join(KEY_DIR, "rsa_public_key_pkcs1.der"),
    pkcs8_priv: path.join(KEY_DIR, "rsa_private_key_pkcs8.der"),
    pkcs8_pub: path.join(KEY_DIR, "rsa_public_key_pkcs8.der"),
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Navigate to RSA import page, upload a file and select its format. */
async function importRsaKey(
    page: Parameters<typeof gotoAndWait>[0],
    filePath: string,
    formatLabel: string,
    opts?: {
        keyId?: string;
        usages?: string[];
        tags?: string[];
        replaceExisting?: boolean;
    }
): Promise<string> {
    await gotoAndWait(page, "/ui/rsa/keys/import");
    await page.setInputFiles('input[type="file"]', filePath);
    await selectOptionById(page, "#keyFormat", formatLabel);

    if (opts?.keyId) {
        await page.fill('input[placeholder="Enter ID"]', opts.keyId);
    }

    if (opts?.usages && opts.usages.length > 0) {
        await selectMultipleOptions(page, "#keyUsage", opts.usages);
    }

    if (opts?.tags) {
        for (const tag of opts.tags) {
            const tagsInput = page.locator("#tags");
            await tagsInput.click();
            await tagsInput.pressSequentially(tag, { delay: 30 });
            await page.keyboard.press("Enter");
        }
    }

    if (opts?.replaceExisting) {
        await page.locator("text=Replace existing").click();
    }

    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/imported/i);
    return text;
}

// ===========================================================================
// TESTS
// ===========================================================================

test.describe("RSA import — PEM format (auto-detect)", () => {
    test("import PKCS#1 PEM private key", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs1_priv, "PEM (auto-detect format)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import PKCS#8 PEM private key", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs8_priv, "PEM (auto-detect format)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import PKCS#1 PEM public key", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs1_pub, "PEM (auto-detect format)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import SPKI PEM public key", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.spki_pub, "PEM (auto-detect format)");
        expect(extractUuid(text)).not.toBeNull();
    });
});

test.describe("RSA import — DER formats", () => {
    test("import PKCS#1 DER private key", async ({ page }) => {
        const text = await importRsaKey(page, DER_FILES.pkcs1_priv, "PKCS#1 DER (RSA private)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import PKCS#1 DER public key", async ({ page }) => {
        const text = await importRsaKey(page, DER_FILES.pkcs1_pub, "PKCS#1 DER (RSA public)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import PKCS#8 DER private key", async ({ page }) => {
        const text = await importRsaKey(page, DER_FILES.pkcs8_priv, "PKCS#8 DER (RSA private)");
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import PKCS#8 DER public key", async ({ page }) => {
        const text = await importRsaKey(page, DER_FILES.pkcs8_pub, "PKCS#8 DER (RSA public)");
        expect(extractUuid(text)).not.toBeNull();
    });
});

test.describe("RSA import — JSON-TTLV round trip", () => {
    test("create RSA key pair, export as JSON-TTLV, then re-import", async ({ page }) => {
        // Create a key pair
        const { pubKeyId } = await createRsaKeyPair(page);

        // Export public key as JSON-TTLV
        await gotoAndWait(page, "/ui/rsa/keys/export");
        await page.fill('input[placeholder="Enter key ID"]', pubKeyId);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        const { download } = await submitAndWaitForDownload(page);
        const downloadPath = await download.path();
        expect(downloadPath).not.toBeNull();

        // Import the exported file
        await gotoAndWait(page, "/ui/rsa/keys/import");
        await page.setInputFiles('input[type="file"]', downloadPath!);
        await selectOptionById(page, "#keyFormat", "JSON TTLV (default)");
        const importText = await submitAndWaitForResponse(page);
        expect(importText).toMatch(/imported/i);
        expect(extractUuid(importText)).not.toBeNull();
    });
});

test.describe("RSA import — key usage options", () => {
    test("import with Sign usage", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs1_priv, "PEM (auto-detect format)", {
            usages: ["Sign"],
        });
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import with Verify usage", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.spki_pub, "PEM (auto-detect format)", {
            usages: ["Verify"],
        });
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import with Encrypt + Decrypt usage", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs8_priv, "PEM (auto-detect format)", {
            usages: ["Encrypt", "Decrypt"],
        });
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import with Wrap + Unwrap usage", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs8_priv, "PEM (auto-detect format)", {
            usages: ["Wrap", "Unwrap"],
        });
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import with all usages", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.pkcs8_priv, "PEM (auto-detect format)", {
            usages: ["Sign", "Verify", "Encrypt", "Decrypt", "Wrap", "Unwrap"],
        });
        expect(extractUuid(text)).not.toBeNull();
    });
});

test.describe("RSA import — tags and custom ID", () => {
    test("import with custom key ID", async ({ page }) => {
        const customId = `e2e-rsa-custom-${Date.now()}`;
        const text = await importRsaKey(page, PEM_FILES.pkcs1_priv, "PEM (auto-detect format)", {
            keyId: customId,
        });
        expect(text).toContain(customId);
    });

    test("import with tags", async ({ page }) => {
        const text = await importRsaKey(page, PEM_FILES.spki_pub, "PEM (auto-detect format)", {
            tags: ["e2e-test", `rsa-tag-${Date.now()}`],
        });
        expect(extractUuid(text)).not.toBeNull();
    });

    test("import with replace existing", async ({ page }) => {
        const customId = `e2e-rsa-replace-${Date.now()}`;

        // First import
        await importRsaKey(page, PEM_FILES.pkcs1_priv, "PEM (auto-detect format)", {
            keyId: customId,
        });

        // Second import with replace
        const text = await importRsaKey(page, PEM_FILES.pkcs1_priv, "PEM (auto-detect format)", {
            keyId: customId,
            replaceExisting: true,
        });
        expect(text).toContain(customId);
    });
});
