/**
 * Keyset addressing syntax E2E tests.
 *
 * Covers all 4 keyset addressing forms in crypto operations:
 *   • bare keyset name → resolves to latest (encrypt)
 *   • name@latest → explicit latest resolution
 *   • name@first / name@0 → resolves to generation 0
 *   • name@N → resolves to specific generation N
 *   • bare name in decrypt → try-each chain walk
 *   • name@99 → nonexistent generation → error
 *   • get-rotation-policy after rekey → generation incremented
 *
 * All tests use AES-GCM (FIPS-approved) — no FIPS skip needed.
 */
import { expect, test } from "@playwright/test";
import * as fs from "fs";
import {
    UI_READY_TIMEOUT,
    createSymKeyWithId,
    gotoAndWait,
    submitAndWaitForDownload,
    submitAndWaitForResponse,
    uploadFile,
    writeTempFile,
} from "./helpers";

const PLAINTEXT = "keyset-addressing-e2e-test-data";

// Unique suffix per test-run so keys from prior runs don't block creation.
const RUN_ID = Date.now().toString(36).slice(-6);

// ── Local helpers ──────────────────────────────────────────────────────────

async function setRotationPolicy(page: import("@playwright/test").Page, keyId: string, name: string, interval?: number): Promise<void> {
    await gotoAndWait(page, "/ui/rotation-policy/sym/set");
    await page.fill('[data-testid="rotation-key-id"]', keyId);
    await page.fill('[data-testid="rotation-name"]', name);
    if (interval !== undefined) {
        await page.locator('[data-testid="rotation-interval"]').fill(String(interval));
    }
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/rotation policy set successfully/i);
}

async function rekeyKey(page: import("@playwright/test").Page, keyId: string): Promise<string> {
    await gotoAndWait(page, "/ui/sym/keys/rekey");
    await page.fill('[data-testid="rekey-key-id"]', keyId);
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/successfully refreshed/i);
    // New key ID may be a keyset address like "name@1", not a plain UUID.
    const m = text.match(/New key:\s*(\S+)/i);
    expect(m).not.toBeNull();
    const newId = m![1];
    expect(newId).not.toBe(keyId);
    return newId;
}

async function symEncrypt(page: import("@playwright/test").Page, keyIdOrName: string, plainFile: string): Promise<string> {
    await gotoAndWait(page, "/ui/sym/encrypt");
    await uploadFile(page, plainFile);
    await page.fill('input[placeholder="Enter key ID"]', keyIdOrName);
    const { download } = await submitAndWaitForDownload(page);
    const encPath = await download.path();
    expect(encPath).not.toBeNull();
    return encPath!;
}

async function symDecrypt(page: import("@playwright/test").Page, keyIdOrName: string, encFile: string): Promise<string> {
    await gotoAndWait(page, "/ui/sym/decrypt");
    await uploadFile(page, encFile);
    await page.fill('input[placeholder="Enter key ID"]', keyIdOrName);
    const { download } = await submitAndWaitForDownload(page);
    const decPath = await download.path();
    expect(decPath).not.toBeNull();
    return decPath!;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test.describe("Keyset addressing syntax", () => {
    test("encrypt with bare keyset name resolves to latest key", async ({ page }) => {
        // Server requires rotate_name == key UID — create with keyset name as UID
        const keyId = await createSymKeyWithId(page, `e2e-ks-bare-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId, 86400);

        const plainFile = writeTempFile("ks-bare.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, keyId, plainFile);

        // Decrypt with UUID proves the correct key was used
        const decPath = await symDecrypt(page, keyId, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("encrypt with name@latest resolves to latest key", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-latest-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId, 86400);

        const plainFile = writeTempFile("ks-latest.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, `${keyId}@latest`, plainFile);

        const decPath = await symDecrypt(page, keyId, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("decrypt with name@first after rekey resolves to gen-0", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-first-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId);

        // Encrypt while gen-0 is still Active
        const plainFile = writeTempFile("ks-first.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, keyId, plainFile);

        // Rotate: gen-0 → Deactivated, gen-1 → Active
        await rekeyKey(page, keyId);

        // Decrypt with @first — Deactivated keys allow decrypt operations
        const decPath = await symDecrypt(page, `${keyId}@first`, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("decrypt with name@0 after rekey resolves to gen-0", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-zero-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId);

        // Encrypt while gen-0 is still Active
        const plainFile = writeTempFile("ks-zero.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, keyId, plainFile);

        // Rotate: gen-0 → Deactivated, gen-1 → Active
        await rekeyKey(page, keyId);

        // Decrypt with @0 — Deactivated keys allow decrypt operations
        const decPath = await symDecrypt(page, `${keyId}@0`, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("decrypt with name@1 after double rekey resolves to gen-1", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-gen1-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId);

        // First rekey: gen-0 → Deactivated, gen-1 → Active
        const gen1Id = await rekeyKey(page, keyId);

        // Encrypt while gen-1 is still Active
        const plainFile = writeTempFile("ks-gen1.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, gen1Id, plainFile);

        // Second rekey: gen-1 → Deactivated, gen-2 → Active
        await rekeyKey(page, gen1Id);

        // Decrypt with @1 — Deactivated keys allow decrypt operations
        const decPath = await symDecrypt(page, `${keyId}@1`, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("decrypt with bare keyset name walks chain after rotation", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-chain-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId);

        // Encrypt with gen-0 UUID
        const plainFile = writeTempFile("ks-chain.txt", PLAINTEXT);
        const encPath = await symEncrypt(page, keyId, plainFile);

        // Rotate: gen-0 → gen-1
        await rekeyKey(page, keyId);

        // Decrypt with bare keyset name — try-each walks gen-1→gen-0
        const decPath = await symDecrypt(page, keyId, encPath);
        expect(fs.readFileSync(decPath, "utf-8")).toBe(PLAINTEXT);
    });

    test("encrypt with name@99 fails for nonexistent generation", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-bad-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId);

        const plainFile = writeTempFile("ks-bad.txt", PLAINTEXT);
        await gotoAndWait(page, "/ui/sym/encrypt");
        await uploadFile(page, plainFile);
        await page.fill('input[placeholder="Enter key ID"]', `${keyId}@99`);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/error/i);
    });

    test("get rotation policy after rekey shows incremented generation", async ({ page }) => {
        const keyId = await createSymKeyWithId(page, `e2e-ks-gen-${RUN_ID}`);
        await setRotationPolicy(page, keyId, keyId, 86400);

        const newKeyId = await rekeyKey(page, keyId);

        await gotoAndWait(page, "/ui/rotation-policy/sym/get");
        await page.fill('[data-testid="get-rotation-key-id"]', newKeyId);
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/rotation policy retrieved successfully/i);
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toBeVisible({
            timeout: UI_READY_TIMEOUT,
        });
        // Generation should be 1 after one rekey
        await expect(page.locator('[data-testid="rotation-policy-details"]')).toContainText("1");
    });
});
