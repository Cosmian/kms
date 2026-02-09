import { beforeAll, describe, expect, test } from "vitest";

import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";

import { getNoTTLVRequest, sendKmipRequest } from "../../src/utils";
import init, * as wasm from "../../src/wasm/pkg";
import * as wasmClient from "../../src/wasm/pkg/cosmian_kms_client_wasm";

const KMS_URL = process.env.KMS_URL ?? "http://localhost:9998";

async function waitForKmsServer(): Promise<void> {
    const deadline = Date.now() + 60_000;
    let lastError: unknown;

    while (Date.now() < deadline) {
        try {
            await getNoTTLVRequest("/version", null, KMS_URL);
            return;
        } catch (e) {
            lastError = e;
            await new Promise((r) => setTimeout(r, 1000));
        }
    }

    throw new Error(
        `KMS server not reachable at ${KMS_URL} within 60s. ` +
            `Start it with: cargo run -p cosmian_kms_server --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data --hostname 127.0.0.1 --port 9998. Last error: ${String(lastError)}`
    );
}

const toUint8 = (value: unknown): Uint8Array => {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (Array.isArray(value)) return new Uint8Array(value as number[]);
    if (value && typeof value === "object" && "buffer" in value) {
        const v = value as { buffer?: unknown };
        if (v.buffer instanceof ArrayBuffer) return new Uint8Array(v.buffer);
    }
    return new Uint8Array();
};

const base64UrlEncode = (bytes: Uint8Array): string =>
    Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

describe.sequential("Azure BYOK flow (import KEK → export .byok)", () => {
    beforeAll(async () => {
        await waitForKmsServer();
        const wasmBytes = await readFile(new URL("../../src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm", import.meta.url));
        await init(wasmBytes);
    });

    const unique = (): string => `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

    test("imports an Azure KEK and exports a wrapped key as Azure .byok JSON", async () => {
        const run = unique();

        // 1) Generate a PEM public key to simulate Azure KEK export.
        const { publicKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

        const kid = `https://example.vault.azure.net/keys/KEK-BYOK/${run}`;
        const kekTags = ["azure", `kid:${kid}`];
        const kekKeyUsage = ["WrapKey", "Encrypt"];
        const kekPemBytes = new TextEncoder().encode(publicKey);

        const importKekReq = wasm.import_ttlv_request(
            `vitest-azure-kek-${run}`,
            kekPemBytes,
            "pem",
            undefined,
            undefined,
            undefined,
            false,
            true,
            kekTags,
            kekKeyUsage,
            undefined
        );

        const importKekStr = await sendKmipRequest(importKekReq, null, KMS_URL);
        const importKekResp = (await wasm.parse_import_ttlv_response(importKekStr)) as { UniqueIdentifier: string };
        const kekId = importKekResp.UniqueIdentifier;

        // 2) Create a private key to be exported in wrapped form.
        const wrappedKeyTags = ["vitest", "azure-byok", `run-${run}`];
        const createReq = wasm.create_rsa_key_pair_ttlv_request(undefined, wrappedKeyTags, 2048, false, undefined);
        const createStr = await sendKmipRequest(createReq, null, KMS_URL);
        const createResp = (await wasm.parse_create_keypair_ttlv_response(createStr)) as {
            PrivateKeyUniqueIdentifier: string;
            PublicKeyUniqueIdentifier: string;
        };

        const wrappedPrivId = createResp.PrivateKeyUniqueIdentifier;

        try {
            // 3) Export the wrapped key using the imported Azure KEK.
            const exportReq = wasm.export_ttlv_request(wrappedPrivId, false, "raw", kekId, "rsa-aes-key-wrap-sha1", undefined);
            const exportStr = await sendKmipRequest(exportReq, null, KMS_URL);
            const wrappedKeyData = await wasm.parse_export_ttlv_response(exportStr, "raw");

            const wrappedKeyBytes =
                wrappedKeyData instanceof Uint8Array
                    ? wrappedKeyData
                    : typeof wrappedKeyData === "string"
                    ? toUint8(Buffer.from(wrappedKeyData, "base64"))
                    : toUint8(wrappedKeyData);

            expect(wrappedKeyBytes.length).toBeGreaterThan(0);

            // 4) Build the Azure .byok payload (same shape as `ui/src/AzureExportByok.tsx`).
            const ciphertext = base64UrlEncode(wrappedKeyBytes);
            const byok = {
                schema_version: "1.0.0",
                header: {
                    kid,
                    alg: "dir",
                    enc: "CKM_RSA_AES_KEY_WRAP",
                },
                ciphertext,
                generator: "Cosmian_KMS;v5",
            };

            expect(byok.header.kid).toBe(kid);
            expect(byok.header.enc).toBe("CKM_RSA_AES_KEY_WRAP");
            expect(byok.ciphertext).toBeTruthy();
            expect(byok.ciphertext).not.toContain("=");
            expect(byok.ciphertext).not.toContain("+");
            expect(byok.ciphertext).not.toContain("/");

            // Ensure it is valid JSON (Azure expects a JSON transfer blob).
            expect(() => JSON.stringify(byok)).not.toThrow();

            // 5) Cleanup.
            const revokeReq = wasmClient.revoke_ttlv_request(wrappedPrivId, "vitest revoke");
            const revokeStr = await sendKmipRequest(revokeReq, null, KMS_URL);
            await wasmClient.parse_revoke_ttlv_response(revokeStr);

            const destroyReq = wasmClient.destroy_ttlv_request(wrappedPrivId, true);
            const destroyStr = await sendKmipRequest(destroyReq, null, KMS_URL);
            await wasmClient.parse_destroy_ttlv_response(destroyStr);

            const revokeKekReq = wasmClient.revoke_ttlv_request(kekId, "vitest revoke");
            const revokeKekStr = await sendKmipRequest(revokeKekReq, null, KMS_URL);
            await wasmClient.parse_revoke_ttlv_response(revokeKekStr);

            const destroyKekReq = wasmClient.destroy_ttlv_request(kekId, true);
            const destroyKekStr = await sendKmipRequest(destroyKekReq, null, KMS_URL);
            await wasmClient.parse_destroy_ttlv_response(destroyKekStr);
        } catch (e) {
            // Best-effort cleanup.
            try {
                const revokeReq = wasmClient.revoke_ttlv_request(wrappedPrivId, "vitest cleanup revoke");
                await sendKmipRequest(revokeReq, null, KMS_URL);
            } catch {
                // ignore
            }
            try {
                const destroyReq = wasmClient.destroy_ttlv_request(wrappedPrivId, true);
                await sendKmipRequest(destroyReq, null, KMS_URL);
            } catch {
                // ignore
            }
            try {
                const revokeKekReq = wasmClient.revoke_ttlv_request(kekId, "vitest cleanup revoke");
                await sendKmipRequest(revokeKekReq, null, KMS_URL);
            } catch {
                // ignore
            }
            try {
                const destroyKekReq = wasmClient.destroy_ttlv_request(kekId, true);
                await sendKmipRequest(destroyKekReq, null, KMS_URL);
            } catch {
                // ignore
            }
            throw e;
        }
    });
});
