import { beforeAll, describe, expect, test } from "vitest";

import { randomUUID } from "node:crypto";
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

const toBytes = (value: unknown): Uint8Array => {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (Array.isArray(value)) return new Uint8Array(value as number[]);
    if (typeof value === "string") return new TextEncoder().encode(value);
    return new Uint8Array();
};

describe.sequential("KMS locate/export/import roundtrip", () => {
    beforeAll(async () => {
        await waitForKmsServer();
        const wasmBytes = await readFile(new URL("../../src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm", import.meta.url));
        await init(wasmBytes);
    });

    test("symmetric key: locate by tags, export json-ttlv, import under new ID, locate imported, then cleanup", async () => {
        const baseTags = ["vitest", "roundtrip", `t-${randomUUID()}`];
        const importedTags = [...baseTags, "imported"];

        const createReq = wasm.create_sym_key_ttlv_request(undefined, baseTags, 256, "Aes", false, undefined, undefined);
        const createStr = await sendKmipRequest(createReq, null, KMS_URL);
        const createResp = (await wasm.parse_create_ttlv_response(createStr)) as { UniqueIdentifier: string };
        const keyId = createResp.UniqueIdentifier;

        const importedKeyId = `vitest-import-${randomUUID()}`;

        const cleanup = async (): Promise<void> => {
            for (const id of [importedKeyId, keyId]) {
                try {
                    const revokeReq = wasmClient.revoke_ttlv_request(id, "vitest cleanup revoke");
                    await sendKmipRequest(revokeReq, null, KMS_URL);
                } catch {
                    // ignore
                }
                try {
                    const destroyReq = wasmClient.destroy_ttlv_request(id, true);
                    await sendKmipRequest(destroyReq, null, KMS_URL);
                } catch {
                    // ignore
                }
            }
        };

        try {
            const locateReq = wasm.locate_ttlv_request(
                baseTags,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined
            );
            const locateStr = await sendKmipRequest(locateReq, null, KMS_URL);
            const locateResp = await wasm.parse_locate_ttlv_response(locateStr);
            const locatedIds = Array.isArray(locateResp.UniqueIdentifier) ? (locateResp.UniqueIdentifier as string[]) : [];
            expect(locatedIds).toContain(keyId);

            const exportReq = wasm.export_ttlv_request(keyId, false, "json-ttlv", undefined, undefined);
            const exportStr = await sendKmipRequest(exportReq, null, KMS_URL);
            const exported = await wasm.parse_export_ttlv_response(exportStr, "json-ttlv");
            const exportedBytes = toBytes(exported);
            expect(exportedBytes.byteLength).toBeGreaterThan(0);

            const importReq = wasm.import_ttlv_request(
                importedKeyId,
                exportedBytes,
                "json-ttlv",
                undefined,
                undefined,
                undefined,
                false,
                true,
                importedTags,
                undefined,
                undefined
            );
            const importStr = await sendKmipRequest(importReq, null, KMS_URL);
            const importResp = (await wasm.parse_import_ttlv_response(importStr)) as { UniqueIdentifier: string };
            expect(importResp.UniqueIdentifier).toBeTruthy();

            const locateImportedReq = wasm.locate_ttlv_request(
                importedTags,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined
            );
            const locateImportedStr = await sendKmipRequest(locateImportedReq, null, KMS_URL);
            const locateImportedResp = await wasm.parse_locate_ttlv_response(locateImportedStr);
            const importedLocatedIds = Array.isArray(locateImportedResp.UniqueIdentifier)
                ? (locateImportedResp.UniqueIdentifier as string[])
                : [];

            expect(importedLocatedIds).toContain(importedKeyId);

            const revokeReq = wasmClient.revoke_ttlv_request(keyId, "vitest revoke");
            const revokeStr = await sendKmipRequest(revokeReq, null, KMS_URL);
            await wasmClient.parse_revoke_ttlv_response(revokeStr);

            const destroyReq = wasmClient.destroy_ttlv_request(keyId, true);
            const destroyStr = await sendKmipRequest(destroyReq, null, KMS_URL);
            await wasmClient.parse_destroy_ttlv_response(destroyStr);

            const revokeImportedReq = wasmClient.revoke_ttlv_request(importedKeyId, "vitest revoke imported");
            const revokeImportedStr = await sendKmipRequest(revokeImportedReq, null, KMS_URL);
            await wasmClient.parse_revoke_ttlv_response(revokeImportedStr);

            const destroyImportedReq = wasmClient.destroy_ttlv_request(importedKeyId, true);
            const destroyImportedStr = await sendKmipRequest(destroyImportedReq, null, KMS_URL);
            await wasmClient.parse_destroy_ttlv_response(destroyImportedStr);
        } catch (e) {
            await cleanup();
            throw e;
        }
    });
});
