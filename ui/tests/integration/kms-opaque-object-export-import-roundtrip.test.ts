import { beforeAll, describe, expect, test } from "vitest";

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { getNoTTLVRequest, sendKmipRequest } from "../../src/utils";
import init, * as wasm from "../../src/wasm/pkg/cosmian_kms_client_wasm";
import * as wasmClient from "../../src/wasm/pkg/cosmian_kms_client_wasm";

const KMS_URL = process.env.KMS_URL ?? "http://localhost:9998";

async function waitForKmsServer(): Promise<void> {
    const deadline = Date.now() + 120_000;
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

const recordFromParsed = (value: unknown): Record<string, unknown> => {
    if (value instanceof Map) return Object.fromEntries(value as Map<string, unknown>);
    return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
};

describe.sequential("KMS opaque object export/import roundtrip", () => {
    beforeAll(async () => {
        await waitForKmsServer();
        const wasmBytes = await readFile(new URL("../../src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm", import.meta.url));
        await init(wasmBytes);
    });

    test("opaque object: create (from value) → locate → export json-ttlv → import under new ID → locate → cleanup", async () => {
        const baseTags = ["vitest", "secret-data", `t-${randomUUID()}`];
        const importedTags = [...baseTags, "imported"];

        const secretValue = `vitest-secret-${randomUUID()}`;

        const createReq = wasm.create_opaque_object_ttlv_request(secretValue, "test-opaque-object", baseTags, false);
        const createStr = await sendKmipRequest(createReq, null, KMS_URL);
        const createResp = (await wasm.parse_import_ttlv_response(createStr)) as { UniqueIdentifier: string };
        const secretId = createResp.UniqueIdentifier;

        const importedId = `vitest-secret-import-${randomUUID()}`;

        const cleanup = async (): Promise<void> => {
            for (const id of [importedId, secretId]) {
                try {
                    await sendKmipRequest(wasmClient.revoke_ttlv_request(id, "vitest cleanup revoke"), null, KMS_URL);
                } catch {
                    // ignore
                }
                try {
                    await sendKmipRequest(wasmClient.destroy_ttlv_request(id, true), null, KMS_URL);
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
            const locatedIds = Array.isArray((locateResp as { UniqueIdentifier?: string[] }).UniqueIdentifier)
                ? ((locateResp as { UniqueIdentifier?: string[] }).UniqueIdentifier as string[])
                : [];
            expect(locatedIds).toContain(secretId);

            const exportReq = wasm.export_ttlv_request(secretId, false, "json-ttlv", undefined, undefined);
            const exportStr = await sendKmipRequest(exportReq, null, KMS_URL);
            const exported = await wasm.parse_export_ttlv_response(exportStr, "json-ttlv");
            const exportedBytes = toBytes(exported);
            expect(exportedBytes.byteLength).toBeGreaterThan(0);

            const importReq = wasm.import_ttlv_request(
                importedId,
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
            const importedLocatedIds = Array.isArray((locateImportedResp as { UniqueIdentifier?: string[] }).UniqueIdentifier)
                ? ((locateImportedResp as { UniqueIdentifier?: string[] }).UniqueIdentifier as string[])
                : [];
            expect(importedLocatedIds).toContain(importedId);

            // Sanity-check object type via GetAttributes.
            const attrsStr = await sendKmipRequest(wasm.get_attributes_ttlv_request(importedId), null, KMS_URL);
            const parsedAttrs = await wasm.parse_get_attributes_ttlv_response(attrsStr, ["object_type"]);
            const meta = recordFromParsed(parsedAttrs);
            expect(String(meta.object_type ?? "")).toMatch(/opaque/i);

            await wasmClient.parse_revoke_ttlv_response(
                await sendKmipRequest(wasmClient.revoke_ttlv_request(secretId, "vitest revoke"), null, KMS_URL)
            );
            await wasmClient.parse_destroy_ttlv_response(
                await sendKmipRequest(wasmClient.destroy_ttlv_request(secretId, true), null, KMS_URL)
            );
            await wasmClient.parse_revoke_ttlv_response(
                await sendKmipRequest(wasmClient.revoke_ttlv_request(importedId, "vitest revoke imported"), null, KMS_URL)
            );
            await wasmClient.parse_destroy_ttlv_response(
                await sendKmipRequest(wasmClient.destroy_ttlv_request(importedId, true), null, KMS_URL)
            );
        } catch (e) {
            await cleanup();
            throw e;
        }
    });
});
