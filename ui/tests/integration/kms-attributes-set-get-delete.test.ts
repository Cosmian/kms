import { beforeAll, describe, expect, test } from "vitest";

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { getNoTTLVRequest, sendKmipRequest } from "../../src/utils";
import init, * as wasm from "../../src/wasm/pkg";
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

function recordFromParsed(value: unknown): Record<string, unknown> {
    if (value instanceof Map) return Object.fromEntries(value as Map<string, unknown>);
    return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

describe.sequential("KMS attributes flow (set → get → delete)", () => {
    beforeAll(async () => {
        await waitForKmsServer();
        const wasmBytes = await readFile(new URL("../../src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm", import.meta.url));
        await init(wasmBytes);
    });

    test("symmetric key: set public_key_id link, read it back, delete it, then cleanup", async () => {
        const tags = ["vitest", "attributes", `t-${randomUUID()}`];

        const createReq = wasm.create_sym_key_ttlv_request(undefined, tags, 256, "Aes", false, undefined, undefined);
        const createStr = await sendKmipRequest(createReq, null, KMS_URL);
        const createResp = (await wasm.parse_create_ttlv_response(createStr)) as { UniqueIdentifier: string };
        const keyId = createResp.UniqueIdentifier;

        const cleanup = async (): Promise<void> => {
            try {
                await sendKmipRequest(wasmClient.revoke_ttlv_request(keyId, "vitest cleanup revoke"), null, KMS_URL);
            } catch {
                // ignore
            }
            try {
                await sendKmipRequest(wasmClient.destroy_ttlv_request(keyId, true), null, KMS_URL);
            } catch {
                // ignore
            }
        };

        try {
            const linkedPublicKeyId = `vitest-linked-pk-${randomUUID()}`;

            const setReq = wasmClient.set_attribute_ttlv_request(keyId, "public_key_id", linkedPublicKeyId);
            const setStr = await sendKmipRequest(setReq, null, KMS_URL);
            const setResp = wasmClient.parse_set_attribute_ttlv_response(setStr) as { UniqueIdentifier: string };
            expect(setResp.UniqueIdentifier).toBeTruthy();

            const getReq = wasmClient.get_attributes_ttlv_request(keyId);
            const getStr = await sendKmipRequest(getReq, null, KMS_URL);
            const parsed = wasmClient.parse_get_attributes_ttlv_response(getStr, ["public_key_id"]);
            const meta = recordFromParsed(parsed);

            expect(meta).toHaveProperty("public_key_id");
            expect(String(meta.public_key_id)).toContain(linkedPublicKeyId);

            const delReq = wasmClient.delete_attribute_ttlv_request(keyId, "public_key_id");
            const delStr = await sendKmipRequest(delReq, null, KMS_URL);
            const delResp = wasmClient.parse_delete_attribute_ttlv_response(delStr) as { UniqueIdentifier: string };
            expect(delResp.UniqueIdentifier).toBeTruthy();

            const getAfterReq = wasmClient.get_attributes_ttlv_request(keyId);
            const getAfterStr = await sendKmipRequest(getAfterReq, null, KMS_URL);
            const parsedAfter = wasmClient.parse_get_attributes_ttlv_response(getAfterStr, ["public_key_id"]);
            const metaAfter = recordFromParsed(parsedAfter);

            // Server may omit the attribute entirely or return an empty/null value.
            const afterVal = metaAfter.public_key_id;
            expect(afterVal == null || afterVal === "").toBe(true);

            await wasmClient.parse_revoke_ttlv_response(
                await sendKmipRequest(wasmClient.revoke_ttlv_request(keyId, "vitest revoke"), null, KMS_URL)
            );
            await wasmClient.parse_destroy_ttlv_response(
                await sendKmipRequest(wasmClient.destroy_ttlv_request(keyId, true), null, KMS_URL)
            );
        } catch (e) {
            await cleanup();
            throw e;
        }
    });
});
