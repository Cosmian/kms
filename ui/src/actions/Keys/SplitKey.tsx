import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SplitKeyFormData {
    keyId?: string;
}

/// Build a CreateSplitKey request. The server determines the number of shares
/// (from `crypto_officer_users` count when ceremony mode is enabled, or a
/// server-specified default otherwise). The client sends 2 as a placeholder —
/// the server will override it as needed.
const buildCreateSplitKeyRequest = (keyId: string) => ({
    tag: "CreateSplitKey",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        { tag: "SplitKeyParts", type: "Integer", value: 2 },
        { tag: "SplitKeyThreshold", type: "Integer", value: 2 },
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

type CreateSymKeyResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

const SplitKeyForm: React.FC = () => {
    const [form] = Form.useForm<SplitKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();

    const onFinish = async (values: SplitKeyFormData) => {
        await execute(async () => {
            // ── Step 1: Transparently create an AES-256 symmetric key ──────────
            const symReq = wasm.create_sym_key_ttlv_request(
                values.keyId || undefined,
                [],
                /* number_of_bits */ 256,
                "Aes",
                /* sensitive */ false,
                /* wrap_key_id */ undefined,
                /* wrap_key_b64 */ undefined,
            );
            const symRespStr = await sendKmipRequest(symReq, serverUrl);
            if (!symRespStr) {
                throw new Error("Symmetric key creation returned an empty response");
            }
            const symResp: CreateSymKeyResponse = await wasm.parse_create_ttlv_response(symRespStr);
            const createdKeyId = symResp.UniqueIdentifier;

            // ── Step 2: Split the newly created key ────────────────────────────
            const splitReq = buildCreateSplitKeyRequest(createdKeyId);
            const splitRespStr = await sendKmipRequest(splitReq, serverUrl);
            if (!splitRespStr) {
                throw new Error("Split key operation returned an empty response");
            }

            // Extract share UIDs from the TTLV response
            const parsed: { value: { tag: string; type: string; value: unknown }[] } = JSON.parse(splitRespStr);
            const shareUids = parsed.value
                .filter(
                    (item) =>
                        item.tag === "PrivateKeyUniqueIdentifier" ||
                        item.tag === "UniqueIdentifier" ||
                        item.tag === "SplitKeyUniqueIdentifiers",
                )
                .flatMap((item) => {
                    if (typeof item.value === "string") return [item.value];
                    if (Array.isArray(item.value)) {
                        return item.value
                            .filter(
                                (v: unknown) => typeof v === "object" && v != null && typeof (v as { value?: string }).value === "string",
                            )
                            .map((v: unknown) => (v as { value: string }).value);
                    }
                    return [];
                })
                .filter((v) => v.length > 0 && v !== createdKeyId);

            if (shareUids.length > 0) {
                return (
                    `AES-256 symmetric key created: ${createdKeyId}\n` +
                    `Split into ${shareUids.length} share(s):\n` +
                    shareUids.map((uid, i) => `  Share ${i + 1}: ${uid}`).join("\n")
                );
            }
            return `Symmetric key ${createdKeyId} created and split. Response: ${splitRespStr}`;
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Split Key</h1>

            <div className="mb-8 space-y-2">
                <p>Create an AES-256 symmetric key and split it into shares using XOR secret sharing (n-of-n):</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        A new AES-256 symmetric key is <strong>created transparently</strong> before the split operation.
                    </li>
                    <li>
                        <strong>All shares are required</strong> to reconstruct the key (threshold equals total parts).
                    </li>
                    <li>
                        The number of shares is determined by the server from the Crypto Officer configuration (when ceremony mode is
                        enabled) or a server default.
                    </li>
                    <li>Provides information-theoretic security for key ceremony workflows.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label="Key Unique Identifier" help="Optional: leave empty to auto‑generate a UUID">
                            <Input placeholder="Enter key ID (optional)" data-testid="split-key-id-input" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="split-key-submit-btn"
                        >
                            Create & Split Key
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Split Key Response" />
            </Form>
        </div>
    );
};

export default SplitKeyForm;
