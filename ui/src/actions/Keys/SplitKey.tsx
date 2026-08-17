import { Badge, Button, Card, Form, Input, InputNumber, Space, Spin } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { getNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/useAuth";

interface SplitKeyFormData {
    keyId?: string;
    shareCount: number;
}

interface CoStatus {
    enabled: boolean;
    require_ceremony: boolean;
    custodians_count: number;
}

/// Build a CreateSplitKey TTLV request.  The caller supplies the resolved `n`
/// (either from the server's CO configuration or from the user's input field).
const buildCreateSplitKeyRequest = (keyId: string, n: number) => ({
    tag: "CreateSplitKey",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        { tag: "SplitKeyParts", type: "Integer", value: n },
        { tag: "SplitKeyThreshold", type: "Integer", value: n },
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

type CreateSymKeyResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

type CreateSplitKeyResponse = {
    UniqueIdentifier: string;
    PrivateKeyUniqueIdentifier: string[];
};

const SplitKeyForm: React.FC = () => {
    const [form] = Form.useForm<SplitKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { serverUrl: authServerUrl } = useAuth();
    const [coStatus, setCoStatus] = useState<CoStatus | undefined>(undefined);
    const [statusLoading, setStatusLoading] = useState(false);

    // Fetch CO status once on mount to discover custodians_count.
    const fetchCoStatus = useCallback(async () => {
        setStatusLoading(true);
        try {
            const s = (await getNoTTLVRequest("/access/crypto_officer/status", authServerUrl ?? serverUrl)) as CoStatus;
            setCoStatus(s);
            if (s.enabled && s.require_ceremony && s.custodians_count >= 2) {
                form.setFieldsValue({ shareCount: s.custodians_count });
            }
        } catch {
            // Status endpoint may be unavailable when CO is not configured — ignore.
        } finally {
            setStatusLoading(false);
        }
    }, [authServerUrl, serverUrl, form]);

    useEffect(() => {
        fetchCoStatus();
    }, [fetchCoStatus]);

    const ceremonyMode = coStatus?.enabled && coStatus.require_ceremony && (coStatus.custodians_count ?? 0) >= 2;
    const resolvedShareCount = ceremonyMode ? coStatus!.custodians_count : undefined;

    const onFinish = async (values: SplitKeyFormData) => {
        const n = resolvedShareCount ?? values.shareCount ?? 2;

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
            const splitReq = buildCreateSplitKeyRequest(createdKeyId, n);
            const splitRespStr = await sendKmipRequest(splitReq, serverUrl);
            if (!splitRespStr) {
                throw new Error("Split key operation returned an empty response");
            }

            // Use the WASM parser for type-safe CreateSplitKeyResponse parsing.
            const splitResp: CreateSplitKeyResponse = await wasm.parse_create_split_key_ttlv_response(splitRespStr);
            const shareUids: string[] = Array.isArray(splitResp.PrivateKeyUniqueIdentifier)
                ? splitResp.PrivateKeyUniqueIdentifier
                : splitResp.PrivateKeyUniqueIdentifier
                  ? [splitResp.PrivateKeyUniqueIdentifier]
                  : [];

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
                    {ceremonyMode ? (
                        <li>
                            <strong>Ceremony mode:</strong> the server determines the number of shares from the Crypto Officer configuration
                            ({resolvedShareCount} shares — one per CO candidate).
                        </li>
                    ) : (
                        <li>The number of shares is set below.</li>
                    )}
                    <li>Provides information-theoretic security for key ceremony workflows.</li>
                </ul>
            </div>

            {statusLoading && (
                <div className="mb-4 flex items-center gap-2 text-gray-500">
                    <Spin size="small" /> Loading server configuration…
                </div>
            )}

            {!statusLoading && coStatus && (
                <div className="mb-4">
                    <Badge
                        status={ceremonyMode ? "warning" : "default"}
                        text={
                            ceremonyMode
                                ? `Ceremony mode — ${resolvedShareCount} shares (from server CO config)`
                                : "Standard split key mode"
                        }
                        data-testid="split-key-mode-badge"
                    />
                </div>
            )}

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ shareCount: 2 }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label="Key Unique Identifier" help="Optional: leave empty to auto‑generate a UUID">
                            <Input placeholder="Enter key ID (optional)" data-testid="split-key-id-input" />
                        </Form.Item>

                        <Form.Item
                            name="shareCount"
                            label="Number of shares (n)"
                            tooltip={
                                ceremonyMode
                                    ? `Fixed to ${resolvedShareCount} by the server's Crypto Officer configuration`
                                    : "All n shares are required to reconstruct the key (n-of-n XOR)"
                            }
                            rules={[{ required: !ceremonyMode, message: "Share count is required" }]}
                        >
                            <InputNumber
                                min={2}
                                max={20}
                                disabled={ceremonyMode}
                                data-testid="split-key-share-count-input"
                                style={{ width: 120 }}
                            />
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
