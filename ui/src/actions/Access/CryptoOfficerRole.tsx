import { Badge, Button, Card, Form, Input, Space, Tag, Tooltip } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/useAuth";
import { getNoTTLVRequest, postNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import LocateButton from "../../components/common/LocateButton";
import * as wasm from "../../wasm/pkg";

interface CryptoOfficerStatus {
    enabled: boolean;
    users: string[];
    custodians_count: number;
    require_ceremony: boolean;
    ceremony_activated: boolean;
    is_crypto_officer: boolean;
}

interface CeremonyActivateFormData {
    shareIds: { value: string }[];
}

type CreateSymKeyResponse = { UniqueIdentifier: string };
type CreateSplitKeyResponse = { UniqueIdentifier: string; PrivateKeyUniqueIdentifier: string[] };

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

const CryptoOfficerRole: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [isDisabling, setIsDisabling] = useState(false);
    const [isActivating, setIsActivating] = useState(false);
    const [isSplitting, setIsSplitting] = useState(false);
    const [status, setStatus] = useState<CryptoOfficerStatus | undefined>(undefined);
    const [res, setRes] = useState<string | undefined>(undefined);
    const [splitRes, setSplitRes] = useState<string | undefined>(undefined);
    const { serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [activateForm] = Form.useForm<CeremonyActivateFormData>();

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchStatus = useCallback(async () => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = (await getNoTTLVRequest("/access/crypto_officer/status", serverUrl)) as CryptoOfficerStatus;
            setStatus(response);
            // Pre-fill share ID slots when custodians_count is known
            if (response.enabled && response.custodians_count > 0) {
                activateForm.setFieldsValue({
                    shareIds: Array.from({ length: response.custodians_count }, () => ({ value: "" })),
                });
            }
        } catch (e) {
            setRes(`Error fetching Crypto Officer status: ${e}`);
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, activateForm]);

    const disableCeremony = useCallback(async () => {
        setIsDisabling(true);
        setRes(undefined);
        try {
            const response = (await postNoTTLVRequest("/access/crypto_officer/disable", {}, serverUrl)) as {
                success: string;
            };
            setRes(response.success);
            await fetchStatus();
        } catch (e) {
            setRes(`Error disabling Crypto Officer ceremony: ${e}`);
        } finally {
            setIsDisabling(false);
        }
    }, [serverUrl, fetchStatus]);

    // ── Step 1: Create & Split Key ────────────────────────────────────────────
    // Creates an AES-256 key and splits it into `custodians_count` shares, then
    // auto-populates the "Activate Ceremony" share-ID inputs below.
    const createAndSplitKey = useCallback(async () => {
        if (!status) return;
        const n = status.custodians_count;
        setIsSplitting(true);
        setSplitRes(undefined);
        try {
            // Create a new AES-256 symmetric key
            const symReq = wasm.create_sym_key_ttlv_request(
                undefined,
                [],
                256,
                "Aes",
                false,
                undefined,
                undefined,
            );
            const symRespStr = await sendKmipRequest(symReq, serverUrl);
            if (!symRespStr) throw new Error("Symmetric key creation returned an empty response");

            const symResp: CreateSymKeyResponse = await wasm.parse_create_ttlv_response(symRespStr);
            const createdKeyId = symResp.UniqueIdentifier;

            // Split the key into n shares (n = custodians_count)
            const splitReq = buildCreateSplitKeyRequest(createdKeyId, n);
            const splitRespStr = await sendKmipRequest(splitReq, serverUrl);
            if (!splitRespStr) throw new Error("Split key operation returned an empty response");

            const splitResp: CreateSplitKeyResponse = await wasm.parse_create_split_key_ttlv_response(splitRespStr);
            const shareUids: string[] = Array.isArray(splitResp.PrivateKeyUniqueIdentifier)
                ? splitResp.PrivateKeyUniqueIdentifier
                : splitResp.PrivateKeyUniqueIdentifier
                  ? [splitResp.PrivateKeyUniqueIdentifier]
                  : [];

            if (shareUids.length === 0) {
                throw new Error(`No share UIDs returned from split operation. Raw response: ${splitRespStr}`);
            }

            // Auto-populate the activation form's share UID inputs
            activateForm.setFieldsValue({
                shareIds: shareUids.map((uid) => ({ value: uid })),
            });

            setSplitRes(
                `AES-256 key created: ${createdKeyId}\n` +
                    `Split into ${shareUids.length} share(s) — UIDs auto-filled below:\n` +
                    shareUids.map((uid, i) => `  Share ${i + 1}: ${uid}`).join("\n"),
            );
        } catch (e) {
            setSplitRes(`Error creating/splitting key: ${e}`);
        } finally {
            setIsSplitting(false);
        }
    }, [status, serverUrl, activateForm]);

    const activateCeremony = useCallback(
        async (values: CeremonyActivateFormData) => {
            setIsActivating(true);
            setRes(undefined);
            try {
                const shareIds = values.shareIds.map((item) => item.value).filter((v) => v && v.trim().length > 0);
                if (shareIds.length < 2) {
                    setRes("Error: at least 2 share UIDs are required.");
                    return;
                }
                const response = (await postNoTTLVRequest(
                    "/access/crypto_officer/ceremony/activate",
                    { share_ids: shareIds },
                    serverUrl,
                )) as { success: string };
                setRes(response.success);
                await fetchStatus();
            } catch (e) {
                setRes(`Error activating Crypto Officer ceremony: ${e}`);
            } finally {
                setIsActivating(false);
            }
        },
        [serverUrl, fetchStatus],
    );

    const onLocateSelect = useCallback(
        (index: number, uid: string) => {
            const current: { value: string }[] = activateForm.getFieldValue("shareIds") || [];
            const updated = [...current];
            if (index < updated.length) updated[index] = { value: uid };
            activateForm.setFieldsValue({ shareIds: updated });
        },
        [activateForm],
    );

    useEffect(() => {
        fetchStatus();
    }, [fetchStatus]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">Crypto Officer Role</h1>
                <Button
                    type="primary"
                    onClick={fetchStatus}
                    loading={isLoading}
                    data-testid="refresh-btn"
                    className="bg-black-500 hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>
                    The <strong>Crypto Officer</strong> role grants key lifecycle management (create, import, certify, rekey, activate,
                    revoke, destroy), raw key material access (get, export), and an ownership bypass — allowing retrieval and management of
                    any object regardless of who created it.
                </p>
                <p>
                    This role can operate in <em>config-only</em> mode (immediately active) or <em>ceremony mode</em> (dormant until a
                    split-key ceremony completes). See{" "}
                    <a href="https://docs.cosmian.com/key_ceremony" target="_blank" rel="noreferrer" className="text-blue-600 underline">
                        Key ceremony documentation
                    </a>{" "}
                    for details.
                </p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                {status && !status.enabled && (
                    <Card data-testid="response-output">
                        <p className="text-gray-500">Crypto Officer role is not configured on this server.</p>
                    </Card>
                )}

                {status && status.enabled && (
                    <Card title="Crypto Officer Role Status" data-testid="role-status-card">
                        <div className="space-y-4">
                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">Role enabled:</span>
                                <Badge status="success" text="Yes" />
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">Ceremony required:</span>
                                {status.require_ceremony ? (
                                    <Badge status="warning" text="Yes — split-key ceremony" />
                                ) : (
                                    <Badge status="default" text="No — config-only" />
                                )}
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">Ceremony active:</span>
                                {status.ceremony_activated ? (
                                    <Badge status="success" text="Active" />
                                ) : status.require_ceremony ? (
                                    <Badge status="error" text="Dormant (ceremony not completed)" />
                                ) : (
                                    <Badge status="default" text="N/A (config-only mode)" />
                                )}
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">You are CO:</span>
                                {status.is_crypto_officer ? (
                                    <Badge status="success" text="Yes — your requests have ownership bypass" />
                                ) : (
                                    <Badge status="default" text="No" />
                                )}
                            </div>

                            <div className="flex items-start gap-3">
                                <span className="font-medium w-40">CO users:</span>
                                <div className="flex flex-wrap gap-1">
                                    {status.users.map((u) => (
                                        <Tag key={u} color="blue">
                                            {u}
                                        </Tag>
                                    ))}
                                </div>
                            </div>

                            {status.ceremony_activated && (
                                <div className="pt-2 border-t">
                                    <Tooltip
                                        title={
                                            !status.is_crypto_officer
                                                ? "Only an active Crypto Officer can disable the ceremony"
                                                : "Revokes the active ceremony. The role becomes dormant until a new ceremony completes."
                                        }
                                    >
                                        <Button
                                            danger
                                            onClick={disableCeremony}
                                            loading={isDisabling}
                                            disabled={!status.is_crypto_officer}
                                            data-testid="disable-btn"
                                        >
                                            Revoke Crypto Officer Ceremony
                                        </Button>
                                    </Tooltip>
                                </div>
                            )}
                        </div>
                    </Card>
                )}

                {/* Ceremony workflow — only shown when ceremony mode is required and role is dormant */}
                {status && status.enabled && status.require_ceremony && !status.ceremony_activated && (
                    <>
                        {/* ── Step 1: Create & Split Key ────────────────────────────── */}
                        <Card
                            title={`Step 1 — Create & Split Key (${status.custodians_count} shares)`}
                            data-testid="split-key-step-card"
                        >
                            <p className="mb-4 text-gray-600">
                                Creates a new AES-256 key and splits it into <strong>{status.custodians_count} shares</strong> — one per
                                Crypto Officer candidate. The share UIDs are auto-filled into Step 2 below. You may also fill the UIDs
                                manually if you already have them.
                            </p>
                            <Button
                                type="default"
                                onClick={createAndSplitKey}
                                loading={isSplitting}
                                data-testid="create-split-key-btn"
                            >
                                Create & Split Key ({status.custodians_count} shares)
                            </Button>
                            {splitRes && (
                                <pre className="mt-3 p-3 bg-gray-50 border rounded text-xs overflow-auto whitespace-pre-wrap" data-testid="split-key-result">
                                    {splitRes}
                                </pre>
                            )}
                        </Card>

                        {/* ── Step 2: Activate Ceremony ─────────────────────────────── */}
                        <Card title="Step 2 — Activate Ceremony" data-testid="activate-ceremony-card">
                            <p className="mb-4 text-gray-600">
                                Provide all {status.custodians_count} share UIDs from the ceremony split key. Each share must be owned by a
                                different Crypto Officer — not by you (dual-control requirement). The server reconstructs the secret in RAM
                                and zeroizes it immediately after activation; no key is stored.
                            </p>
                            <Form
                                form={activateForm}
                                onFinish={activateCeremony}
                                layout="vertical"
                                initialValues={{
                                    shareIds: Array.from({ length: status.custodians_count }, () => ({ value: "" })),
                                }}
                            >
                                <Form.List name="shareIds">
                                    {(fields) => (
                                        <>
                                            {fields.map((field, index) => (
                                                <Form.Item key={field.key} required>
                                                    <Space align="baseline" className="w-full">
                                                        <Form.Item
                                                            {...field}
                                                            name={[field.name, "value"]}
                                                            rules={[{ required: true, message: "Share UID is required" }]}
                                                            noStyle
                                                        >
                                                            <Input
                                                                placeholder={`Share ${index + 1} UID (from CO ${index + 1})`}
                                                                style={{ width: 380 }}
                                                                data-testid={`ceremony-share-id-${index}`}
                                                            />
                                                        </Form.Item>
                                                        <LocateButton
                                                            objectType="SplitKey"
                                                            onSelect={(uid: string) => onLocateSelect(index, uid)}
                                                        />
                                                    </Space>
                                                </Form.Item>
                                            ))}
                                        </>
                                    )}
                                </Form.List>
                                <Form.Item>
                                    <Button
                                        type="primary"
                                        htmlType="submit"
                                        loading={isActivating}
                                        data-testid="activate-ceremony-btn"
                                        className="bg-green-600 hover:bg-green-700 border-0"
                                    >
                                        Activate Crypto Officer Ceremony
                                    </Button>
                                </Form.Item>
                            </Form>
                        </Card>
                    </>
                )}
            </Space>

            {res && (
                <div ref={responseRef} className="mt-4">
                    <Card title="Response" data-testid="activate-ceremony-response">
                        <p>{res}</p>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default CryptoOfficerRole;
