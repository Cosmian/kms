import { Badge, Button, Card, Form, Input, Select, Space, Tag, Tooltip, Typography } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { getNoTTLVRequest, postNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import LocateButton from "../../components/common/LocateButton";
import * as wasm from "../../wasm/pkg";
import { buildCreateSplitKeyRequest } from "../../utils/splitKeyUtils";

const { Text } = Typography;

interface CryptoOfficerStatus {
    enabled: boolean;
    users: string[];
    /** Subset of `users` that currently hold an active ceremony activation. */
    active_co_users: string[];
    custodians_count: number;
    require_ceremony: boolean;
    ceremony_activated: boolean;
    is_crypto_officer: boolean;
}

interface CeremonyActivateFormData {
    shareIds: { value: string }[];
}

type CreateSymKeyResponse = { UniqueIdentifier: string };
type CreateSplitKeyResponse = { UniqueIdentifier: string | string[] };

const CryptoOfficerRole: React.FC = () => {
    const { t } = useTranslation("actions");
    const [isLoading, setIsLoading] = useState(false);
    const [isDisabling, setIsDisabling] = useState(false);
    const [isActivating, setIsActivating] = useState(false);
    const [isSplitting, setIsSplitting] = useState(false);
    const [status, setStatus] = useState<CryptoOfficerStatus | undefined>(undefined);
    const [res, setRes] = useState<string | undefined>(undefined);
    const [splitRes, setSplitRes] = useState<string | undefined>(undefined);
    /** Custom base UID for the ceremony key — shares will be named `<id>#1`, `<id>#2`, … */
    const [splitKeyId, setSplitKeyId] = useState<string>("");
    /** Target user for peer revocation (empty = self-revoke) */
    const [revokeTarget, setRevokeTarget] = useState<string>("");
    const { serverUrl, userId } = useAuth();
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
            setRes(t("cryptoOfficer.errorFetching", { error: String(e) }));
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, activateForm, t]);

    const disableCeremony = useCallback(async () => {
        setIsDisabling(true);
        setRes(undefined);
        try {
            const body: { target_user?: string } = {};
            if (revokeTarget.trim()) body.target_user = revokeTarget.trim();
            const response = (await postNoTTLVRequest("/access/crypto_officer/disable", body, serverUrl)) as {
                success: string;
            };
            setRes(response.success);
            setRevokeTarget("");
            await fetchStatus();
        } catch (e) {
            setRes(t("cryptoOfficer.errorDisabling", { error: String(e) }));
        } finally {
            setIsDisabling(false);
        }
    }, [serverUrl, fetchStatus, revokeTarget, t]);

    // ── Step 1: Create & Split Key ────────────────────────────────────────────
    // Creates an AES-256 key (optionally with a custom UID) and splits it into
    // `custodians_count` shares — one per CO candidate.  When a custom UID is
    // provided, shares are named `<id>#1`, `<id>#2`, … for human-friendly lookup.
    const createAndSplitKey = useCallback(async () => {
        if (!status) return;
        const n = status.custodians_count;
        const customId = splitKeyId.trim() || undefined;
        setIsSplitting(true);
        setSplitRes(undefined);
        try {
            // Create a new AES-256 symmetric key, optionally with a custom UID
            const symReq = wasm.create_sym_key_ttlv_request(customId ?? null, [], 256, "Aes", false, undefined, undefined);
            const symRespStr = await sendKmipRequest(symReq, serverUrl);
            if (!symRespStr) throw new Error("Symmetric key creation returned an empty response");

            const symResp: CreateSymKeyResponse = await wasm.parse_create_ttlv_response(symRespStr);
            const createdKeyId = symResp.UniqueIdentifier;

            // Split the key into n shares (n = custodians_count)
            const splitReq = buildCreateSplitKeyRequest(createdKeyId, n);
            let splitRespStr: string | null;
            try {
                splitRespStr = await sendKmipRequest(splitReq, serverUrl);
            } catch (splitErr) {
                // Compensating delete: destroy the orphaned AES key before re-throwing
                try {
                    const destroyReq = wasm.destroy_ttlv_request(createdKeyId, true);
                    await sendKmipRequest(destroyReq, serverUrl);
                } catch {
                    /* best-effort; ignore cleanup errors */
                }
                throw splitErr;
            }
            if (!splitRespStr) throw new Error("Split key operation returned an empty response");

            const splitResp: CreateSplitKeyResponse = await wasm.parse_create_split_key_ttlv_response(splitRespStr);
            const shareUids: string[] = Array.isArray(splitResp.UniqueIdentifier)
                ? splitResp.UniqueIdentifier
                : splitResp.UniqueIdentifier
                  ? [splitResp.UniqueIdentifier]
                  : [];

            if (shareUids.length === 0) {
                throw new Error(`No share UIDs returned from split operation. Raw response: ${splitRespStr}`);
            }

            // Auto-populate the activation form's share UID inputs
            activateForm.setFieldsValue({
                shareIds: shareUids.map((uid) => ({ value: uid })),
            });

            setSplitRes(
                `${t("cryptoOfficer.splitResult", { keyId: createdKeyId, count: shareUids.length })}\n` +
                    shareUids.map((uid, i) => `  ${t("cryptoOfficer.shareLine", { n: i + 1 })}: ${uid}`).join("\n"),
            );
        } catch (e) {
            setSplitRes(t("cryptoOfficer.errorSplitting", { error: String(e) }));
        } finally {
            setIsSplitting(false);
        }
    }, [status, serverUrl, activateForm, splitKeyId, t]);

    const activateCeremony = useCallback(
        async (values: CeremonyActivateFormData) => {
            setIsActivating(true);
            setRes(undefined);
            try {
                const shareIds = values.shareIds.map((item) => item.value).filter((v) => v && v.trim().length > 0);
                if (shareIds.length < 2) {
                    setRes(t("cryptoOfficer.errorAtLeastTwoShares"));
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
                setRes(t("cryptoOfficer.errorActivating", { error: String(e) }));
            } finally {
                setIsActivating(false);
            }
        },
        [serverUrl, fetchStatus, t],
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
                <h1 className="text-2xl font-bold">{t("cryptoOfficer.title")}</h1>
                <Button
                    type="primary"
                    onClick={fetchStatus}
                    loading={isLoading}
                    data-testid="refresh-btn"
                    className="bg-black-500 hover:bg-blue-700 border-0"
                >
                    {t("cryptoOfficer.refresh")}
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>
                    <Trans ns="actions" i18nKey="cryptoOfficer.intro" components={{ strong: <strong /> }} />
                </p>
                <p>
                    <Trans
                        ns="actions"
                        i18nKey="cryptoOfficer.introModes"
                        components={{
                            em: <em />,
                            a: (
                                <a
                                    href="https://docs.cosmian.com/key_management_system/configuration/authorization/key_ceremony/"
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-blue-600 dark:text-blue-400 underline"
                                />
                            ),
                        }}
                    />
                </p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                {status && !status.enabled && (
                    <Card data-testid="response-output">
                        <p className="text-gray-500 dark:text-gray-400">{t("cryptoOfficer.notConfigured")}</p>
                    </Card>
                )}

                {status && status.enabled && (
                    <Card title={t("cryptoOfficer.statusTitle")} data-testid="role-status-card">
                        <div className="space-y-4">
                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">{t("cryptoOfficer.roleEnabled")}</span>
                                <Badge status="success" text={t("cryptoOfficer.yes")} />
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">{t("cryptoOfficer.ceremonyRequired")}</span>
                                {status.require_ceremony ? (
                                    <Badge status="warning" text={t("cryptoOfficer.yesSplitKeyCeremony")} />
                                ) : (
                                    <Badge status="default" text={t("cryptoOfficer.noConfigOnly")} />
                                )}
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">{t("cryptoOfficer.ceremonyActive")}</span>
                                {status.ceremony_activated ? (
                                    <Badge status="success" text={t("cryptoOfficer.active")} />
                                ) : status.require_ceremony ? (
                                    <Badge status="error" text={t("cryptoOfficer.dormant")} />
                                ) : (
                                    <Badge status="default" text={t("cryptoOfficer.naConfigOnly")} />
                                )}
                            </div>

                            <div className="flex items-center gap-3">
                                <span className="font-medium w-40">{t("cryptoOfficer.youAreCo")}</span>
                                {status.is_crypto_officer ? (
                                    <Badge status="success" text={t("cryptoOfficer.yesOwnershipBypass")} />
                                ) : (
                                    <Badge status="default" text={t("cryptoOfficer.no")} />
                                )}
                            </div>

                            <div className="flex items-start gap-3">
                                <span className="font-medium w-40">{t("cryptoOfficer.coUsers")}</span>
                                <div className="flex flex-wrap gap-1">
                                    {status.users.map((u) => (
                                        <Tag key={u} color="blue">
                                            {u}
                                        </Tag>
                                    ))}
                                </div>
                            </div>

                            {/* Only CO candidates (active or dormant) see the revoke section.
                                Active COs can self-revoke (empty target) or peer-revoke.
                                Dormant candidates can only peer-revoke (button disabled otherwise).
                                Non-CO users are excluded: ceremony_activated is system-wide
                                (any CO active), but users who are not CO candidates have no
                                meaningful action here and should not see the controls. */}
                            {status.ceremony_activated && (status.is_crypto_officer || status.users.includes(userId ?? "")) && (
                                <div className="pt-2 border-t space-y-3">
                                    <p className="text-sm font-medium">{t("cryptoOfficer.revokeRole")}</p>
                                    <Space direction="vertical" style={{ display: "flex" }}>
                                        {/* List active COs only; current user is filtered out (self-revoke uses empty selection) */}
                                        <Select
                                            placeholder={t("cryptoOfficer.selectRevokePlaceholder")}
                                            value={revokeTarget || undefined}
                                            onChange={(val: string | undefined) => setRevokeTarget(val ?? "")}
                                            allowClear
                                            style={{ width: 380 }}
                                            options={(status.active_co_users ?? status.users)
                                                .filter((u) => u !== userId)
                                                .map((u) => ({
                                                    value: u,
                                                    label: u,
                                                }))}
                                            data-testid="revoke-target-select"
                                        />
                                        <p className="text-xs text-gray-500 dark:text-gray-400">
                                            {status.is_crypto_officer
                                                ? t("cryptoOfficer.revokeHint")
                                                : t("cryptoOfficer.revokeHintDormant")}
                                        </p>
                                        <Tooltip
                                            title={
                                                !status.is_crypto_officer && !revokeTarget.trim()
                                                    ? t("cryptoOfficer.tooltipNotActive")
                                                    : revokeTarget.trim()
                                                      ? t("cryptoOfficer.tooltipRevokeFor", { user: revokeTarget.trim() })
                                                      : t("cryptoOfficer.tooltipSelfRevoke")
                                            }
                                        >
                                            <Button
                                                danger
                                                onClick={disableCeremony}
                                                loading={isDisabling}
                                                disabled={!status.is_crypto_officer && !revokeTarget.trim()}
                                                data-testid="disable-btn"
                                            >
                                                {revokeTarget.trim()
                                                    ? t("cryptoOfficer.revokeFor", { user: revokeTarget.trim() })
                                                    : t("cryptoOfficer.revokeMyCeremony")}
                                            </Button>
                                        </Tooltip>
                                    </Space>
                                </div>
                            )}
                        </div>
                    </Card>
                )}

                {/* Ceremony workflow — shown when ceremony is required and the current user is not yet active.
                    With the per-user model multiple COs can be simultaneously active, so we gate on
                    `is_crypto_officer` (am I personally active?) not `ceremony_activated` (is anyone active?). */}
                {status && status.enabled && status.require_ceremony && !status.is_crypto_officer && (
                    <>
                        {/* ── Step 1: Create & Split Key ────────────────────────────── */}
                        <Card title={t("cryptoOfficer.step1Title", { count: status.custodians_count })} data-testid="split-key-step-card">
                            <p className="mb-4 text-gray-600 dark:text-gray-300">
                                <Trans
                                    ns="actions"
                                    i18nKey="cryptoOfficer.step1Description"
                                    values={{ count: status.custodians_count }}
                                    components={{ strong: <strong /> }}
                                />
                            </p>
                            <Space direction="vertical" style={{ display: "flex", marginBottom: 16 }}>
                                <Space align="baseline" wrap>
                                    <Input
                                        placeholder={t("cryptoOfficer.ceremonyKeyPlaceholder")}
                                        value={splitKeyId}
                                        onChange={(e) => setSplitKeyId(e.target.value)}
                                        style={{ width: 320 }}
                                        allowClear
                                        data-testid="split-key-id-input"
                                    />
                                    <Button
                                        type="default"
                                        onClick={createAndSplitKey}
                                        loading={isSplitting}
                                        data-testid="create-split-key-btn"
                                    >
                                        {t("cryptoOfficer.createSplitKey", { count: status.custodians_count })}
                                    </Button>
                                </Space>
                                {splitKeyId.trim() && (
                                    <Text type="secondary" style={{ fontSize: 12 }}>
                                        {t("cryptoOfficer.shareIdsWillBe")}{" "}
                                        {Array.from({ length: status.custodians_count }, (_, i) => (
                                            <Text key={i} code style={{ marginRight: 4 }}>
                                                {splitKeyId.trim()}#{i + 1}
                                            </Text>
                                        ))}
                                    </Text>
                                )}
                            </Space>
                            {splitRes && (
                                <pre
                                    className="mt-3 p-3 bg-gray-50 dark:bg-gray-800 border rounded text-xs overflow-auto whitespace-pre-wrap"
                                    data-testid="split-key-result"
                                >
                                    {splitRes}
                                </pre>
                            )}
                        </Card>

                        {/* ── Step 2: Activate Ceremony ─────────────────────────────── */}
                        <Card title={t("cryptoOfficer.step2Title")} data-testid="activate-ceremony-card">
                            <p className="mb-4 text-gray-600 dark:text-gray-300">
                                {t("cryptoOfficer.step2Description", { count: status.custodians_count })}
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
                                                            rules={[{ required: true, message: t("cryptoOfficer.shareUidRequired") }]}
                                                            noStyle
                                                        >
                                                            <Input
                                                                placeholder={t("cryptoOfficer.sharePlaceholder", { n: index + 1 })}
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
                                        {t("cryptoOfficer.activateCeremony")}
                                    </Button>
                                </Form.Item>
                            </Form>
                        </Card>
                    </>
                )}
            </Space>

            {res && (
                <div ref={responseRef} className="mt-4">
                    <Card title={t("cryptoOfficer.response")} data-testid="activate-ceremony-response">
                        <p>{res}</p>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default CryptoOfficerRole;
