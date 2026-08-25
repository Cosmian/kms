import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { buildCreateSplitKeyRequest } from "../../utils/splitKeyUtils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SplitKeyFormData {
    keyId?: string;
    shareCount: number;
}

type CreateSymKeyResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

type CreateSplitKeyResponse = {
    // Vec<UniqueIdentifier> serialised by serde_wasm_bindgen as an array
    UniqueIdentifier: string | string[];
};

const SplitKeyForm: React.FC = () => {
    const { t } = useTranslation("actions");
    const [form] = Form.useForm<SplitKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();

    const onFinish = async (values: SplitKeyFormData) => {
        const n = values.shareCount ?? 2;

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
            if (!splitRespStr) {
                throw new Error("Split key operation returned an empty response");
            }

            const splitResp: CreateSplitKeyResponse = await wasm.parse_create_split_key_ttlv_response(splitRespStr);
            const shareUids: string[] = Array.isArray(splitResp.UniqueIdentifier)
                ? splitResp.UniqueIdentifier
                : splitResp.UniqueIdentifier
                  ? [splitResp.UniqueIdentifier]
                  : [];

            if (shareUids.length > 0) {
                return (
                    `${t("splitKey.result", { keyId: createdKeyId, count: shareUids.length })}\n` +
                    shareUids.map((uid, i) => `  ${t("splitKey.shareLine", { n: i + 1 })}: ${uid}`).join("\n")
                );
            }
            return t("splitKey.resultFallback", { keyId: createdKeyId, response: splitRespStr });
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("splitKey.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("splitKey.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <Trans ns="actions" i18nKey="splitKey.introCreated" components={{ strong: <strong /> }} />
                    </li>
                    <li>
                        <Trans ns="actions" i18nKey="splitKey.introAllShares" components={{ strong: <strong /> }} />
                    </li>
                    <li>{t("splitKey.introSetBelow")}</li>
                    <li>{t("splitKey.introSecurity")}</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ shareCount: 2 }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label={t("splitKey.keyIdLabel")} help={t("splitKey.keyIdHelp")}>
                            <Input placeholder={t("splitKey.keyIdPlaceholder")} data-testid="split-key-id-input" />
                        </Form.Item>

                        <Form.Item
                            name="shareCount"
                            label={t("splitKey.shareCountLabel")}
                            tooltip={t("splitKey.shareCountTooltip")}
                            rules={[{ required: true, message: t("splitKey.shareCountRequired") }]}
                        >
                            <InputNumber min={2} max={20} data-testid="split-key-share-count-input" style={{ width: 120 }} />
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
                            {t("splitKey.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("splitKey.responseTitle")} />
            </Form>
        </div>
    );
};

export default SplitKeyForm;
