import { Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useCallback, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import LocateButton from "../../components/common/LocateButton";

interface JoinSplitKeyFormData {
    shareCount: number;
    shareIds: { value: string }[];
    objectType: string;
}

const buildJoinSplitKeyRequest = (shareIds: string[], objectType: string) => ({
    tag: "JoinSplitKey",
    type: "Structure",
    value: [
        { tag: "ObjectType", type: "Enumeration", value: objectType },
        ...shareIds.map((id) => ({
            tag: "PrivateKeyUniqueIdentifier",
            type: "TextString",
            value: id,
        })),
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

type JoinSplitKeyResponse = {
    UniqueIdentifier: string;
};

const DEFAULT_SHARE_COUNT = 3;

const JoinSplitKeyForm: React.FC = () => {
    const { t } = useTranslation("actions");
    const [form] = Form.useForm<JoinSplitKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [shareCount, setShareCount] = useState<number>(DEFAULT_SHARE_COUNT);

    const onLocateSelect = useCallback(
        (index: number, uid: string) => {
            const currentShares: { value: string }[] = form.getFieldValue("shareIds") || [];
            const updated = [...currentShares];
            if (index < updated.length) {
                updated[index] = { value: uid };
            }
            form.setFieldsValue({ shareIds: updated });
        },
        [form],
    );

    const onShareCountChange = useCallback(
        (value: number | null) => {
            const count = value ?? 2;
            setShareCount(count);
            form.setFieldsValue({
                shareIds: Array.from({ length: count }, () => ({ value: "" })),
            });
        },
        [form],
    );

    const onFinish = async (values: JoinSplitKeyFormData) => {
        await execute(async () => {
            const shareIds = values.shareIds.map((item) => item.value).filter((v) => v && v.trim().length > 0);
            if (shareIds.length < 2) {
                throw new Error(t("joinSplitKey.atLeastTwoShares"));
            }
            const objectType = values.objectType ?? "SymmetricKey";
            const request = buildJoinSplitKeyRequest(shareIds, objectType);
            const resultStr = await sendKmipRequest(request, serverUrl);
            if (resultStr) {
                const parsed: JoinSplitKeyResponse = await wasm.parse_join_split_key_ttlv_response(resultStr);
                if (parsed.UniqueIdentifier) {
                    return t("joinSplitKey.result", { count: shareIds.length, uid: parsed.UniqueIdentifier });
                }
                return t("joinSplitKey.resultFallback", { response: resultStr });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("joinSplitKey.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("joinSplitKey.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <Trans ns="actions" i18nKey="joinSplitKey.introAllShares" components={{ strong: <strong /> }} />
                    </li>
                    <li>{t("joinSplitKey.introShareCount")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    method: "XOR",
                    objectType: "SymmetricKey",
                    shareIds: [{ value: "" }, { value: "" }],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item label={t("joinSplitKey.shareCountLabel")} name="shareCount">
                            <InputNumber
                                min={2}
                                max={20}
                                value={shareCount}
                                onChange={onShareCountChange}
                                data-testid="share-count-input"
                            />
                        </Form.Item>

                        <Form.List name="shareIds">
                            {(fields) => (
                                <>
                                    <label className="block font-medium mb-2">{t("joinSplitKey.shareIdsLabel")}</label>
                                    {fields.map((field, index) => (
                                        <Form.Item key={field.key} required>
                                            <Space align="baseline" className="w-full">
                                                <Form.Item
                                                    {...field}
                                                    name={[field.name, "value"]}
                                                    rules={[{ required: true, message: t("joinSplitKey.shareUidRequired") }]}
                                                    noStyle
                                                >
                                                    <Input
                                                        placeholder={t("joinSplitKey.sharePlaceholder", { n: index + 1 })}
                                                        style={{ width: 400 }}
                                                        data-testid={`join-share-id-${index}`}
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

                        <Form.Item
                            name="objectType"
                            label={t("joinSplitKey.objectTypeLabel")}
                            rules={[{ required: true, message: t("joinSplitKey.objectTypeRequired") }]}
                        >
                            <Select
                                data-testid="join-object-type-select"
                                options={[
                                    { label: t("joinSplitKey.objectTypeSymmetricKey"), value: "SymmetricKey" },
                                    { label: t("joinSplitKey.objectTypeSecretData"), value: "SecretData" },
                                ]}
                            />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="join-split-key-submit-btn"
                        >
                            {t("joinSplitKey.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("joinSplitKey.responseTitle")} />
            </Form>
        </div>
    );
};

export default JoinSplitKeyForm;
