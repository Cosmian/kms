import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface SetRotationPolicyFormData {
    keyId: string;
    interval?: number;
    offset?: number;
    name?: string;
}

const SetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<SetRotationPolicyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: SetRotationPolicyFormData) => {
        await execute(async () => {
            if (values.interval !== undefined && values.interval !== null) {
                const intervalRequest = wasm.set_rotate_interval_ttlv_request(values.keyId, BigInt(values.interval));
                const intervalResult = await sendKmipRequest(intervalRequest, serverUrl);
                if (!intervalResult) return;
                wasm.parse_set_attribute_ttlv_response(intervalResult);
            }

            if (values.offset !== undefined && values.offset !== null) {
                const offsetRequest = wasm.set_rotate_offset_ttlv_request(values.keyId, BigInt(values.offset));
                const offsetResult = await sendKmipRequest(offsetRequest, serverUrl);
                if (!offsetResult) return;
                wasm.parse_set_attribute_ttlv_response(offsetResult);
            }

            if (values.name) {
                const nameRequest = wasm.set_rotate_name_ttlv_request(values.keyId, values.name);
                const nameResult = await sendKmipRequest(nameRequest, serverUrl);
                if (!nameResult) return;
                wasm.parse_set_attribute_ttlv_response(nameResult);
            }

            return t("setRotationPolicy.success");
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("setRotationPolicy.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("setRotationPolicy.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("setRotationPolicy.introInterval")}</li>
                    <li>{t("setRotationPolicy.introOffset")}</li>
                    <li>{t("setRotationPolicy.introName")}</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyId"
                            label={t("common:keyId")}
                            rules={[{ required: true, message: t("setRotationPolicy.pleaseEnterKeyId") }]}
                        >
                            <Input placeholder={t("setRotationPolicy.keyIdPlaceholder")} data-testid="rotation-key-id" />
                        </Form.Item>

                        <Form.Item name="interval" label={t("setRotationPolicy.interval")} help={t("setRotationPolicy.intervalHelp")}>
                            <InputNumber
                                className="w-[200px]"
                                min={0}
                                placeholder={t("setRotationPolicy.intervalPlaceholder")}
                                data-testid="rotation-interval"
                            />
                        </Form.Item>

                        <Form.Item name="offset" label={t("setRotationPolicy.offset")} help={t("setRotationPolicy.offsetHelp")}>
                            <InputNumber
                                className="w-[200px]"
                                min={0}
                                placeholder={t("setRotationPolicy.offsetPlaceholder")}
                                data-testid="rotation-offset"
                            />
                        </Form.Item>

                        <Form.Item name="name" label={t("setRotationPolicy.keysetName")} help={t("setRotationPolicy.keysetNameHelp")}>
                            <Input placeholder={t("setRotationPolicy.keysetNamePlaceholder")} data-testid="rotation-name" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("setRotationPolicy.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("setRotationPolicy.responseTitle")} />
            </Form>
        </div>
    );
};

export default SetRotationPolicyForm;
