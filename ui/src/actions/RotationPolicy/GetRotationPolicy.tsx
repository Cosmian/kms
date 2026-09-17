import { Button, Card, Descriptions, Form, Space } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import KeyIdInput from "../../components/common/KeyIdInput";

interface GetRotationPolicyFormData {
    keyId: string;
}

interface RotationPolicy {
    interval?: number;
    offset?: number;
    name?: string;
    generation?: number;
    date?: string;
}

const GetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<GetRotationPolicyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [policy, setPolicy] = useState<RotationPolicy | null>(null);

    const onFinish = async (values: GetRotationPolicyFormData) => {
        setPolicy(null);
        await execute(async () => {
            const request = wasm.get_attributes_ttlv_request(values.keyId);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: RotationPolicy = await wasm.parse_rotation_policy_response(result_str);
                setPolicy(result);
                if (!result.interval && !result.name && !result.generation) {
                    return t("getRotationPolicy.noPolicy");
                }
                return t("getRotationPolicy.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("getRotationPolicy.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("getRotationPolicy.intro")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            rules={[{ required: true, message: t("getRotationPolicy.pleaseEnterKeyId") }]}
                            placeholder={t("getRotationPolicy.keyIdPlaceholder")}
                            data-testid="get-rotation-key-id"
                        />
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("getRotationPolicy.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("getRotationPolicy.responseTitle")} />
            </Form>

            {policy && (policy.interval || policy.name || policy.generation) && (
                <Card className="mt-6" title={t("getRotationPolicy.detailsTitle")} data-testid="rotation-policy-details">
                    <Descriptions bordered column={1}>
                        <Descriptions.Item label={t("getRotationPolicy.interval")}>
                            {policy.interval ?? t("getRotationPolicy.notSet")}
                        </Descriptions.Item>
                        <Descriptions.Item label={t("getRotationPolicy.offset")}>
                            {policy.offset ?? t("getRotationPolicy.notSet")}
                        </Descriptions.Item>
                        <Descriptions.Item label={t("getRotationPolicy.keysetName")}>
                            {policy.name ?? t("getRotationPolicy.notSet")}
                        </Descriptions.Item>
                        <Descriptions.Item label={t("getRotationPolicy.generation")}>
                            {policy.generation ?? t("getRotationPolicy.notSet")}
                        </Descriptions.Item>
                        <Descriptions.Item label={t("getRotationPolicy.lastRotationDate")}>
                            {policy.date ?? t("getRotationPolicy.never")}
                        </Descriptions.Item>
                    </Descriptions>
                </Card>
            )}
        </div>
    );
};

export default GetRotationPolicyForm;
