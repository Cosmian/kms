import { Button, Card, Form, Select, Space, Typography } from "antd";
import moment from "moment";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import {
    get_crypto_algorithms,
    modify_attribute_ttlv_request,
    parse_modify_attribute_ttlv_response,
} from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ATTRIBUTE_REGISTRY, SET_MODIFY_ATTRIBUTES, type AlgoOption } from "./attributeRegistry";
import AttributeValueInput from "./AttributeValueInput";
import KeyIdInput from "../../components/common/KeyIdInput";

const { Title } = Typography;
const { Option } = Select;

interface AttributeModifyFormData {
    id?: string;
    tags?: string[];
    attribute_name: string;
    attribute_value: string | string[];
}

const AttributeModifyForm: React.FC = () => {
    const [form] = Form.useForm<AttributeModifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [selectedAttributeName, setSelectedAttributeName] = useState<string | undefined>(undefined);
    const [cryptoAlgorithms, setCryptoAlgorithms] = useState<AlgoOption[]>([]);
    const { t } = useTranslation("actions");
    const attrLabel = (value: string, fallback: string) => t(`attribute.${value}`, { defaultValue: fallback });

    useEffect(() => {
        try {
            const opts = get_crypto_algorithms() as unknown as AlgoOption[];
            if (Array.isArray(opts)) setCryptoAlgorithms(opts);
        } catch {
            // ignore; WASM not ready or not built yet
        }
    }, []);

    const onAttributeNameChange = (value: string) => {
        setSelectedAttributeName(value);
        form.setFieldsValue({ attribute_value: undefined });
    };

    const onFinish = async (values: AttributeModifyFormData) => {
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("form.missingObjectId"));
            }

            if (
                !values.attribute_name ||
                !values.attribute_value ||
                (Array.isArray(values.attribute_value) && values.attribute_value.length === 0)
            ) {
                throw new Error(t("form.missingAttribute"));
            }

            // Normalise: multi-select (key_usage) returns string[]; join to CSV for Rust
            let attributeValue = Array.isArray(values.attribute_value) ? values.attribute_value.join(",") : values.attribute_value;

            // Date attributes: convert DatePicker value to Unix timestamp in seconds
            const entry = ATTRIBUTE_REGISTRY.find((a) => a.value === values.attribute_name);
            if (entry?.inputType === "date" && attributeValue) {
                const date = moment(attributeValue);
                attributeValue = Math.floor(date.valueOf() / 1000).toString();
            }
            const request = modify_attribute_ttlv_request(id, values.attribute_name, attributeValue);
            const result_str = await sendKmipRequest(request, serverUrl);

            if (result_str) {
                const response = parse_modify_attribute_ttlv_response(result_str);
                return t("attributeModify.success", { id: response.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <Title level={2}>{t("attributeModify.title")}</Title>
            <div className="mb-8 space-y-2">
                <div>{t("attributeModify.intro")}</div>
                <div className="text-sm text-yellow-600">{t("attributeSet.introWarning")}</div>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{}}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title={t("form.objectIdentification")}>
                        <div className="mb-5">{t("form.identifyHint")}</div>

                        <KeyIdInput
                            form={form}
                            fieldName="id"
                            label={t("common:objectId")}
                            help={t("common:objectIdHelp")}
                            placeholder={t("common:enterObjectId")}
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("common:tagsHelp")}>
                            <Select mode="tags" style={{ width: "100%" }} placeholder={t("common:enterTags")} tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title={t("attributeModify.cardTitle")}>
                        <div className="mb-5">{t("attributeModify.settingHint")}</div>

                        <Form.Item
                            name="attribute_name"
                            label={t("form.attributeName")}
                            rules={[{ required: true, message: t("attributeSet.pleaseSelectAttributeName") }]}
                            help={t("attributeModify.attributeNameHelp")}
                        >
                            <Select
                                data-testid="attribute-name-select"
                                placeholder={t("form.selectAttributeName")}
                                onChange={onAttributeNameChange}
                            >
                                {SET_MODIFY_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.value} value={attr.value}>
                                        {attrLabel(attr.value, attr.label)}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>

                        <AttributeValueInput selectedAttributeName={selectedAttributeName} cryptoAlgorithms={cryptoAlgorithms} />
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("attributeModify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <Card>
                    <div ref={responseRef} data-testid="response-output">
                        {res}
                    </div>
                </Card>
            )}
        </div>
    );
};

export default AttributeModifyForm;
