import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { delete_attribute_ttlv_request, parse_delete_attribute_ttlv_response } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { DELETE_ATTRIBUTES } from "./attributeRegistry";

const { Title } = Typography;
const { Option } = Select;

interface AttributeDeleteFormData {
    id?: string;
    tags?: string[];
    attribute_name: string;
}

const DeleteAttribute: React.FC = () => {
    const [form] = Form.useForm<AttributeDeleteFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const attrLabel = (value: string, fallback: string) => t(`attribute.${value}`, { defaultValue: fallback });

    const onFinish = async (values: AttributeDeleteFormData) => {
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("form.missingObjectId"));
            }

            if (!values.attribute_name) {
                throw new Error(t("attributeDelete.missingAttributeName"));
            }

            const request = delete_attribute_ttlv_request(id, values.attribute_name);
            const result_str = await sendKmipRequest(request, serverUrl);

            if (result_str) {
                const response = parse_delete_attribute_ttlv_response(result_str);
                return t("attributeDelete.success", { name: values.attribute_name, id: response.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <Title level={2}>{t("attributeDelete.title")}</Title>
            <div className="mb-8 space-y-2">
                <div>{t("attributeDelete.intro")}</div>
                <div className="text-sm text-yellow-600">{t("attributeSet.introWarning")}</div>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{}}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title={t("form.objectIdentification")}>
                        <div className="mb-5">{t("form.identifyHint")}</div>

                        <Form.Item name="id" label={t("common:objectId")} help={t("common:objectIdHelp")}>
                            <Input placeholder={t("common:enterObjectId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("common:tagsHelp")}>
                            <Select mode="tags" style={{ width: "100%" }} placeholder={t("common:enterTags")} tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title={t("attributeDelete.cardTitle")}>
                        <div className="mb-5">{t("attributeDelete.settingHint")}</div>

                        <Form.Item
                            name="attribute_name"
                            label={t("form.attributeName")}
                            rules={[{ required: true, message: t("attributeDelete.pleaseSelectAttributeToDelete") }]}
                            help={t("attributeDelete.attributeNameHelp")}
                        >
                            <Select data-testid="attribute-name-select" placeholder={t("form.selectAttributeName")}>
                                {DELETE_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.deleteValue ?? attr.value} value={attr.deleteValue ?? attr.value}>
                                        {attrLabel(attr.value, attr.label)}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            danger
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full font-medium"
                            data-testid="submit-btn"
                        >
                            {t("attributeDelete.submit")}
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

export default DeleteAttribute;
