import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import HashMapDisplay from "../../components/common/HashMapDisplay";
import { sendKmipRequest } from "../../utils/utils";
import { get_attributes_ttlv_request, parse_get_attributes_ttlv_response } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { ATTRIBUTE_REGISTRY } from "./attributeRegistry";

const { Title } = Typography;
const { Option } = Select;

interface AttributeGetFormData {
    id?: string;
    tags?: string[];
    selected_attributes: string[];
}

const AttributeGetForm: React.FC = () => {
    const [form] = Form.useForm<AttributeGetFormData>();
    const [res, setRes] = useState<Map<string, unknown> | string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const { t } = useTranslation("actions");
    const attrLabel = (value: string, fallback: string) => t(`attribute.${value}`, { defaultValue: fallback });

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AttributeGetFormData) => {
        setIsLoading(true);

        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes(t("attributeGet.missingObjectId"));
                throw Error("Missing object identifier");
            }
            const request = get_attributes_ttlv_request(id);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = parse_get_attributes_ttlv_response(result_str, values.selected_attributes);
                setRes(response.size ? response : t("attributeGet.emptyResult"));
            }
        } catch (e) {
            setRes(t("attributeGet.error", { error: String(e) }));
            console.error("Error getting attributes:", e);
        } finally {
            setIsLoading(false);
        }
    };
    return (
        <div className="p-6">
            <Title level={2}>{t("attributeGet.title")}</Title>
            <div className="mb-8 space-y-2">
                <div>{t("attributeGet.intro")}</div>
                <div className="text-sm text-yellow-600">{t("attributeGet.introWarning")}</div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    selected_attributes: [],
                }}
            >
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

                    <Card title={t("attributeGet.cardSelection")}>
                        <Form.Item
                            name="selected_attributes"
                            label={t("form.attributeNames")}
                            help={t("form.attributeNamesHelp")}
                        >
                            <Select mode="multiple" data-testid="attribute-name-select" style={{ width: "100%" }} placeholder={t("form.selectAttribute")}>
                                {ATTRIBUTE_REGISTRY.map((attribute) => (
                                    <Option key={attribute.value} value={attribute.value}>
                                        {attrLabel(attribute.value, attribute.label)}
                                    </Option>
                                ))}
                            </Select>
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
                            {t("form.getAttributes")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    {typeof res !== "string" && res.size ? (
                        <HashMapDisplay data={res} />
                    ) : (
                        <Card>
                            <div>{res instanceof Map ? JSON.stringify(Object.fromEntries(res)) : res}</div>
                        </Card>
                    )}
                </div>
            )}
        </div>
    );
};

export default AttributeGetForm;
