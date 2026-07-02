import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import moment from "moment";
import React, { useEffect, useState } from "react";
import { sendKmipRequest } from "../../utils/utils";
import {
    get_crypto_algorithms,
    modify_attribute_ttlv_request,
    parse_modify_attribute_ttlv_response,
} from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ATTRIBUTE_REGISTRY, SET_MODIFY_ATTRIBUTES, type AlgoOption } from "./attributeRegistry";
import AttributeValueInput from "./AttributeValueInput";

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
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();
    const [selectedAttributeName, setSelectedAttributeName] = useState<string | undefined>(undefined);
    const [cryptoAlgorithms, setCryptoAlgorithms] = useState<AlgoOption[]>([]);

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
                throw new Error("Missing object identifier.");
            }

            if (
                !values.attribute_name ||
                !values.attribute_value ||
                (Array.isArray(values.attribute_value) && values.attribute_value.length === 0)
            ) {
                throw new Error("Missing attribute.");
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
            const result_str = await sendKmipRequest(request, idToken, serverUrl);

            if (result_str) {
                const response = parse_modify_attribute_ttlv_response(result_str);
                return `Attribute has been modified for ${response.UniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <Title level={2}>Modify KMIP Object Attribute</Title>
            <div className="mb-8 space-y-2">
                <div>Modify an existing attribute on a KMIP object by specifying the object ID or tags.</div>
                <div className="text-sm text-yellow-600">
                    When using tags to identify the object, rather than the object ID, an error is returned if multiple objects matching the
                    tags are found.
                </div>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{}}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the object.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the cryptographic object">
                            <Input placeholder="Enter object ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to use to retrieve the object when no object ID is specified">
                            <Select mode="tags" style={{ width: "100%" }} placeholder="Enter tags" tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title="Attribute Modification">
                        <div className="mb-5">Select one attribute to modify on the selected KMIP object.</div>

                        <Form.Item
                            name="attribute_name"
                            label="Attribute Name"
                            rules={[{ required: true, message: "Please select an attribute name" }]}
                            help="Select the KMIP attribute you want to modify"
                        >
                            <Select
                                data-testid="attribute-name-select"
                                placeholder="Select attribute name"
                                onChange={onAttributeNameChange}
                            >
                                {SET_MODIFY_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.value} value={attr.value}>
                                        {attr.label}
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
                            Modify Attribute
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
