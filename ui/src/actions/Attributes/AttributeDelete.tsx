import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React from "react";
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

    const onFinish = async (values: AttributeDeleteFormData) => {
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing object identifier.");
            }

            if (!values.attribute_name) {
                throw new Error("Missing attribute name.");
            }

            const request = delete_attribute_ttlv_request(id, values.attribute_name);
            const result_str = await sendKmipRequest(request, serverUrl);

            if (result_str) {
                const response = parse_delete_attribute_ttlv_response(result_str);
                return `Attribute '${values.attribute_name}' has been deleted for ${response.UniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <Title level={2}>Delete KMIP Object Attribute</Title>
            <div className="mb-8 space-y-2">
                <div>Delete a single attribute from a KMIP object by specifying the object ID or tags.</div>
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

                    <Card title="Attribute Deletion">
                        <div className="mb-5">Select the attribute to delete from the selected KMIP object.</div>

                        <Form.Item
                            name="attribute_name"
                            label="Attribute Name"
                            rules={[{ required: true, message: "Please select an attribute name to delete" }]}
                            help="Select the KMIP attribute you want to delete"
                        >
                            <Select data-testid="attribute-name-select" placeholder="Select attribute name">
                                {DELETE_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.deleteValue ?? attr.value} value={attr.deleteValue ?? attr.value}>
                                        {attr.label}
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
                            Delete Attribute
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
