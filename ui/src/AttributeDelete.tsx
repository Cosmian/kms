import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { delete_attribute_ttlv_request, parse_delete_attribute_ttlv_response } from "./wasm/pkg/cosmian_kms_client_wasm";

const { Title } = Typography;
const { Option } = Select;

const ALLOWED_ATTRIBUTES = [
    { value: "ActivationDate", label: "Activation Date" },
    { value: "CryptographicAlgorithm", label: "Cryptographic Algorithm" },
    { value: "CryptographicLength", label: "Cryptographic Length" },
    { value: "CryptographicUsageMask", label: "Key Usage" },
    { value: "public_key_id", label: "Public Key ID link" },
    { value: "private_key_id", label: "Private Key ID link" },
    { value: "certificate_id", label: "Certificate ID link" },
    { value: "pkcs12_certificate_id", label: "PKCS12 Certificate ID link" },
    { value: "pkcs12_password_certificate", label: "PKCS12 Password Certificate link" },
    { value: "parent_id", label: "Parent ID link" },
    { value: "child_id", label: "Child ID link" },
];

interface AttributeDeleteFormData {
    id?: string;
    tags?: string[];
    attribute_name: string;
}

const DeleteAttribute: React.FC = () => {
    const [form] = Form.useForm<AttributeDeleteFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl, idToken } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AttributeDeleteFormData) => {
        setIsLoading(true);
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing object identifier.");
                throw Error("Missing object identifier");
            }

            if (!values.attribute_name) {
                setRes("Missing attribute name.");
                throw Error("Missing attribute name");
            }

            const request = delete_attribute_ttlv_request(id, values.attribute_name);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);

            if (result_str) {
                const response = parse_delete_attribute_ttlv_response(result_str);
                setRes(`Attribute '${values.attribute_name}' has been deleted for ${response.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error deleting attribute: ${e}`);
            console.error("Error deleting attribute:", e);
        } finally {
            setIsLoading(false);
        }
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
                            <Select placeholder="Select attribute name">
                                {ALLOWED_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.value} value={attr.value}>
                                        {attr.label}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" danger htmlType="submit" loading={isLoading} className="w-full font-medium">
                            Delete Attribute
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <Card>
                    <div ref={responseRef}>{res}</div>
                </Card>
            )}
        </div>
    );
};

export default DeleteAttribute;
