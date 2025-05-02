import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import HashMapDisplay from "./HashMapDisplay";
import { sendKmipRequest } from "./utils";
import { get_attributes_ttlv_request, parse_get_attributes_ttlv_response } from "./wasm/pkg/cosmian_kms_client_wasm";

const { Title } = Typography;
const { Option } = Select;

const ATTRIBUTE_NAMES = [
    {
        value: "activation_date",
        label: "Activation Date",
    },
    {
        value: "cryptographic_algorithm",
        label: "Cryptographic Algorithm",
    },
    {
        value: "cryptographic_length",
        label: "Cryptographic Length",
    },
    {
        value: "key_usage",
        label: "Key Usage",
    },
    {
        value: "key_format_type",
        label: "Key Format Type",
    },
    {
        value: "object_type",
        label: "Object Type",
    },
    {
        value: "vendor_attributes",
        label: "Vendor Attributes",
    },
    {
        value: "public_key_id",
        label: "Public key ID",
    },
    {
        value: "private_key_id",
        label: "Private key ID",
    },
    {
        value: "certificate_id",
        label: "Certificate ID",
    },
    {
        value: "pkcs12_certificate_id",
        label: "Pkcs12 Certificate ID",
    },
    {
        value: "pkcs12_password_certificate",
        label: "Pkcs12 Password Certificate",
    },
    {
        value: "parent_id",
        label: "Parent ID",
    },
    {
        value: "child_id",
        label: "Child ID",
    },
];

interface AttributeGetFormData {
    id?: string;
    tags?: string[];
    selected_attributes: string[];
}

const AttributeGetForm: React.FC = () => {
    const [form] = Form.useForm<AttributeGetFormData>();
    const [res, setRes] = useState<Map<string, unknown> | string>(new Map());
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

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
                setRes("Missing object identifier.");
                throw Error("Missing object identifier");
            }
            const request = get_attributes_ttlv_request(id);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = parse_get_attributes_ttlv_response(result_str, values.selected_attributes);
                setRes(response.size ? response : "Empty result");
            }
        } catch (e) {
            setRes(`Error getting attributes: ${e}`);
            console.error("Error getting attributes:", e);
        } finally {
            setIsLoading(false);
        }
    };
    return (
        <div className="p-6">
            <Title level={2}>Get KMIP Object Attributes</Title>
            <div className="mb-8 space-y-2">
                <div>Retrieve attributes for a KMIP object by specifying either the object ID or tags.</div>
                <div className="text-sm text-yellow-600">
                    When using tags to retrieve the object, rather than the object id, an error is returned if multiple objects matching the
                    tags are found.
                </div>
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
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the object.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the cryptographic object">
                            <Input placeholder="Enter object ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to use to retrieve the key when no key ID is specified">
                            <Select mode="tags" style={{ width: "100%" }} placeholder="Enter tags" tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title="Attribute Selection">
                        <Form.Item
                            name="selected_attributes"
                            label="Attribute Names"
                            help="The attributes or KMIP-tags to retrieve (all attributes will be returned if none specified)"
                        >
                            <Select mode="multiple" style={{ width: "100%" }} placeholder="Select attribute">
                                {ATTRIBUTE_NAMES.map((attribute) => (
                                    <Option key={attribute.value} value={attribute.value}>
                                        {attribute.label}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Get Attributes
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && typeof res !== "string" && res.size ? (
                <div ref={responseRef}>
                    <HashMapDisplay data={res} />
                </div>
            ) : (
                <Card>
                    <div ref={responseRef}>{res instanceof Map ? JSON.stringify(Object.fromEntries(res)) : res}</div>
                </Card>
            )}
        </div>
    );
};

export default AttributeGetForm;
