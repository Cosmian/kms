import { Button, Card, DatePicker, Form, Input, Select, Space, Typography } from "antd";
import moment from "moment";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import HashMapDisplay from "./HashMapDisplay";
import { sendKmipRequest } from "./utils";
import { parse_set_attribute_ttlv_response, set_attribute_ttlv_request } from "./wasm/pkg/cosmian_kms_ui_utils";

const { Title } = Typography;
const { Option } = Select;

// Define the allowed attribute names from the Rust function
const ALLOWED_ATTRIBUTES = [
    { value: "activation_date", label: "Activation Date" },
    { value: "cryptographic_algorithm", label: "Cryptographic Algorithm" },
    { value: "cryptographic_length", label: "Cryptographic Length" },
    { value: "key_usage", label: "Key Usage" },
    { value: "public_key_id", label: "Public Key ID link" },
    { value: "private_key_id", label: "Private Key ID link" },
    { value: "certificate_id", label: "Certificate ID link" },
    { value: "pkcs12_certificate_id", label: "PKCS12 Certificate ID link" },
    { value: "pkcs12_password_certificate", label: "PKCS12 Password Certificate link" },
    { value: "parent_id", label: "Parent ID link" },
    { value: "child_id", label: "Child ID link" },
];

// Define cryptographic algorithms as shown in the Rust code
const CRYPTO_ALGORITHMS = [
    { value: "AES", label: "AES" },
    { value: "RSA", label: "RSA" },
    { value: "ECDSA", label: "ECDSA" },
    { value: "ECDH", label: "ECDH" },
    { value: "EC", label: "EC" },
    { value: "ChaCha20", label: "ChaCha20" },
    { value: "ChaCha20Poly1305", label: "ChaCha20-Poly1305" },
    { value: "SHA3224", label: "SHA3-224" },
    { value: "SHA3256", label: "SHA3-256" },
    { value: "SHA3384", label: "SHA3-384" },
    { value: "SHA3512", label: "SHA3-512" },
    { value: "Ed25519", label: "Ed25519" },
    { value: "Ed448", label: "Ed448" },
    { value: "CoverCrypt", label: "CoverCrypt" },
    { value: "CoverCryptBulk", label: "CoverCryptBulk" },
];

// Define key usage options
const KEY_USAGE_OPTIONS = [
    { value: "Sign", label: "Sign" },
    { value: "Verify", label: "Verify" },
    { value: "Encrypt", label: "Encrypt" },
    { value: "Decrypt", label: "Decrypt" },
    { value: "WrapKey", label: "Wrap Key" },
    { value: "UnwrapKey", label: "Unwrap Key" },
];

interface AttributeSetFormData {
    id?: string;
    tags?: string[];
    attribute_name: string;
    attribute_value: string;
}

const AttributeSetForm: React.FC = () => {
    const [form] = Form.useForm<AttributeSetFormData>();
    const [res, setRes] = useState<Map<any, any> | string>(new Map());
    const [isLoading, setIsLoading] = useState(false);
    const [selectedAttributeName, setSelectedAttributeName] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onAttributeNameChange = (value: string) => {
        setSelectedAttributeName(value);
        // Reset attribute value when name changes
        form.setFieldsValue({ attribute_value: undefined });
    };

    const onFinish = async (values: AttributeSetFormData) => {
        console.log("Set attribute values:", values);
        setIsLoading(true);

        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing object identifier.");
                throw Error("Missing object identifier");
            }

            if (!values.attribute_name || !values.attribute_value) {
                setRes("Missing attribute.");
                throw Error("Missing attribute");
            }

            // Process special attribute values
            let attributeValue = values.attribute_value;

            // For activation_date, convert from timestamp to Unix timestamp in seconds
            if (values.attribute_name === "activation_date" && attributeValue) {
                const date = moment(attributeValue);
                attributeValue = Math.floor(date.valueOf() / 1000).toString();
            }
            const request = set_attribute_ttlv_request(id, values.attribute_name, attributeValue);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);

            if (result_str) {
                const response = parse_set_attribute_ttlv_response(result_str);
                setRes(`Attribute has been set for ${response.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error setting attribute: ${e}`);
            console.error("Error setting attribute:", e);
        } finally {
            setIsLoading(false);
        }
    };

    // Render different input components based on the selected attribute name
    const renderAttributeValueInput = () => {
        if (!selectedAttributeName) {
            return <Input placeholder="First select an attribute name" disabled />;
        }

        switch (selectedAttributeName) {
            case "activation_date":
                return (
                    <Form.Item
                        name="attribute_value"
                        label="Activation Date"
                        rules={[{ required: true, message: "Please select activation date" }]}
                    >
                        <DatePicker showTime style={{ width: "100%" }} />
                    </Form.Item>
                );

            case "cryptographic_algorithm":
                return (
                    <Form.Item
                        name="attribute_value"
                        label="Cryptographic Algorithm"
                        rules={[{ required: true, message: "Please select an algorithm" }]}
                    >
                        <Select placeholder="Select algorithm">
                            {CRYPTO_ALGORITHMS.map((algo) => (
                                <Option key={algo.value} value={algo.value}>
                                    {algo.label}
                                </Option>
                            ))}
                        </Select>
                    </Form.Item>
                );

            case "cryptographic_length":
                return (
                    <Form.Item
                        name="attribute_value"
                        label="Cryptographic Length"
                        rules={[{ required: true, message: "Please enter length" }]}
                    >
                        <Input type="number" placeholder="Enter length in bits" />
                    </Form.Item>
                );

            case "key_usage":
                return (
                    <Form.Item name="attribute_value" label="Key Usage" rules={[{ required: true, message: "Please select key usage" }]}>
                        <Select placeholder="Select key usage">
                            {KEY_USAGE_OPTIONS.map((usage) => (
                                <Option key={usage.value} value={usage.value}>
                                    {usage.label}
                                </Option>
                            ))}
                        </Select>
                    </Form.Item>
                );

            // For all ID fields, render a simple input
            case "public_key_id":
            case "private_key_id":
            case "certificate_id":
            case "pkcs12_certificate_id":
            case "pkcs12_password_certificate":
            case "parent_id":
            case "child_id":
                return (
                    <Form.Item
                        name="attribute_value"
                        label={`${ALLOWED_ATTRIBUTES.find((attr) => attr.value === selectedAttributeName)?.label} Value`}
                        rules={[{ required: true, message: "Please enter ID value" }]}
                    >
                        <Input placeholder="Enter ID value" />
                    </Form.Item>
                );

            default:
                return (
                    <Form.Item
                        name="attribute_value"
                        label="Attribute Value"
                        rules={[{ required: true, message: "Please enter attribute value" }]}
                    >
                        <Input placeholder="Enter attribute value" />
                    </Form.Item>
                );
        }
    };

    return (
        <div className="p-6">
            <Title level={2}>Set KMIP Object Attribute</Title>
            <div className="mb-8 space-y-2">
                <div>Set a single attribute for a KMIP object by specifying the object ID or tags.</div>
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

                    <Card title="Attribute Setting">
                        <div className="mb-5">Select one attribute to set for the selected KMIP object.</div>

                        <Form.Item
                            name="attribute_name"
                            label="Attribute Name"
                            rules={[{ required: true, message: "Please select an attribute name" }]}
                            help="Select the KMIP attribute you want to set"
                        >
                            <Select placeholder="Select attribute name" onChange={onAttributeNameChange}>
                                {ALLOWED_ATTRIBUTES.map((attr) => (
                                    <Option key={attr.value} value={attr.value}>
                                        {attr.label}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>

                        {renderAttributeValueInput()}
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Set Attribute
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && typeof res !== "string" && res.size ? (
                <div ref={responseRef}>
                    <HashMapDisplay data={res} />
                </div>
            ) : (
                <div ref={responseRef}>{res}</div>
            )}
        </div>
    );
};

export default AttributeSetForm;
