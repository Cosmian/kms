import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { sendKmipRequest } from "./utils";
import { create_cc_master_keypair_ttlv_request, parse_create_keypair_ttlv_response } from "./wasm/pkg";

interface CovercryptMasterKeyFormData {
    specification: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

const SPECIFICATION_EXAMPLE = `{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}`;

const CovercryptMasterKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptMasterKeyFormData>();
    const [specificationType, setSpecificationType] = React.useState<"json-file" | "json-text">("json-file");
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: CovercryptMasterKeyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_cc_master_keypair_ttlv_request(
                values.specification,
                values.tags,
                values.sensitive,
                values.wrappingKeyId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result = await parse_create_keypair_ttlv_response(result_str);
                setRes(
                    `Key pair has been created. Private key Id: ${result.PrivateKeyUniqueIdentifier} - Public key Id: ${result.PublicKeyUniqueIdentifier}`
                );
            }
        } catch (e) {
            setRes(`${e}`);
            console.error(e);
        } finally {
            setIsLoading(false);
        }
    };

    const SpecificationExplanation = () => (
        <div className="mt-2 space-y-1">
            <p className="font-medium">This example creates a specification with:</p>
            <ul className="list-disc pl-5 space-y-1">
                <li>
                    Two specification axes: <code>Security Level</code> and <code>Department</code>
                </li>
                <li>
                    Hierarchical <code>Security Level</code> axis (indicated by <code>::&lt;</code> suffix)
                </li>
                <li>Three security levels: Protected, Confidential, and Top Secret</li>
                <li>Four departments: R&D, HR, MKG, and FIN</li>
                <li>
                    Post-quantum encryption for Top Secret level (indicated by <code>::+</code> suffix)
                </li>
                <li>Classic cryptography for other levels</li>
            </ul>
        </div>
    );

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold  mb-6">Create a Covercrypt master key pair</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new master key pair for a given specification.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The master public key is used to encrypt files and can be safely shared</li>
                    <li>The master secret key is used to generate user decryption keys and must be kept confidential</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sensitive: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <div className="p-4 rounded-lg space-y-4">
                            <h3 className="text-m font-bold mb-4">Specification Configuration (required)</h3>

                            <Form.Item name="specification" style={{ display: "none" }}>
                                <Input />
                            </Form.Item>

                            <Form.Item>
                                <Select
                                    value={specificationType}
                                    onChange={(value) => setSpecificationType(value)}
                                    options={[
                                        { label: "Upload JSON Specification File", value: "json-file" },
                                        { label: "Enter JSON Specification", value: "json-text" },
                                    ]}
                                />
                            </Form.Item>

                            {specificationType === "json-file" && (
                                <Form.Item name="specificationFile" rules={[{ required: true, message: "Please provide specifications" }]}>
                                    <FormUploadDragger
                                        accept=".json"
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const text = e.target?.result as string;
                                                if (text) {
                                                    form.setFieldsValue({ specification: text });
                                                }
                                            };
                                            reader.readAsText(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <p className="ant-upload-text">Click or drag JSON specification file</p>
                                    </FormUploadDragger>
                                </Form.Item>
                            )}

                            {specificationType === "json-text" && (
                                <Form.Item
                                    name="specificationText"
                                    rules={[
                                        { required: true, message: "Please enter specification JSON" },
                                        {
                                            validator: async (_, value) => {
                                                if (value) {
                                                    try {
                                                        JSON.parse(value); // Ensure it's valid JSON
                                                        form.setFieldValue("specification", value);
                                                    } catch (e) {
                                                        throw new Error(`Invalid JSON format: ${e}`);
                                                    }
                                                }
                                            },
                                        },
                                    ]}
                                >
                                    <Input.TextArea
                                        placeholder="Paste your JSON Specification here"
                                        rows={10}
                                        className="font-mono text-sm"
                                    />
                                </Form.Item>
                            )}
                        </div>

                        <div className="p-4 rounded mb-4">
                            <p className="text-sm mb-2">Example Specification Format:</p>
                            <pre className="p-2 rounded text-xs overflow-auto">{SPECIFICATION_EXAMPLE}</pre>
                            <SpecificationExplanation />
                        </div>

                        <Form.Item name="tags" label="Tags" help="Optional tags to help retrieve the keys later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="wrappingKeyId" label="Wrapping Key ID" help="Optional: ID of the key to wrap this new key with">
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If enabled, the private key will not be exportable">
                            <Checkbox>
                                <span>Sensitive Key</span>
                            </Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Create Master Key pair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Covercrypt Master keys creation response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CovercryptMasterKeyForm;
