import { Button, Card, Checkbox, Form, Input, Select, Space, Upload } from 'antd'
import React, { useState } from 'react'
import { sendKmipRequest } from './utils'
import { create_covercrypt_master_keypair_ttlv_request, parse_create_keypair_ttlv_response } from "./wasm/pkg"



interface CovercryptMasterKeyFormData {
    policy: Uint8Array;
    tags: string[];
    sensitive: boolean;
}

const POLICY_EXAMPLE = `{
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
    const [policyType, setPolicyType] = React.useState<'json-file' | 'json-text'>('json-file');
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: CovercryptMasterKeyFormData) => {
        console.log('Create master key pair values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_covercrypt_master_keypair_ttlv_request(values.policy, values.tags, values.sensitive);
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result = await parse_create_keypair_ttlv_response(result_str)
                setRes(`Key pair has been created. Private key Id: ${result.PrivateKeyUniqueIdentifier} - Public key Id: ${result.PublicKeyUniqueIdentifier}`)
            }
        } catch (e) {
            setRes(`${e}`)
            console.error(e);
        } finally {
            setIsLoading(false);
        }
    };

    const PolicyExplanation = () => (
        <div className="mt-2 space-y-1">
            <p className="font-medium">This example creates a policy with:</p>
            <ul className="list-disc pl-5 space-y-1">
                <li>Two policy axes: <code>Security Level</code> and <code>Department</code></li>
                <li>Hierarchical <code>Security Level</code> axis (indicated by <code>::&lt;</code> suffix)</li>
                <li>Three security levels: Protected, Confidential, and Top Secret</li>
                <li>Four departments: R&D, HR, MKG, and FIN</li>
                <li>Post-quantum encryption for Top Secret level (indicated by <code>::+</code> suffix)</li>
                <li>Classic cryptography for other levels</li>
            </ul>
        </div>
    );

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold  mb-6">Create a Covercrypt master key pair</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new master key pair for a given policy.</p>
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
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <div className="p-4 rounded-lg space-y-4">
                            <h3 className="text-m font-bold mb-4">Policy Configuration (required)</h3>

                            <Form.Item name="policy" style={{ display: "none" }}>
                                <Input />
                            </Form.Item>

                            <Form.Item>
                                <Select
                                    value={policyType}
                                    onChange={(value) => setPolicyType(value)}
                                    options={[
                                        { label: 'Upload JSON Policy File', value: 'json-file' },
                                        { label: 'Enter JSON Policy', value: 'json-text' },
                                    ]}
                                />
                            </Form.Item>

                            <div className="p-4 rounded mb-4">
                                <p className="text-sm mb-2">Example Policy Format:</p>
                                <pre className="p-2 rounded text-xs overflow-auto">{POLICY_EXAMPLE}</pre>
                                <PolicyExplanation />
                            </div>

                            {policyType === 'json-file' && (
                                <Form.Item
                                    name="policySpecifications"
                                    rules={[{ required: true, message: 'Please provide policy specifications' }]}
                                >
                                    <Upload.Dragger
                                        accept=".json"
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const arrayBuffer = e.target?.result;
                                                if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                                    const bytes = new Uint8Array(arrayBuffer);
                                                    form.setFieldsValue({ policy: bytes })
                                                }
                                            };
                                            reader.readAsArrayBuffer(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <p className="ant-upload-text">Click or drag JSON policy file</p>
                                    </Upload.Dragger>
                                </Form.Item>
                            )}

                            {policyType === 'json-text' && (
                                <Form.Item
                                    name="policyJson"
                                    rules={[
                                        { required: true, message: 'Please enter policy JSON' },
                                        {
                                            validator: async (_, value) => {
                                                if (value) {
                                                    try {
                                                        const jsonObject = JSON.parse(value);
                                                        const encoder = new TextEncoder();
                                                        const uint8Array = encoder.encode(JSON.stringify(jsonObject));
                                                        form.setFieldValue("policy", uint8Array)
                                                    } catch (e) {
                                                        throw new Error(`Invalid JSON format: ${e}`);
                                                    }
                                                }
                                            },
                                        },
                                    ]}
                                >
                                    <Input.TextArea
                                        placeholder="Paste your JSON policy here"
                                        rows={10}
                                        className="font-mono text-sm"
                                    />
                                </Form.Item>
                            )}
                        </div>

                        <Form.Item
                            name="tags"
                            label="Tags"
                            help="Optional tags to help retrieve the keys later"
                        >
                            <Select
                                mode="tags"
                                placeholder="Enter tags"
                                open={false}
                            />
                        </Form.Item>

                        <Form.Item
                            name="sensitive"
                            valuePropName="checked"
                            help="If enabled, the private key will not be exportable"
                        >
                            <Checkbox>
                                <span>Sensitive Key</span>
                            </Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Create Master Key pair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <Card title="Covercrypt Master keys creation response">{res}</Card>}
        </div>
    );
};

export default CovercryptMasterKeyForm;
