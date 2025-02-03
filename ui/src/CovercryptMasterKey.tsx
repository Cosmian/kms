import React from 'react';
import { Form, Select, Checkbox, Button, Upload } from 'antd';

interface CovercryptMasterKeyFormData {
    policySpecifications?: File;
    policyBinary?: File;
    tags?: string[];
    sensitive: boolean;
}

const CovercryptMasterKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptMasterKeyFormData>();
    const [policyType, setPolicyType] = React.useState<'json' | 'binary'>('json');

    const onFinish = (values: CovercryptMasterKeyFormData) => {
        console.log('Create master key pair values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Create Covercrypt master key pair</h1>

            <div className="mb-8 text-gray-600 space-y-2">
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
                }}
                className="space-y-6"
            >
                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Policy Configuration (required)</h3>

                    <Form.Item>
                        <Select
                            value={policyType}
                            onChange={(value) => setPolicyType(value)}
                            options={[
                                { label: 'JSON Policy Specifications', value: 'json' },
                                { label: 'Binary Policy File', value: 'binary' },
                            ]}
                        />
                    </Form.Item>

                    {policyType === 'json' ? (
                        <Form.Item
                            name="policySpecifications"
                            help={
                                <div className="text-gray-500 text-sm space-y-1">
                                    <p>JSON file containing policy specifications.</p>
                                    <p>Example format:</p>
                                    <pre className="bg-gray-100 p-2 rounded text-xs">
                                        {`{
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
}`}
                                    </pre>
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
                                </div>
                            }
                            rules={[{ required: true, message: 'Please provide policy specifications' }]}
                        >
                            <Upload.Dragger
                                accept=".json"
                                beforeUpload={(file) => {
                                    form.setFieldsValue({ policySpecifications: file });
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">Click or drag JSON policy file</p>
                            </Upload.Dragger>
                        </Form.Item>
                    ) : (
                        <Form.Item
                            name="policyBinary"
                            help="Binary policy file generated using the policy command"
                            rules={[{ required: true, message: 'Please provide binary policy file' }]}
                        >
                            <Upload.Dragger
                                beforeUpload={(file) => {
                                    form.setFieldsValue({ policyBinary: file });
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">Click or drag binary policy file</p>
                            </Upload.Dragger>
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
                        <span className="text-gray-700">Sensitive Key</span>
                    </Checkbox>
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Create Master Key Pair
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default CovercryptMasterKeyForm;
