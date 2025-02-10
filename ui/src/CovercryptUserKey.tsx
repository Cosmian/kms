import { Button, Checkbox, Form, Input, Select } from 'antd'
import React from 'react'

interface CovercryptUserKeyFormData {
    masterPrivateKeyId: string;
    accessPolicy: string;
    tags?: string[];
    sensitive: boolean;
}

const POLICY_EXAMPLE = `Department::HR && Security Level::Confidential

More examples:
(Department::MKG && Security Level::Confidential) || (Department::HR && Security Level::Protected)`;

const CovercryptUserKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptUserKeyFormData>();

    const onFinish = (values: CovercryptUserKeyFormData) => {
        console.log('Create user key values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">Create a Covercrypt user key</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Create a new user decryption key with specific access rights.</p>
                <p>The access policy is a boolean expression combining policy attributes.</p>
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
                    <h3 className="text-sm font-medium text-gray-700">Key Configuration</h3>

                    <Form.Item
                        name="masterPrivateKeyId"
                        label="Master Private Key ID"
                        help="The unique identifier of the master private key"
                        rules={[{ required: true, message: 'Please enter master private key ID' }]}
                    >
                        <Input placeholder="Enter master private key ID" />
                    </Form.Item>

                    <Form.Item
                        name="accessPolicy"
                        label="Access Policy"
                        help={
                            <div className="text-gray-500 text-sm space-y-2">
                                <p>Boolean expression combining policy attributes</p>
                                <div className="bg-gray-100 p-3 rounded">
                                    <p className="font-medium mb-2">Example formats:</p>
                                    <pre className="text-xs whitespace-pre-wrap">{POLICY_EXAMPLE}</pre>
                                    <p className="mt-2 text-xs">Note: A user with "Confidential" access will also have access to "Protected" data due to hierarchy.</p>
                                </div>
                                <ul className="list-disc pl-5 mt-2 space-y-1">
                                    <li>Use <code>&&</code> for AND, <code>||</code> for OR</li>
                                    <li>Group expressions with parentheses</li>
                                    <li>Use exact attribute names from the policy</li>
                                </ul>
                            </div>
                        }
                        rules={[{ required: true, message: 'Please enter access policy' }]}
                    >
                        <Input.TextArea
                            placeholder="Enter access policy expression"
                            rows={4}
                            className="font-mono text-sm"
                        />
                    </Form.Item>
                </div>

                <Form.Item
                    name="tags"
                    label="Tags"
                    help="Optional tags to help retrieve the key later"
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
                    help="If enabled, the key will not be exportable"
                >
                    <Checkbox>
                        <span className="text-gray-700">Sensitive Key</span>
                    </Checkbox>
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-primary hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Create User Key
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default CovercryptUserKeyForm;
