import React from 'react';
import { Form, Input, Select, Checkbox, Button } from 'antd';

interface ECKeyCreateFormData {
    privateKeyId?: string;
    curve: string;
    tags: string[];
    sensitive: boolean;
}

const ECKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<ECKeyCreateFormData>();

    const onFinish = (values: ECKeyCreateFormData) => {
        console.log('Create EC key pair values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Create an EC key pair</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Create a new Elliptic Curve key pair:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The public key is used to encrypt or verify a signature and can be safely shared.</li>
                    <li>The private key is used to decrypt or sign and must be kept secret.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    curve: 'nist-p256',
                    tags: [],
                    sensitive: false,
                }}
                className="space-y-6"
            >
                <Form.Item
                    name="curve"
                    label="Curve"
                    help="Select the elliptic curve to use"
                    rules={[{ required: true, message: 'Please select a curve' }]}
                >
                    <Select className="max-w-[500px]">
                        <Select.Option value="nist-p192">NIST P-192</Select.Option>
                        <Select.Option value="nist-p224">NIST P-224</Select.Option>
                        <Select.Option value="nist-p256">NIST P-256</Select.Option>
                        <Select.Option value="nist-p384">NIST P-384</Select.Option>
                        <Select.Option value="nist-p521">NIST P-521</Select.Option>
                        <Select.Option value="x25519">X25519</Select.Option>
                        <Select.Option value="ed25519">Ed25519</Select.Option>
                        <Select.Option value="x448">X448</Select.Option>
                        <Select.Option value="ed448">Ed448</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item
                    name="privateKeyId"
                    label="Private Key ID"
                    help="Optional: a random UUID will be generated if not specified"
                >
                    <Input
                        placeholder="Enter private key ID"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item
                    name="tags"
                    label="Tags"
                    help="Optional: Add tags to help retrieve the keys later"
                >
                    <Select
                        mode="tags"
                        placeholder="Enter tags"
                        className="max-w-[500px]"
                        open={false}
                    />
                </Form.Item>

                <Form.Item
                    name="sensitive"
                    valuePropName="checked"
                    help="If set, the private key will not be exportable"
                >
                    <Checkbox>
                        Sensitive
                    </Checkbox>
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Create an EC key pair
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default ECKeyCreateForm;
