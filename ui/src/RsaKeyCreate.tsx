import React from 'react';
import { Form, Input, InputNumber, Select, Checkbox, Button } from 'antd';

interface RsaKeyCreateFormData {
    privateKeyId?: string;
    sizeInBits: number;
    tags: string[];
    sensitive: boolean;
}

const RsaKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<RsaKeyCreateFormData>();

    const onFinish = (values: RsaKeyCreateFormData) => {
        console.log('Form values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-8">
            <h1 className="text-2xl font-bold text-gray-800 mb-6">Create RSA Key Pair</h1>
            <div className="mb-8 text-gray-600 space-y-1">
                <p>- The public key is used to encrypt and can be safely shared.</p>
                <p>- The private key is used to decrypt and must be kept secret.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                initialValues={{
                    sizeInBits: 4096,
                    tags: [],
                    sensitive: false,
                }}
                className="space-y-6"
            >
                <div className="space-y-2">
                    <Form.Item
                        name="privateKeyId"
                        label={<span className="text-gray-700 font-medium">Private Key ID</span>}
                        help={<span className="text-gray-500 text-sm">Optional. A random UUID will be generated if not specified</span>}
                    >
                        <Input
                            placeholder="Enter private key ID"
                            className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                        />
                    </Form.Item>

                    <Form.Item
                        name="sizeInBits"
                        label={<span className="text-gray-700 font-medium">Size in Bits</span>}
                        rules={[{ required: true }]}
                    >
                        <InputNumber
                            className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                            min={1024}
                            step={1024}
                        />
                    </Form.Item>

                    <Form.Item
                        name="tags"
                        label={<span className="text-gray-700 font-medium">Tags</span>}
                        help={<span className="text-gray-500 text-sm">Add multiple tags to help retrieve the keys later</span>}
                    >
                        <Select
                            mode="tags"
                            className="w-full rounded-md border-gray-300"
                            placeholder="Enter tags"
                            open={false}
                        />
                    </Form.Item>

                    <Form.Item
                        name="sensitive"
                        valuePropName="checked"
                    >
                        <Checkbox>
                            <span className="text-gray-700">Sensitive (private key will not be exportable)</span>
                        </Checkbox>
                    </Form.Item>
                </div>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Create RSA Key Pair
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default RsaKeyCreateForm;