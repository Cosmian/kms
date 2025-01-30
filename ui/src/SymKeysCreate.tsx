import React from 'react';
import { Form, Input, InputNumber, Select, Checkbox, Button } from 'antd';

interface SymKeyCreateFormData {
    keyId?: string;
    algorithm: 'aes' | 'chacha20' | 'sha3' | 'shake';
    numberOfBits?: number;
    bytesB64?: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

const SymKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<SymKeyCreateFormData>();

    const onFinish = (values: SymKeyCreateFormData) => {
        console.log('Create symmetric key values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Create a symmetric key</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Create a new symmetric key:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>When bytes are specified, the key will be created from the provided bytes.</li>
                    <li>Otherwise, the key will be randomly generated with the specified number of bits.</li>
                    <li>If no options are specified, a fresh 256-bit AES key will be created.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    algorithm: 'aes',
                    numberOfBits: 256,
                    tags: [],
                    sensitive: false,
                }}
                className="space-y-6"
            >
                <Form.Item
                    name="algorithm"
                    label="Algorithm"
                    rules={[{ required: true, message: 'Please select an algorithm' }]}
                >
                    <Select className="max-w-[500px]">
                        <Select.Option value="aes">AES</Select.Option>
                        <Select.Option value="chacha20">ChaCha20</Select.Option>
                        <Select.Option value="sha3">SHA3</Select.Option>
                        <Select.Option value="shake">SHAKE</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item
                    name="numberOfBits"
                    label="Number of Bits"
                    help="The length of the generated random key in bits"
                >
                    <InputNumber
                        className="w-[200px]"
                        min={128}
                        step={128}
                        max={512}
                    />
                </Form.Item>

                <Form.Item
                    name="bytesB64"
                    label="Key Bytes (Base64)"
                    help="Optional: specify the key bytes directly instead of generating random ones"
                >
                    <Input.TextArea
                        placeholder="Enter base64 encoded key bytes"
                        className="max-w-[500px]"
                        rows={4}
                    />
                </Form.Item>

                <Form.Item
                    name="keyId"
                    label="Key ID"
                    help="Optional: a random UUID will be generated if not specified"
                >
                    <Input
                        placeholder="Enter key ID"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item
                    name="tags"
                    label="Tags"
                    help="Optional: Add tags to help retrieve the key later"
                >
                    <Select
                        mode="tags"
                        placeholder="Enter tags"
                        className="max-w-[500px]"
                        open={false}
                    />
                </Form.Item>

                <Form.Item
                    name="wrappingKeyId"
                    label="Wrapping Key ID"
                    help="Optional: ID of the key to wrap this new key with"
                >
                    <Input
                        placeholder="Enter wrapping key ID"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item
                    name="sensitive"
                    valuePropName="checked"
                    help="If set, the key will not be exportable"
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
                        Create a symmetric key
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default SymKeyCreateForm;
