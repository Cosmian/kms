import { Button, Card, Checkbox, Form, Input, InputNumber, Select, Space } from 'antd'
import React, { useState } from 'react'
import { sendKmipRequest } from './utils'
import { create_sym_key_ttlv_request, parse_create_ttlv_response } from "./wasm/pkg"


interface SymKeyCreateFormData {
    keyId?: string;
    algorithm: 'Aes' | 'ChaCha20' | 'Sha3' | 'Shake';
    numberOfBits?: number;
    bytesB64?: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type CreateResponse = {
    ObjectType: string,
    UniqueIdentifier: string,
}

const SymKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<SymKeyCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: SymKeyCreateFormData) => {
        console.log('Create symmetric key values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_sym_key_ttlv_request(values.keyId, values.tags, values.numberOfBits, values.algorithm, values.sensitive, values.wrappingKeyId);
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result: CreateResponse = await parse_create_ttlv_response(result_str)
                setRes(`${result.UniqueIdentifier} has been created.`)
            }
        } catch (e) {
            setRes(`Error creating key: ${e}`)
            console.error("Error creating key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a symmetric key</h1>

            <div className="mb-8 space-y-2">
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
                    algorithm: 'Aes',
                    numberOfBits: 256,
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <Form.Item
                            name="algorithm"
                            label="Algorithm"
                            rules={[{ required: true, message: 'Please select an algorithm' }]}
                        >
                            <Select>
                                <Select.Option value="Aes">Aes</Select.Option>
                                <Select.Option value="ChaCha20">ChaCha20</Select.Option>
                                <Select.Option value="Sha3">SHA3</Select.Option>
                                <Select.Option value="Shake">SHAKE</Select.Option>
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
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            >
                            Create Symmetric Key
                        </Button>
                    </Form.Item>
                </Space>
                {res && <div>{res}</div>}
            </Form>
        </div>
    );
};

export default SymKeyCreateForm;
