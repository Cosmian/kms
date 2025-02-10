import { Button, Form, Input, Select, Upload } from 'antd'
import type { UploadFile } from 'antd/es/upload/interface'
import React, { useState } from 'react'

interface SymmetricEncryptFormData {
    inputFile: UploadFile[];
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: 'aes-gcm' | 'aes-gcm-siv' | 'chacha20-poly1305' | 'aes-xts';
    keyEncryptionAlgorithm?: 'rsa-oaep' | 'rsa-oaep-256' | 'rsa-oaep-384' | 'rsa-oaep-512';
    outputFile?: string;
    nonce?: string;
    authenticationData?: string;
}

const SymmetricEncryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricEncryptFormData>();
    const [isClientSide, setIsClientSide] = useState(false);

    const onFinish = (values: SymmetricEncryptFormData) => {
        console.log('Encrypt values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">Symmetric Encryption</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Encrypt a file using a symmetric key.</p>
                <p>Encryption can happen in two ways:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>Server side: the data is sent to the server and encrypted there.</li>
                    <li>Client side: The data encryption key (DEK) is encrypted server-side, then data is encrypted locally.</li>
                </ul>
                <p className="text-sm text-yellow-600">Note: Server-side encryption loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    dataEncryptionAlgorithm: 'aes-gcm',
                }}
                className="space-y-6"
            >
                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Input File</h3>
                    <Form.Item
                        name="inputFile"
                        rules={[{ required: true, message: 'Please select a file to encrypt' }]}
                    >
                        <Upload.Dragger
                            beforeUpload={(file) => {
                                form.setFieldsValue({ inputFile: file });
                                return false;
                            }}
                            maxCount={1}
                        >
                            <p className="ant-upload-text">Click or drag file to this area to encrypt</p>
                        </Upload.Dragger>
                    </Form.Item>
                </div>

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Identification (required)</h3>
                    <Form.Item
                        name="keyId"
                        label="Key ID"
                        help="The unique identifier of the symmetric key"
                    >
                        <Input placeholder="Enter key ID" />
                    </Form.Item>

                    <Form.Item
                        name="tags"
                        label="Tags"
                        help="Alternative to Key ID: specify tags to identify the key"
                    >
                        <Select
                            mode="tags"
                            placeholder="Enter tags"
                            open={false}
                        />
                    </Form.Item>
                </div>

                <Form.Item
                    name="dataEncryptionAlgorithm"
                    label="Data Encryption Algorithm"
                    rules={[{ required: true }]}
                    help="Algorithm used to encrypt the data"
                >
                    <Select>
                        <Select.Option value="aes-gcm">AES-GCM</Select.Option>
                        <Select.Option value="aes-gcm-siv">AES-GCM-SIV</Select.Option>
                        <Select.Option value="chacha20-poly1305">ChaCha20-Poly1305</Select.Option>
                        <Select.Option value="aes-xts">AES-XTS</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item
                    name="keyEncryptionAlgorithm"
                    label="Key Encryption Algorithm"
                    help="Optional. If specified, encryption will be performed client-side"
                >
                    <Select
                        onChange={(value) => setIsClientSide(!!value)}
                        allowClear
                        placeholder="Select for client-side encryption"
                    >
                        <Select.Option value="rsa-oaep">RSA-OAEP</Select.Option>
                        <Select.Option value="rsa-oaep-256">RSA-OAEP-256</Select.Option>
                        <Select.Option value="rsa-oaep-384">RSA-OAEP-384</Select.Option>
                        <Select.Option value="rsa-oaep-512">RSA-OAEP-512</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item
                    name="nonce"
                    label="Nonce/IV"
                    help="Optional: random value will be generated if not provided (hex string)"
                >
                    <Input placeholder="Enter nonce in hex format" />
                </Form.Item>

                <Form.Item
                    name="authenticationData"
                    label="Authentication Data"
                    help="Optional: additional authentication data (hex string)"
                >
                    <Input placeholder="Enter authentication data in hex format" />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-primary hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        {isClientSide ? 'Encrypt File (Client-side)' : 'Encrypt File (Server-side)'}
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default SymmetricEncryptForm;
