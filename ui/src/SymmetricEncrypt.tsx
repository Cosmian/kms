import React, { useState } from 'react';
import { Form, Input, Select, Button, Upload, Divider } from 'antd';
import { UploadOutlined } from '@ant-design/icons';
import type { UploadFile } from 'antd/es/upload/interface';

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
    const [fileList, setFileList] = useState<UploadFile[]>([]);
    const [isClientSide, setIsClientSide] = useState(false);

    const onFinish = (values: SymmetricEncryptFormData) => {
        console.log('Encrypt values:', values);
        // Handle form submission
    };

    const normFile = (e: any) => {
        if (Array.isArray(e)) {
            return e;
        }
        return e?.fileList;
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Encrypt a file with a symmetric key</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Encryption can happen in two ways:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>Server-side encryption: data is sent and encrypted on the server</li>
                    <li>Client-side encryption: data is encrypted locally with a random key (DEK), then the DEK is encrypted with the specified key encryption algorithm</li>
                    <li>For client-side encryption, specify a key encryption algorithm</li>
                </ul>
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
                <Form.Item
                    name="inputFile"
                    label="Input File"
                    valuePropName="fileList"
                    getValueFromEvent={normFile}
                    rules={[{ required: true, message: 'Please select a file to encrypt' }]}
                >
                    <Upload
                        beforeUpload={() => false}
                        maxCount={1}
                        fileList={fileList}
                        onChange={({ fileList }) => setFileList(fileList)}
                    >
                        <Button icon={<UploadOutlined />}>Select File</Button>
                    </Upload>
                </Form.Item>

                <Form.Item
                    name="keyId"
                    label="Key ID"
                    help="The symmetric key unique identifier (required if no tags specified)"
                >
                    <Input
                        placeholder="Enter key ID"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item
                    name="tags"
                    label="Tags"
                    help="Tags to retrieve the key when no key ID is specified"
                >
                    <Select
                        mode="tags"
                        placeholder="Enter tags"
                        className="max-w-[500px]"
                        open={false}
                    />
                </Form.Item>

                <Form.Item
                    name="dataEncryptionAlgorithm"
                    label="Data Encryption Algorithm"
                    help="The algorithm used to encrypt the data"
                    rules={[{ required: true }]}
                >
                    <Select className="max-w-[500px]">
                        <Select.Option value="aes-gcm">AES-GCM</Select.Option>
                        <Select.Option value="aes-gcm-siv">AES-GCM-SIV</Select.Option>
                        <Select.Option value="chacha20-poly1305">ChaCha20-Poly1305</Select.Option>
                        <Select.Option value="aes-xts">AES-XTS</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item
                    name="keyEncryptionAlgorithm"
                    label="Key Encryption Algorithm"
                    help="Optional: if specified, encryption will be performed client-side"
                >
                    <Select
                        className="max-w-[500px]"
                        onChange={(value) => setIsClientSide(!!value)}
                        allowClear
                    >
                        <Select.Option value="rsa-oaep">RSA-OAEP</Select.Option>
                        <Select.Option value="rsa-oaep-256">RSA-OAEP-256</Select.Option>
                        <Select.Option value="rsa-oaep-384">RSA-OAEP-384</Select.Option>
                        <Select.Option value="rsa-oaep-512">RSA-OAEP-512</Select.Option>
                    </Select>
                </Form.Item>

                <Divider className="my-6" />

                <div className="mb-4 text-gray-600">
                    <h3 className="text-lg font-medium mb-2">Advanced Options</h3>
                </div>

                <Form.Item
                    name="nonce"
                    label="Nonce/IV"
                    help="Optional: random value will be generated if not provided (hex string)"
                >
                    <Input
                        placeholder="Enter nonce in hex format"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item
                    name="authenticationData"
                    label="Authentication Data"
                    help="Optional: additional authentication data (hex string)"
                >
                    <Input
                        placeholder="Enter authentication data in hex format"
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        {isClientSide ? 'Encrypt File (Client-side)' : 'Encrypt File (Server-side)'}
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default SymmetricEncryptForm;
