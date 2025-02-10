import { Button, Form, Input, Select, Upload } from 'antd'
import React from 'react'

interface SymmetricDecryptFormData {
    inputFile: File;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: 'aes-gcm' | 'aes-xts' | 'aes-gcm-siv' | 'chacha20-poly1305';
    keyEncryptionAlgorithm?: 'nist-key-wrap' | 'aes-gcm' | 'rsa-pkcs-v15' | 'rsa-oaep' | 'rsa-aes-key-wrap';
    outputFile?: string;
    authenticationData?: string;
}

const DATA_ENCRYPTION_ALGORITHMS = [
    { label: 'AES-GCM (default)', value: 'aes-gcm' },
    { label: 'AES-XTS', value: 'aes-xts' },
    { label: 'AES-GCM-SIV', value: 'aes-gcm-siv' },
    { label: 'ChaCha20-Poly1305', value: 'chacha20-poly1305' },
];

const KEY_ENCRYPTION_ALGORITHMS = [
    { label: 'NIST Key Wrap (RFC 5649)', value: 'nist-key-wrap' },
    { label: 'AES GCM', value: 'aes-gcm' },
    { label: 'RSA PKCS v1.5', value: 'rsa-pkcs-v15' },
    { label: 'RSA OAEP', value: 'rsa-oaep' },
    { label: 'RSA AES Key Wrap', value: 'rsa-aes-key-wrap' },
];

const SymmetricDecryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricDecryptFormData>();

    const onFinish = (values: SymmetricDecryptFormData) => {
        console.log('Decrypt values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">Symmetric Decryption</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Decrypt a file using a symmetric key.</p>
                <p>Decryption can happen in two ways:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>Server side: the data is sent to the server and decrypted there.</li>
                    <li>Client side: The data encryption key (DEK) is decrypted server-side, then data is decrypted locally.</li>
                </ul>
                <p className="text-sm text-yellow-600">Note: Server-side decryption loads the entire file in memory.</p>
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
                        rules={[{ required: true, message: 'Please select a file to decrypt' }]}
                    >
                        <Upload.Dragger
                            beforeUpload={(file) => {
                                form.setFieldsValue({ inputFile: file });
                                return false;
                            }}
                            maxCount={1}
                        >
                            <p className="ant-upload-text">Click or drag file to this area to decrypt</p>
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
                    <Select options={DATA_ENCRYPTION_ALGORITHMS} />
                </Form.Item>

                <Form.Item
                    name="keyEncryptionAlgorithm"
                    label="Key Encryption Algorithm"
                    help="Optional. If not specified, decryption happens server-side"
                >
                    <Select
                        options={KEY_ENCRYPTION_ALGORITHMS}
                        allowClear
                        placeholder="Select for client-side decryption"
                    />
                </Form.Item>

                <Form.Item
                    name="authenticationData"
                    label="Authentication Data"
                    help="Optional hex-encoded authentication data used during encryption"
                >
                    <Input placeholder="Enter authentication data (hex)" />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-primary hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Decrypt File
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default SymmetricDecryptForm;
