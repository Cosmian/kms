import { Button, Form, Input, Select, Upload } from 'antd'
import React from 'react'

interface RsaDecryptFormData {
    inputFile: File;
    keyId?: string;
    tags?: string[];
    encryptionAlgorithm: 'ckm-rsa-pkcs' | 'ckm-rsa-pkcs-oaep' | 'ckm-rsa-aes-key-wrap';
    hashingAlgorithm: 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512';
    outputFile?: string;
}

const ENCRYPTION_ALGORITHMS = [
    { label: 'RSA OAEP (Recommended)', value: 'ckm-rsa-pkcs-oaep' },
    { label: 'RSA PKCS #1 v1.5 (Legacy)', value: 'ckm-rsa-pkcs' },
    { label: 'RSA AES Key Wrap', value: 'ckm-rsa-aes-key-wrap' },
];

const HASH_ALGORITHMS = [
    { label: 'SHA-1', value: 'sha1' },
    { label: 'SHA-224', value: 'sha224' },
    { label: 'SHA-256', value: 'sha256' },
    { label: 'SHA-384', value: 'sha384' },
    { label: 'SHA-512', value: 'sha512' },
];

const RsaDecryptForm: React.FC = () => {
    const [form] = Form.useForm<RsaDecryptFormData>();

    const onFinish = (values: RsaDecryptFormData) => {
        console.log('Decrypt values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">RSA Decryption</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Decrypt a file using RSA private key.</p>
                <p>The key can be identified using either its ID or associated tags.</p>
                <p className="text-sm text-yellow-600">Note: This operation loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    encryptionAlgorithm: 'ckm-rsa-pkcs-oaep',
                    hashingAlgorithm: 'sha256',
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
                        help="The unique identifier of the private key"
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
                    name="encryptionAlgorithm"
                    label="Encryption Algorithm"
                    rules={[{ required: true }]}
                    help="Must match the algorithm used for encryption"
                >
                    <Select options={ENCRYPTION_ALGORITHMS} />
                </Form.Item>

                <Form.Item
                    name="hashingAlgorithm"
                    label="Hashing Algorithm"
                    rules={[{ required: true }]}
                    help="For OAEP and AES key wrap (must match encryption)"
                >
                    <Select options={HASH_ALGORITHMS} />
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

export default RsaDecryptForm;
