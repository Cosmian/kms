import { Button, Card, Form, Input, Select, Space, Upload } from 'antd'
import React from 'react'

interface ECEncryptFormData {
    inputFile: File;
    keyId?: string;
    tags?: string[];
    authenticationData?: string;
    outputFile?: string;
}

const ECEncryptForm: React.FC = () => {
    const [form] = Form.useForm<ECEncryptFormData>();

    const onFinish = (values: ECEncryptFormData) => {
        console.log('Encrypt values:', values);
        // Handle form submission
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold  mb-6">EC Encryption</h1>

            <div className="mb-8 space-y-2">
                <p>Encrypt a file using ECIES (Elliptic Curve Integrated Encryption Scheme).</p>
                <p>The key can be identified using either its ID or associated tags.</p>
                <p className="text-sm text-yellow-600">Note: This operation loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Input File</h3>
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
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item
                            name="keyId"
                            label="Key ID"
                            help="The unique identifier of the public key"
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
                    </Card>
                    <Card>
                        <Form.Item
                            name="authenticationData"
                            label="Authentication Data"
                            help="Optional: this data needs to be provided back for decryption"
                        >
                            <Input.TextArea
                                placeholder="Enter authentication data"
                                rows={2}
                            />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            className="w-full text-white font-medium"
                        >
                            Encrypt File
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
        </div>
    );
};

export default ECEncryptForm;
