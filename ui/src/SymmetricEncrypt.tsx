import { Button, Card, Form, Input, Select, Space, Upload } from 'antd'
import React, { useState } from 'react'
import { downloadFile, sendKmipRequest } from './utils'
import { encrypt_sym_ttlv_request, parse_encrypt_ttlv_response } from "./wasm/pkg"

interface SymmetricEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: 'AesGcm' | 'AesGcmSiv' | 'Chacha20Poly1305' | 'AesXts';
    // keyEncryptionAlgorithm?: 'rsa-oaep' | 'rsa-oaep-256' | 'rsa-oaep-384' | 'rsa-oaep-512';
    outputFile?: string;
    nonce?: string;
    authenticationData?: string;
}

const SymmetricEncryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricEncryptFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    // const [isClientSide, setIsClientSide] = useState(false);

    const onFinish = async (values: SymmetricEncryptFormData) => {
        console.log('Encrypt values:', values);
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.")
                throw Error("Missing key identifier")
            }
            const request = encrypt_sym_ttlv_request(id , undefined, values.inputFile, undefined, values.nonce, values.authenticationData, values.dataEncryptionAlgorithm);
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const  { IvCounterNonce, Data, AuthenticatedEncryptionTag } = await parse_encrypt_ttlv_response(result_str)
                const combinedData = new Uint8Array(IvCounterNonce.length + Data.length + AuthenticatedEncryptionTag.length);
                combinedData.set(IvCounterNonce, 0);
                combinedData.set(Data, IvCounterNonce.length);
                combinedData.set(AuthenticatedEncryptionTag, IvCounterNonce.length + Data.length);
                const mimeType = "application/octet-stream";
                const name = values.fileName.substring(0, values.fileName.lastIndexOf(".")) || values.fileName;
                const filename = `${name}.enc`;
                downloadFile(combinedData, filename, mimeType);
                setRes("File has been encrypted")
            }
        } catch (e) {
            setRes(`Error encrypting: ${e}`)
            console.error("Error encrypting:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold  mb-6">Symmetric Encryption</h1>

            <div className="mb-8 space-y-2">
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
                    dataEncryptionAlgorithm: 'AesGcm',
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Input File</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item
                            name="inputFile"
                            rules={[{ required: true, message: 'Please select a file to encrypt' }]}
                        >
                            <Upload.Dragger
                                beforeUpload={(file) => {
                                    form.setFieldValue("fileName", file.name)
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ inputFile: bytes })
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
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
                    </Card>
                    <Card>
                        <Form.Item
                            name="dataEncryptionAlgorithm"
                            label="Data Encryption Algorithm"
                            rules={[{ required: true }]}
                            help="Algorithm used to encrypt the data"
                        >
                            <Select>
                                <Select.Option value="AesGcm">AES-GCM</Select.Option>
                                <Select.Option value="AesGcmSiv">AES-GCM-SIV</Select.Option>
                                <Select.Option value="Chacha20Poly1305">ChaCha20-Poly1305</Select.Option>
                                <Select.Option value="AesXts">AES-XTS</Select.Option>
                            </Select>
                        </Form.Item>

                        {/* <Form.Item
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
                        </Form.Item> */}

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
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            >
                            Encrypt File (Server-side)
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <div>{res}</div>}
        </div>
    );
};

export default SymmetricEncryptForm;
