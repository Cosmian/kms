import { UploadOutlined } from "@ant-design/icons"
import { Button, Card, Checkbox, Form, Input, Select, Space, Upload } from 'antd'
import React, { useEffect, useRef, useState } from 'react'
import { useAuth } from "./AuthContext"
import { sendKmipRequest } from './utils'
import { import_ttlv_request, parse_import_ttlv_response } from "./wasm/pkg"

type ImportKeyFormat =
    | 'json-ttlv' | 'pem' | 'sec1'
    | 'pkcs1-priv' | 'pkcs1-pub'
    | 'pkcs8' | 'spki'
    | 'aes' | 'chacha20';

type KeyUsage =
    | 'sign' | 'verify'
    | 'encrypt' | 'decrypt'
    | 'wrap' | 'unwrap';

interface ImportKeyFormData {
    keyFile: Uint8Array;
    keyId?: string;
    keyFormat: ImportKeyFormat;
    publicKeyId?: string;
    privateKeyId?: string;
    certificateId?: string;
    unwrap: boolean;
    replaceExisting: boolean;
    tags: string[];
    keyUsage?: KeyUsage[];
    authenticatedAdditionalData?: string;
}

type KeyType = 'rsa' | 'ec' | 'symmetric' | 'covercrypt';

interface KeyImportFormProps {
    key_type: KeyType;
}

type KeyImportResponse = {
    UniqueIdentifier: string
}

const KeyImportForm: React.FC<KeyImportFormProps> = (props: KeyImportFormProps) => {
    const [form] = Form.useForm<ImportKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl  } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [res]);

    const onFinish = async (values: ImportKeyFormData) => {
        console.log('Import key values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = import_ttlv_request(values.keyId, values.keyFile, values.keyFormat, values.publicKeyId, values.privateKeyId, values.certificateId, values.unwrap, values.replaceExisting, values.tags, values.keyUsage, values.authenticatedAdditionalData);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await parse_import_ttlv_response(result_str)
                setRes(`File has been imported - imported object id: ${result.UniqueIdentifier}`)
            }
        } catch (e) {
            setRes(`Error importing key: ${e}`)
            console.error("Error importing key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    let key_type_string = '';
    let key_formats = [];
    let key_usages = [];
    if (props.key_type === 'rsa') {
        key_type_string = 'an RSA';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'PEM (auto-detect format)', value: 'pem' },
            { label: 'PKCS#1 DER (RSA private)', value: 'pkcs1-priv' },
            { label: 'PKCS#1 DER (RSA public)', value: 'pkcs1-pub' },
            { label: 'PKCS#8 DER (RSA private)', value: 'pkcs8-priv' },
            { label: 'PKCS#8 DER (RSA public)', value: 'pkcs8-pub' },
            { label: 'SPKI DER (RSA public)', value: 'spki' },
        ];
        key_usages = [
            { label: 'Sign', value: 'sign' },
            { label: 'Verify', value: 'verify' },
            { label: 'Encrypt', value: 'encrypt' },
            { label: 'Decrypt', value: 'decrypt' },
            { label: 'Wrap', value: 'wrap' },
            { label: 'Unwrap', value: 'unwrap' },
        ];
    } else if (props.key_type === 'ec') {
        key_type_string = 'an EC';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'PEM (auto-detect format)', value: 'pem' },
            { label: 'SEC1 DER (EC private)', value: 'sec1' },
            { label: 'PKCS#8 DER (RSA public)', value: 'pkcs8-pub' },
            { label: 'PKCS#8 DER (RSA private)', value: 'pkcs8-priv' },
        ];
        key_usages = [
            { label: 'Sign', value: 'sign' },
            { label: 'Verify', value: 'verify' },
            { label: 'Encrypt', value: 'encrypt' },
            { label: 'Decrypt', value: 'decrypt' },
            { label: 'Wrap', value: 'wrap' },
            { label: 'Unwrap', value: 'unwrap' },
        ];
    } else if (props.key_type === 'symmetric') {
        key_type_string = 'a symmetric';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'PEM (auto-detect format)', value: 'pem' },
            { label: 'AES (symmetric)', value: 'aes' },
            { label: 'ChaCha20 (symmetric)', value: 'chacha20' },
        ];
        key_usages = [
            { label: 'Encrypt', value: 'encrypt' },
            { label: 'Decrypt', value: 'decrypt' },
            { label: 'Wrap', value: 'wrap' },
            { label: 'Unwrap', value: 'unwrap' },
        ];
    } else {
        key_type_string = 'a Covercrypt';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
        ];
        key_usages = [
            { label: 'Encrypt', value: 'encrypt' },
            { label: 'Decrypt', value: 'decrypt' },
        ];
    }

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Import {key_type_string} key</h1>

            <div className="mb-8 space-y-2">
                <p>Import {key_type_string} key in the KMS.</p>
                <p>When no unique ID is specified, a random UUID will be generated.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: 'json-ttlv',
                    unwrap: false,
                    replaceExisting: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <Form.Item
                            name="keyFile"
                            label="Key File"
                            rules={[{ required: true, message: "Please upload a key file" }]}
                            help="Upload the key file to import"
                        >
                            <Upload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ keyFile: bytes })
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>Upload Key File</Button>
                            </Upload>
                        </Form.Item>

                        <Form.Item
                            name="keyId"
                            label="Key ID"
                            help="Optional: A random UUID will be generated if not specified"
                        >
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item
                            name="keyFormat"
                            label="Key Format"
                            help="Format of the key file to import"
                            rules={[{ required: true }]}
                        >
                            <Select options={key_formats} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Relationships</h3>

                        <Form.Item
                            name="publicKeyId"
                            label="Public Key ID"
                            help="For private keys: link to corresponding public key in KMS"
                        >
                            <Input placeholder="Enter public key ID" />
                        </Form.Item>

                        <Form.Item
                            name="privateKeyId"
                            label="Private Key ID"
                            help="For public keys: link to corresponding private key in KMS"
                        >
                            <Input placeholder="Enter private key ID" />
                        </Form.Item>

                        <Form.Item
                            name="certificateId"
                            label="Certificate ID"
                            help="Link to corresponding certificate in KMS"
                        >
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="keyUsage"
                            label="Key Usage"
                            help="Specify allowed operations for this key"
                        >
                            <Select
                                mode="multiple"
                                options={key_usages}
                                placeholder="Select key usage"
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
                    </Card>
                    <Card>
                        <Form.Item
                            name="unwrap"
                            valuePropName="checked"
                            help="For JSON TTLV keys: unwrap the key if wrapped before storing"
                        >
                            <Checkbox>Unwrap key before import</Checkbox>
                        </Form.Item>

                        <Form.Item
                            name="replaceExisting"
                            valuePropName="checked"
                            help="Replace an existing key with the same ID"
                        >
                            <Checkbox>Replace existing key</Checkbox>
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="authenticatedAdditionalData"
                            label="Authenticated Additional Data"
                            help="Optional: For AES256GCM authenticated encryption unwrapping"
                        >
                            <Input placeholder="Enter authenticated data" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            >
                            Import Key
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Key import response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default KeyImportForm;
