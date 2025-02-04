import { LoadingOutlined, UploadOutlined } from "@ant-design/icons"
import { Button, Checkbox, Form, Input, Select, Spin, Upload } from 'antd'
import React, { useState } from 'react'
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
    keyFile: string;
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

const KeyImportForm: React.FC<KeyImportFormProps> = (props: KeyImportFormProps) => {
    const [form] = Form.useForm<ImportKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: ImportKeyFormData) => {
        console.log('Import key values:', values);
        setIsLoading(true);
        setRes(undefined);
        const request = import_ttlv_request(values.keyId, values.keyFile, values.keyFormat, values.publicKeyId, values.privateKeyId. values.certificateId, values.unwrap, values.replaceExisting, values.tags, values.keyUsage);
        try {
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result = await parse_import_ttlv_response(result_str)
                console.log(result)
                setRes("File has been imported")
            }
        } catch (e) {
            setRes(`${e}`)
            console.error(e);
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
            { label: 'PKCS#8 DER (RSA private)', value: 'pkcs8' },
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
            { label: 'PKCS#8 DER (EC private)', value: 'pkcs8' },
            { label: 'SPKI DER (EC public)', value: 'spki' },
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
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Import {key_type_string} key</h1>

            <div className="mb-8 text-gray-600 space-y-2">
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
                className="space-y-6"
            >
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
                                form.setFieldsValue({ keyFile: e.target?.result });
                            };
                            reader.readAsText(file);
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

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Relationships</h3>

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
                </div>

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

                <div className="space-y-4">
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
                </div>

                <Form.Item
                    name="authenticatedAdditionalData"
                    label="Authenticated Additional Data"
                    help="Optional: For AES256GCM authenticated encryption unwrapping"
                >
                    <Input placeholder="Enter authenticated data" />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        {isLoading ? (
                            <Spin
                                indicator={<LoadingOutlined style={{ fontSize: 24, color: 'white' }} spin />}
                            />
                        ) : (
                            'Import key'
                        )}
                    </Button>
                </Form.Item>
            </Form>
            {res && <div>{res}</div>}
        </div>
    );
};

export default KeyImportForm;
