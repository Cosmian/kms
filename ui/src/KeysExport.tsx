import React from 'react';
import { Form, Input, Select, Checkbox, Button } from 'antd';

interface KeyExportFormData {
    keyId?: string;
    tags?: string[];
    keyFormat: ExportKeyFormat;
    unwrap: boolean;
    wrapKeyId?: string;
    allowRevoked: boolean;
    wrappingAlgorithm?: WrappingAlgorithm;
    authenticatedAdditionalData?: string;
}

type ExportKeyFormat =
    | 'json-ttlv' | 'sec1-pem' | 'sec1-der'
    | 'pkcs1-pem' | 'pkcs1-der'
    | 'pkcs8-pem' | 'pkcs8-der'
    | 'spki-pem' | 'spki-der'
    | 'base64' | 'raw';

type WrappingAlgorithm =
    | 'nist-key-wrap' | 'aes-gcm'
    | 'rsa-pkcs-v15' | 'rsa-oaep'
    | 'rsa-aes-key-wrap';

const WRAPPING_ALGORITHMS: { label: string; value: WrappingAlgorithm }[] = [
    { label: 'NIST Key Wrap (RFC 5649)', value: 'nist-key-wrap' },
    { label: 'AES GCM', value: 'aes-gcm' },
    { label: 'RSA PKCS v1.5', value: 'rsa-pkcs-v15' },
    { label: 'RSA OAEP', value: 'rsa-oaep' },
    { label: 'RSA AES Key Wrap', value: 'rsa-aes-key-wrap' },
];

type KeyType = 'rsa' | 'ec' | 'symmetric' | 'covercrypt';

interface KeyExportFormProps {
    key_type: KeyType;
}

const KeyExportForm: React.FC<KeyExportFormProps> = (props: KeyExportFormProps) => {
    const [form] = Form.useForm<KeyExportFormData>();

    const onFinish = (values: KeyExportFormData) => {
        console.log('Export key values:', values);
        // Handle form submission
    };

    let key_type_string = '';
    let key_formats = [];
    if (props.key_type === 'rsa') {
        key_type_string = 'an RSA';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'PKCS1 PEM', value: 'pkcs1-pem' },
            { label: 'PKCS1 DER', value: 'pkcs1-der' },
            { label: 'PKCS8 PEM', value: 'pkcs8-pem' },
            { label: 'PKCS8 DER', value: 'pkcs8-der' },
            { label: 'SPKI PEM', value: 'spki-pem' },
            { label: 'SPKI DER', value: 'spki-der' },
            { label: 'Base64', value: 'base64' },
            { label: 'Raw', value: 'raw' },
        ];
    } else if (props.key_type === 'ec') {
        key_type_string = 'an EC';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'SEC1 PEM', value: 'sec1-pem' },
            { label: 'SEC1 DER', value: 'sec1-der' },
            { label: 'PKCS8 PEM', value: 'pkcs8-pem' },
            { label: 'PKCS8 DER', value: 'pkcs8-der' },
            { label: 'SPKI PEM', value: 'spki-pem' },
            { label: 'SPKI DER', value: 'spki-der' },
            { label: 'Base64', value: 'base64' },
            { label: 'Raw', value: 'raw' },
        ]
    } else if (props.key_type === 'symmetric') {
        key_type_string = 'a symmetric';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'Base64', value: 'base64' },
            { label: 'Raw', value: 'raw' },
        ]
    } else {
        key_type_string = 'a Covercrypt';
        key_formats = [
            { label: 'JSON TTLV (default)', value: 'json-ttlv' },
            { label: 'Raw', value: 'raw' },
        ]
    }

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Export {key_type_string} key</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Export {key_type_string} key from the KMS. The key can be identified using either its ID or associated tags.</p>
                <p>The key can optionally be unwrapped and/or wrapped when exported.</p>
                <p className="text-sm text-yellow-600">Note: Wrapping a key that is already wrapped is an error.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: 'json-ttlv',
                    unwrap: false,
                    allowRevoked: false,
                }}
                className="space-y-6"
            >

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Identification (required)</h3>
                    <Form.Item
                        name="keyId"
                        label="Key ID"
                        help="The unique identifier of the key stored in the KMS"
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
                    name="keyFormat"
                    label="Key Format"
                    help="Format for the exported key. JSON TTLV is recommended for later re-import."
                    rules={[{ required: true }]}
                >
                    <Select options={key_formats} />
                </Form.Item>

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Wrapping Options</h3>

                    <Form.Item
                        name="unwrap"
                        valuePropName="checked"
                    >
                        <Checkbox>Unwrap the key before export</Checkbox>
                    </Form.Item>

                    <Form.Item
                        name="wrapKeyId"
                        label="Wrap Key ID"
                        help="ID of the key/certificate to use for wrapping"
                    >
                        <Input placeholder="Enter wrap key ID" />
                    </Form.Item>

                    <Form.Item
                        name="wrappingAlgorithm"
                        label="Wrapping Algorithm"
                        help="Algorithm to use when wrapping the key"
                    >
                        <Select
                            options={WRAPPING_ALGORITHMS}
                            placeholder="Select wrapping algorithm"
                        />
                    </Form.Item>

                    <Form.Item
                        name="authenticatedAdditionalData"
                        label="Authenticated Additional Data"
                        help="Only available for AES GCM wrapping"
                    >
                        <Input placeholder="Enter authenticated data" />
                    </Form.Item>
                </div>

                <Form.Item
                    name="allowRevoked"
                    valuePropName="checked"
                    help="Allow exporting revoked and destroyed keys (user must be the owner)"
                >
                    <Checkbox>Allow revoked keys</Checkbox>
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Export Key
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default KeyExportForm;
