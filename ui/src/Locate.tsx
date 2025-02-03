import React from 'react';
import { Form, Input, Select, Button } from 'antd';

interface LocateFormData {
    tags?: string[];
    cryptographicAlgorithm?: string;
    cryptographicLength?: number;
    keyFormatType?: string;
    objectType?: string;
    publicKeyId?: string;
    privateKeyId?: string;
    certificateId?: string;
}

const CRYPTO_ALGORITHMS = [
    { label: 'Covercrypt', value: 'Covercrypt' },
    { label: 'ECDH', value: 'ECDH' },
    { label: 'ChaCha20-Poly1305', value: 'ChaCha20Poly1305' },
    { label: 'AES', value: 'AES' },
    { label: 'Ed25519', value: 'Ed25519' },
];

const KEY_FORMAT_TYPES = [
    { label: 'CoverCrypt Secret Key', value: 'CoverCryptSecretKey' },
    { label: 'CoverCrypt Public Key', value: 'CoverCryptPublicKey' },
    { label: 'Raw', value: 'RAW' },
    { label: 'PKCS8', value: 'PKCS8' },
];

const OBJECT_TYPES = [
    { label: 'Certificate', value: 'Certificate' },
    { label: 'Symmetric Key', value: 'SymmetricKey' },
    { label: 'Public Key', value: 'PublicKey' },
    { label: 'Private Key', value: 'PrivateKey' },
    { label: 'Split Key', value: 'SplitKey' },
    { label: 'Secret Data', value: 'SecretData' },
    { label: 'Opaque Object', value: 'OpaqueObject' },
    { label: 'PGP Key', value: 'PGPKey' },
    { label: 'Certificate Request', value: 'CertificateRequest' },
];

const LocateForm: React.FC = () => {
    const [form] = Form.useForm<LocateFormData>();

    const onFinish = (values: LocateFormData) => {
        console.log('Locate values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Locate Cryptographic Objects</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Search for cryptographic objects in the KMS using various criteria.</p>
                <p>Results will show one ID per line.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Basic Search Criteria</h3>

                    <Form.Item
                        name="tags"
                        label="Tags"
                        help="User tags or system tags to locate the object"
                    >
                        <Select
                            mode="tags"
                            placeholder="Enter tags"
                            open={false}
                        />
                    </Form.Item>

                    <Form.Item
                        name="cryptographicAlgorithm"
                        label="Cryptographic Algorithm"
                        help="Algorithm used by the cryptographic object"
                    >
                        <Select
                            options={CRYPTO_ALGORITHMS}
                            allowClear
                            placeholder="Select algorithm"
                        />
                    </Form.Item>

                    <Form.Item
                        name="cryptographicLength"
                        label="Cryptographic Length"
                        help="Key size in bits"
                    >
                        <Input type="number" placeholder="Enter length in bits" />
                    </Form.Item>
                </div>

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Object Type and Format</h3>

                    <Form.Item
                        name="keyFormatType"
                        label="Key Format Type"
                        help="Format used to store the key"
                    >
                        <Select
                            options={KEY_FORMAT_TYPES}
                            allowClear
                            placeholder="Select key format"
                        />
                    </Form.Item>

                    <Form.Item
                        name="objectType"
                        label="Object Type"
                        help="Type of cryptographic object"
                    >
                        <Select
                            options={OBJECT_TYPES}
                            allowClear
                            placeholder="Select object type"
                        />
                    </Form.Item>
                </div>

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Linked Objects</h3>

                    <Form.Item
                        name="publicKeyId"
                        label="Public Key ID"
                        help="Find objects linked to this public key"
                    >
                        <Input placeholder="Enter public key ID" />
                    </Form.Item>

                    <Form.Item
                        name="privateKeyId"
                        label="Private Key ID"
                        help="Find objects linked to this private key"
                    >
                        <Input placeholder="Enter private key ID" />
                    </Form.Item>

                    <Form.Item
                        name="certificateId"
                        label="Certificate ID"
                        help="Find objects linked to this certificate"
                    >
                        <Input placeholder="Enter certificate ID" />
                    </Form.Item>
                </div>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Search Objects
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default LocateForm;
