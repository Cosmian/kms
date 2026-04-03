import { Button, Card, Form, Input, InputNumber, Radio, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { sendKmipRequest } from "../../utils/utils";
import {
    create_secret_data_ttlv_request,
    derive_key_ttlv_request,
    parse_derive_key_ttlv_response,
    parse_import_ttlv_response,
} from "../../wasm/pkg";

const HASHING_ALGORITHMS = [
    { label: "SHA-256", value: "SHA256" },
    { label: "SHA-384", value: "SHA384" },
    { label: "SHA-512", value: "SHA512" },
    { label: "SHA3-256", value: "SHA3256" },
    { label: "SHA3-384", value: "SHA3384" },
    { label: "SHA3-512", value: "SHA3512" },
];

const SYMMETRIC_ALGORITHMS = [
    { label: "AES", value: "Aes" },
    { label: "ChaCha20", value: "Chacha20" },
];

const KEY_LENGTHS = [
    { label: "128 bits", value: 128 },
    { label: "192 bits", value: 192 },
    { label: "256 bits", value: 256 },
];

const HEX_PATTERN = /^[0-9a-fA-F]+$/;

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

interface DeriveKeyFormData {
    sourceType: "key_id" | "password";
    keyId?: string;
    password?: string;
    derivationMethod: "PBKDF2" | "HKDF";
    salt: string;
    iterationCount: number;
    initializationVector?: string;
    hashingAlgorithm: string;
    symmetricAlgorithm: string;
    cryptographicLength: number;
    derivedKeyId?: string;
}

type ImportResponse = { UniqueIdentifier: string };
type DeriveKeyResponse = { UniqueIdentifier: string };

const DeriveKeyForm: React.FC = () => {
    const [form] = Form.useForm<DeriveKeyFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const sourceType = Form.useWatch("sourceType", form);
    const derivationMethod = Form.useWatch("derivationMethod", form);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: DeriveKeyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            let baseKeyId: string;

            if (values.sourceType === "password") {
                if (!values.password) {
                    throw new Error("Password is required");
                }
                // Import password as a SecretData object, then derive from it
                const importRequest = create_secret_data_ttlv_request("Password", values.password, undefined, [], true);
                const importStr = await sendKmipRequest(importRequest, idToken, serverUrl);
                if (!importStr) throw new Error("Failed to import password as secret data");
                const importResp: ImportResponse = await parse_import_ttlv_response(importStr);
                baseKeyId = importResp.UniqueIdentifier;
            } else {
                if (!values.keyId) throw new Error("Key ID is required");
                baseKeyId = values.keyId;
            }

            const saltBytes = hexToBytes(values.salt);
            const ivBytes =
                values.initializationVector && values.initializationVector.length > 0 ? hexToBytes(values.initializationVector) : undefined;

            const request = derive_key_ttlv_request(
                baseKeyId,
                values.derivationMethod,
                saltBytes,
                values.iterationCount,
                ivBytes,
                values.hashingAlgorithm,
                values.symmetricAlgorithm,
                values.cryptographicLength,
                values.derivedKeyId || null,
            );

            const resultStr = await sendKmipRequest(request, idToken, serverUrl);
            if (resultStr) {
                const result: DeriveKeyResponse = await parse_derive_key_ttlv_response(resultStr);
                setRes(`Derived key created with ID: ${result.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error deriving key: ${e}`);
            console.error("Error deriving key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Derive Key</h1>

            <div className="mb-8 space-y-2">
                <p>Derive a new symmetric key from an existing key or a password using PBKDF2 or HKDF.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <strong>Key ID</strong>: derive from an existing managed key or secret data object. The object must have the
                        <em> Derive Key</em> usage mask.
                    </li>
                    <li>
                        <strong>Password</strong>: the password is temporarily stored as a secret data object, used for derivation, and can
                        be revoked afterwards.
                    </li>
                    <li>Salt must be provided as a hexadecimal string.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sourceType: "key_id",
                    derivationMethod: "PBKDF2",
                    iterationCount: 4096,
                    hashingAlgorithm: "SHA256",
                    symmetricAlgorithm: "Aes",
                    cryptographicLength: 256,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    {/* Source */}
                    <Card title="Key Material Source">
                        <Form.Item name="sourceType" label="Source Type">
                            <Radio.Group>
                                <Radio value="key_id">Existing Key ID</Radio>
                                <Radio value="password">Password</Radio>
                            </Radio.Group>
                        </Form.Item>

                        {sourceType === "key_id" && (
                            <Form.Item
                                name="keyId"
                                label="Key ID"
                                rules={[{ required: true, message: "Please enter the source key ID" }]}
                                help="Unique identifier of the symmetric key or secret data to derive from"
                            >
                                <Input placeholder="Enter source key ID" />
                            </Form.Item>
                        )}

                        {sourceType === "password" && (
                            <Form.Item
                                name="password"
                                label="Password"
                                rules={[{ required: true, message: "Please enter the password" }]}
                                help="UTF-8 password to use as base material for key derivation"
                            >
                                <Input.Password placeholder="Enter password" />
                            </Form.Item>
                        )}
                    </Card>

                    {/* Derivation parameters */}
                    <Card title="Derivation Parameters">
                        <Form.Item name="derivationMethod" label="Derivation Method">
                            <Radio.Group>
                                <Radio value="PBKDF2">PBKDF2</Radio>
                                <Radio value="HKDF">HKDF</Radio>
                            </Radio.Group>
                        </Form.Item>

                        <Form.Item
                            name="salt"
                            label="Salt (hex)"
                            rules={[
                                { required: true, message: "Please enter a salt value" },
                                {
                                    pattern: HEX_PATTERN,
                                    message: "Salt must be a hexadecimal string",
                                },
                                {
                                    validator: (_, value: string) =>
                                        value && value.length % 2 !== 0
                                            ? Promise.reject(new Error("Salt must have an even number of hex characters"))
                                            : Promise.resolve(),
                                },
                            ]}
                            help="Salt bytes in hexadecimal format (e.g. 0011223344556677)"
                        >
                            <Input placeholder="e.g. 0011223344556677aabbccddeeff0011" />
                        </Form.Item>

                        {derivationMethod === "PBKDF2" && (
                            <Form.Item
                                name="iterationCount"
                                label="Iteration Count"
                                help="Number of PBKDF2 iterations (recommended: 4096 or more)"
                                rules={[{ required: true, message: "Please enter the iteration count" }]}
                            >
                                <InputNumber min={1} style={{ width: "100%" }} />
                            </Form.Item>
                        )}

                        <Form.Item
                            name="initializationVector"
                            label="Initialization Vector (hex, optional)"
                            rules={[
                                {
                                    pattern: /^([0-9a-fA-F]{2})*$/,
                                    message: "IV must be a hexadecimal string with an even number of characters",
                                },
                            ]}
                            help="Optional initialization vector in hexadecimal format"
                        >
                            <Input placeholder="Optional, e.g. 0102030405060708" />
                        </Form.Item>

                        <Form.Item
                            name="hashingAlgorithm"
                            label="Hashing Algorithm"
                            rules={[{ required: true, message: "Please select a hashing algorithm" }]}
                            help="Hash function used for key derivation"
                        >
                            <Select data-testid="hashing-algorithm-select" options={HASHING_ALGORITHMS} />
                        </Form.Item>
                    </Card>

                    {/* Output key specification */}
                    <Card title="Output Key Specification">
                        <Form.Item
                            name="symmetricAlgorithm"
                            label="Algorithm"
                            rules={[{ required: true, message: "Please select an output key algorithm" }]}
                            help="Algorithm of the derived symmetric key"
                        >
                            <Select data-testid="symmetric-algorithm-select" options={SYMMETRIC_ALGORITHMS} />
                        </Form.Item>

                        <Form.Item
                            name="cryptographicLength"
                            label="Key Length"
                            rules={[{ required: true, message: "Please select a key length" }]}
                            help="Length of the derived key in bits"
                        >
                            <Select data-testid="key-length-select" options={KEY_LENGTHS} />
                        </Form.Item>

                        <Form.Item
                            name="derivedKeyId"
                            label="Derived Key ID (optional)"
                            help="Optional unique identifier for the derived key. A random UUID is assigned if not specified."
                        >
                            <Input placeholder="Optional: enter desired key ID" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Derive Key
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800 break-all">
                    <pre className="whitespace-pre-wrap text-sm">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default DeriveKeyForm;
