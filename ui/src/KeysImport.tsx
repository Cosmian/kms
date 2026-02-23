import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUpload } from "./FormUpload";
import { sendKmipRequest } from "./utils";
import { import_ttlv_request, parse_import_ttlv_response } from "./wasm/pkg";

type ImportKeyFormat = "json-ttlv" | "pem" | "sec1" | "pkcs1-priv" | "pkcs1-pub" | "pkcs8-pub" | "pkcs8-priv" | "aes" | "chacha20";

type KeyUsage = "sign" | "verify" | "encrypt" | "decrypt" | "wrap" | "unwrap";

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
    wrappingKeyId?: string;
}

type KeyType = "rsa" | "ec" | "symmetric" | "covercrypt" | "secret-data" | "opaque-object";

interface KeyImportFormProps {
    key_type: KeyType;
}

type KeyImportResponse = {
    UniqueIdentifier: string;
};

const KeyImportForm: React.FC<KeyImportFormProps> = ({ key_type }) => {
    const [form] = Form.useForm<ImportKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ImportKeyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = import_ttlv_request(
                values.keyId,
                values.keyFile,
                values.keyFormat,
                values.publicKeyId,
                values.privateKeyId,
                values.certificateId,
                values.unwrap,
                values.replaceExisting,
                values.tags,
                values.keyUsage,
                values.wrappingKeyId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await parse_import_ttlv_response(result_str);
                setRes(`File has been imported - imported object id: ${result.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error importing: ${e}`);
            console.error("Error importing:", e);
        } finally {
            setIsLoading(false);
        }
    };

    let key_formats = [];
    let key_usages = [];

    if (key_type === "rsa") {
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "PEM (auto-detect format)", value: "pem" },
            { label: "PKCS#1 DER (RSA private)", value: "pkcs1-priv" },
            { label: "PKCS#1 DER (RSA public)", value: "pkcs1-pub" },
            { label: "PKCS#8 DER (RSA private)", value: "pkcs8-priv" },
            { label: "PKCS#8 DER (RSA public)", value: "pkcs8-pub" },
        ];
        key_usages = [
            { label: "Sign", value: "sign" },
            { label: "Verify", value: "verify" },
            { label: "Encrypt", value: "encrypt" },
            { label: "Decrypt", value: "decrypt" },
            { label: "Wrap", value: "wrap" },
            { label: "Unwrap", value: "unwrap" },
        ];
    } else if (key_type === "ec") {
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "PEM (auto-detect format)", value: "pem" },
            { label: "SEC1 DER (EC private)", value: "sec1" },
            { label: "PKCS#8 DER (RSA public)", value: "pkcs8-pub" },
            { label: "PKCS#8 DER (RSA private)", value: "pkcs8-priv" },
        ];
        key_usages = [
            { label: "Sign", value: "sign" },
            { label: "Verify", value: "verify" },
            { label: "Encrypt", value: "encrypt" },
            { label: "Decrypt", value: "decrypt" },
            { label: "Wrap", value: "wrap" },
            { label: "Unwrap", value: "unwrap" },
        ];
    } else if (key_type === "symmetric") {
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "AES", value: "aes" },
            { label: "ChaCha20", value: "chacha20" },
        ];
        key_usages = [
            { label: "Encrypt", value: "encrypt" },
            { label: "Decrypt", value: "decrypt" },
            { label: "Wrap", value: "wrap" },
            { label: "Unwrap", value: "unwrap" },
        ];
    } else if (key_type === "secret-data" || key_type === "opaque-object") {
        key_formats = [{ label: "JSON TTLV (default)", value: "json-ttlv" }];
        key_usages = [
            { label: "Wrap", value: "wrap" },
            { label: "Unwrap", value: "unwrap" },
        ];
    } else {
        key_formats = [{ label: "JSON TTLV (default)", value: "json-ttlv" }];
        key_usages = [
            { label: "Encrypt", value: "encrypt" },
            { label: "Decrypt", value: "decrypt" },
        ];
    }

    const isSecretData = key_type === "secret-data";
    const isOpaqueObject = key_type === "opaque-object";
    const isDataLike = isSecretData || isOpaqueObject;
    const displayName = isSecretData ? "Secret Data" : isOpaqueObject ? "Opaque Object" : `${key_type} key`;

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Import {displayName}</h1>

            <div className="mb-8 space-y-2">
                <p>Import {displayName} into the KMS.</p>
                <p>When no ID is specified, a random UUID will be generated.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: "json-ttlv",
                    unwrap: false,
                    replaceExisting: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyFile"
                            label={isDataLike ? "Data File" : "Key File"}
                            rules={[{ required: true, message: "Please upload a file" }]}
                            help={isSecretData ? "Upload the secret data file to import" : isOpaqueObject ? "Upload the opaque object file to import" : "Upload the key file to import"}
                        >
                            <FormUpload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const content = e.target?.result;
                                        if (typeof content === "string") {
                                            try {
                                                if (/^[A-Za-z0-9+/=]+$/.test(content.trim())) {
                                                    const decoded = atob(content.trim());
                                                    const bytes = new Uint8Array([...decoded].map((char) => char.charCodeAt(0)));
                                                    form.setFieldsValue({ keyFile: bytes });
                                                } else {
                                                    throw new Error("Invalid Base64 format");
                                                }
                                            } catch {
                                                const binaryReader = new FileReader();
                                                binaryReader.onload = (event) => {
                                                    const rawContent = event.target?.result;
                                                    if (rawContent instanceof ArrayBuffer) {
                                                        const bytes = new Uint8Array(rawContent);
                                                        form.setFieldsValue({ keyFile: bytes });
                                                    }
                                                };
                                                binaryReader.readAsArrayBuffer(file);
                                            }
                                        }
                                    };
                                    reader.readAsText(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>Upload {isSecretData ? "Secret Data File" : isOpaqueObject ? "Opaque Object File" : "Key File"}</Button>
                            </FormUpload>
                        </Form.Item>

                        <Form.Item name="keyId" label="ID" help="Optional: A random UUID will be generated if not specified">
                            <Input placeholder="Enter ID" />
                        </Form.Item>

                        <Form.Item name="keyFormat" label="Format" help="Format of the file to import" rules={[{ required: true }]}>
                            <Select options={key_formats} />
                        </Form.Item>
                    </Card>

                    {!isSecretData && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">Key Relationships</h3>

                            <Form.Item name="publicKeyId" label="Public Key ID" help="Link to public key in KMS">
                                <Input placeholder="Enter public key ID" />
                            </Form.Item>

                            <Form.Item name="privateKeyId" label="Private Key ID" help="Link to private key in KMS">
                                <Input placeholder="Enter private key ID" />
                            </Form.Item>

                            <Form.Item name="certificateId" label="Certificate ID" help="Link to certificate in KMS">
                                <Input placeholder="Enter certificate ID" />
                            </Form.Item>
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="keyUsage" label="Usage" help="Specify allowed operations">
                            <Select mode="multiple" options={key_usages} placeholder="Select usage" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="wrappingKeyId" label="Wrapping Key ID" help="Optional: ID of wrapping key">
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="unwrap" valuePropName="checked" help="Unwrap if wrapped before storing">
                            <Checkbox>Unwrap before import</Checkbox>
                        </Form.Item>

                        <Form.Item name="replaceExisting" valuePropName="checked" help="Replace an existing object with same ID">
                            <Checkbox>Replace existing</Checkbox>
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="authenticatedAdditionalData"
                            label="Authenticated Additional Data"
                            help="Optional: For AES256GCM authenticated encryption"
                        >
                            <Input placeholder="Enter authenticated data" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Import {isDataLike ? "Data" : "Key"}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef}>
                    <Card title="Import Response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default KeyImportForm;
