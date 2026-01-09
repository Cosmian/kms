import { Button, Card, Checkbox, Divider, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { downloadFile, sendKmipRequest } from "./utils";
import { export_ttlv_request, parse_export_ttlv_response } from "./wasm/pkg";

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

type ExportKeyFormat = "json-ttlv" | "sec1-pem" | "sec1-der" | "pkcs1-pem" | "pkcs1-der" | "pkcs8-pem" | "pkcs8-der" | "base64" | "raw";

type WrappingAlgorithm = "aes-key-wrap-padding" | "nist-key-wrap" | "aes-gcm" | "rsa-pkcs-v15" | "rsa-oaep" | "rsa-aes-key-wrap";

const WRAPPING_ALGORITHMS: { label: string; value: WrappingAlgorithm }[] = [
    { label: "AES Key Wrap with Padding (RFC 5649)", value: "aes-key-wrap-padding" },
    { label: "AES Key Wrap with NO Padding (RFC 3394)", value: "nist-key-wrap" },
    { label: "AES GCM", value: "aes-gcm" },
    { label: "RSA PKCS v1.5", value: "rsa-pkcs-v15" },
    { label: "RSA OAEP", value: "rsa-oaep" },
    { label: "RSA AES Key Wrap", value: "rsa-aes-key-wrap" },
];

type KeyType = "rsa" | "ec" | "symmetric" | "covercrypt" | "secret-data" | "opaque-object";

const exportFileExtension = {
    "json-ttlv": "json",
    "sec1-pem": "pem",
    "pkcs1-pem": "pem",
    "pkcs8-pem": "pem",
    "sec1-der": "der",
    "pkcs1-der": "der",
    "pkcs8-der": "der",
    base64: "b64",
    raw: "",
};

interface KeyExportFormProps {
    key_type: KeyType;
}

const KeyExportForm: React.FC<KeyExportFormProps> = ({ key_type }) => {
    const [form] = Form.useForm<KeyExportFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const wrapKeyId = Form.useWatch("wrapKeyId", form);
    const selectedAlgorithm: WrappingAlgorithm | undefined = Form.useWatch("wrappingAlgorithm", form);
    const selectedFormat: ExportKeyFormat | undefined = Form.useWatch("keyFormat", form);

    const isSecretData = key_type === "secret-data";
    const isOpaqueObject = key_type === "opaque-object";
    const isDataLike = isSecretData || isOpaqueObject;
    const displayName = isSecretData ? "Secret Data" : isOpaqueObject ? "Opaque Object" : key_type.toUpperCase();

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        if (!wrapKeyId) {
            form.setFieldsValue({
                wrappingAlgorithm: undefined,
                authenticatedAdditionalData: undefined,
            });
        }
    }, [wrapKeyId, form]);

    useEffect(() => {
        if (selectedAlgorithm !== "aes-gcm") {
            form.setFieldsValue({ authenticatedAdditionalData: undefined });
        }
    }, [selectedAlgorithm, form]);

    const onFinish = async (values: KeyExportFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (!id) {
                setRes("Missing identifier.");
                throw new Error("Missing object identifier");
            }
            const request = export_ttlv_request(id, values.unwrap, values.keyFormat, values.wrapKeyId, values.wrappingAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const data = await parse_export_ttlv_response(result_str, values.keyFormat);
                const filename = `${id}.${exportFileExtension[values.keyFormat]}`;
                const mimeType =
                    values.keyFormat === "json-ttlv"
                        ? "application/json"
                        : values.keyFormat === "base64"
                        ? "text/plain"
                        : "application/octet-stream";
                downloadFile(data, filename, mimeType);
                setRes("File has been exported");
            }
        } catch (e) {
            setRes(`Error exporting ${isSecretData ? "secret data" : "key"}: ${e}`);
            console.error("Export error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    let keyFormats = [];
    if (key_type === "rsa") {
        keyFormats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "PKCS1 PEM", value: "pkcs1-pem" },
            { label: "PKCS1 DER", value: "pkcs1-der" },
            { label: "PKCS8 PEM", value: "pkcs8-pem" },
            { label: "PKCS8 DER", value: "pkcs8-der" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else if (key_type === "ec") {
        keyFormats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "SEC1 PEM", value: "sec1-pem" },
            { label: "SEC1 DER", value: "sec1-der" },
            { label: "PKCS8 PEM", value: "pkcs8-pem" },
            { label: "PKCS8 DER", value: "pkcs8-der" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else if (key_type === "symmetric" || isDataLike) {
        keyFormats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else {
        keyFormats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "Raw", value: "raw" },
        ];
    }

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Export {displayName}</h1>

            <div className="mb-8 space-y-2">
                <p>
                    Export {displayName} from the KMS. The {isDataLike ? "object" : "object"} can be identified using either its ID or associated tags.
                </p>
                {!isDataLike && (
                    <>
                        <p>When exporting a key pair using its ID, only the public key is exported.</p>
                        <p>The key can optionally be unwrapped and/or wrapped when exported.</p>
                        <p className="text-sm text-yellow-600">Note: Wrapping a key that is already wrapped is an error.</p>
                    </>
                )}
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: "json-ttlv",
                    unwrap: false,
                    allowRevoked: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{isDataLike ? "Object" : "Key"} Identification (required)</h3>
                        <Form.Item name="keyId" label={isSecretData ? "Secret Data ID" : isOpaqueObject ? "Opaque Object ID" : "Key ID"}>
                            <Input placeholder={`Enter ${isSecretData ? "secret data" : isOpaqueObject ? "opaque object" : "key"} ID`} />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="keyFormat" label="Export Format" rules={[{ required: true }]}>
                            <Select options={keyFormats} />
                        </Form.Item>
                    </Card>

                    {!isSecretData && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">Unwrapping Options</h3>
                            <Form.Item name="unwrap" valuePropName="checked">
                                <Checkbox>Unwrap {isDataLike ? "object" : "key"} before export</Checkbox>
                            </Form.Item>

                            {selectedFormat !== "raw" && selectedFormat !== "base64" && (
                                <>
                                    <Divider />
                                    <h3 className="text-m font-bold mb-4">Wrapping Options</h3>
                                    <Form.Item name="wrapKeyId" label="Wrap Key ID">
                                        <Input placeholder="Enter wrap key ID" />
                                    </Form.Item>

                                    <Form.Item name="wrappingAlgorithm" label="Wrapping Algorithm">
                                        <Select options={WRAPPING_ALGORITHMS} placeholder="Select algorithm" disabled={!wrapKeyId} />
                                    </Form.Item>

                                    {selectedAlgorithm === "aes-gcm" && (
                                        <Form.Item name="authenticatedAdditionalData" label="Authenticated Additional Data">
                                            <Input placeholder="Enter authenticated data" disabled={!wrapKeyId} />
                                        </Form.Item>
                                    )}
                                </>
                            )}
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="allowRevoked" valuePropName="checked">
                            <Checkbox>Allow revoked objects</Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Export {isDataLike ? "Object" : "Key"}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef}>
                    <Card title={isDataLike ? "Object Export Response" : "Key Export Response"}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default KeyExportForm;
