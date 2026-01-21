import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Space, Upload } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { import_ttlv_request, parse_import_ttlv_response } from "./wasm/pkg";
import ExternalLink from "./components/ExternalLink";

interface ImportAzureKekFormData {
    kekFile: Uint8Array;
    kid: string;
    keyId?: string;
}

type KeyImportResponse = {
    UniqueIdentifier: string;
};

const ImportAzureKekForm: React.FC = () => {
    const [form] = Form.useForm<ImportAzureKekFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ImportAzureKekFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            // Import the KEK with Azure-specific tags and key usage
            const tags = ["azure", `kid:${values.kid}`];
            const keyUsage = ["WrapKey", "Encrypt"];

            const request = import_ttlv_request(
                values.keyId,
                values.kekFile,
                "pem", // KEK file is in PKCS#8 PEM format
                undefined, // publicKeyId
                undefined, // privateKeyId
                undefined, // certificateId
                false, // unwrap
                true, // replaceExisting
                tags,
                keyUsage,
                undefined // wrappingKeyId
            );

            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await parse_import_ttlv_response(result_str);
                setRes(`Azure KEK has been successfully imported - Key ID: ${result.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error importing Azure KEK: ${e}`);
            console.error("Error importing Azure KEK:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Import Azure Key Encryption Key (KEK)</h1>

            <div className="mb-8 space-y-2">
                <p>Import an RSA Key Encryption Key (KEK) generated on Azure Key Vault into the KMS.</p>
                <p>The KEK should be exported from Azure in PKCS#8 PEM format.</p>
                <p className="text-sm text-gray-600">
                    See:{" "}
                    <ExternalLink href="https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek">
                        Azure BYOK Specification - Generate KEK
                    </ExternalLink>
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">KEK File (required)</h3>
                        <Form.Item
                            name="kekFile"
                            label="RSA Key Encryption Key (KEK) File"
                            rules={[{ required: true, message: "Please upload the KEK file" }]}
                            help="The KEK file exported from Azure Key Vault in PKCS#8 PEM format"
                        >
                            <Upload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const content = e.target?.result;
                                        if (typeof content === "string") {
                                            // For PEM files, we need to convert to bytes
                                            const encoder = new TextEncoder();
                                            const bytes = encoder.encode(content);
                                            form.setFieldsValue({ kekFile: bytes });
                                        } else if (content instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(content);
                                            form.setFieldsValue({ kekFile: bytes });
                                        }
                                    };
                                    reader.readAsText(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>Select KEK File</Button>
                            </Upload>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Azure Key ID (required)</h3>
                        <Form.Item
                            name="kid"
                            label="Azure Key ID (kid)"
                            rules={[{ required: true, message: "Please enter the Azure Key ID" }]}
                            help={
                                <span>
                                    The Azure Key ID should be in the format:
                                    <br />
                                    https://mypremiumkeyvault.vault.azure.net/keys/KEK-BYOK/664f5aa2797a4075b8e36ca4500636d8
                                </span>
                            }
                        >
                            <Input placeholder="https://your-vault.vault.azure.net/keys/KEK-BYOK/..." />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">KMS Key ID (optional)</h3>
                        <Form.Item
                            name="keyId"
                            label="Key ID in KMS"
                            help="The unique ID for this key in the KMS. A random UUID will be generated if not specified."
                        >
                            <Input placeholder="Enter custom key ID (optional)" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Import Azure KEK
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

export default ImportAzureKekForm;
