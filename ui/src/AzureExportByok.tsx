import { Button, Card, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { downloadFile, sendKmipRequest } from "./utils";
import {
    export_ttlv_request,
    get_attributes_ttlv_request_with_options,
    parse_export_ttlv_response,
    parse_get_attributes_ttlv_response,
} from "./wasm/pkg";

const getTags = (attributes: Map<string, never>): string[] => {
    const vendor_attributes: Array<Map<string, never>> | undefined = attributes.get("vendor_attributes");
    if (typeof vendor_attributes !== "undefined") {
        const attrs_value_map: Map<string, never> | undefined = (vendor_attributes as Array<Map<string, never>>)
            .find((attribute: Map<string, never>) => {
                return attribute.get("AttributeName") === "tag";
            })
            ?.get("AttributeValue");
        if (typeof attrs_value_map === "undefined") {
            return [];
        }
        const tags_string = (attrs_value_map as Map<string, string>).get("_c");
        if (tags_string) {
            try {
                return JSON.parse(tags_string);
            } catch (error) {
                console.error("Error parsing tags JSON:", error);
                return [];
            }
        } else {
            return [];
        }
    }

    return [];
};

interface ExportAzureBYOKFormData {
    wrappedKeyId: string;
    kekId: string;
    byokFile?: string;
}

const ExportAzureBYOKForm: React.FC = () => {
    const [form] = Form.useForm<ExportAzureBYOKFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ExportAzureBYOKFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            // Step 1: Get the KEK attributes to retrieve the Azure kid
            const getAttrsRequest = get_attributes_ttlv_request_with_options(values.kekId, true);
            const attrsResultStr = await sendKmipRequest(getAttrsRequest, idToken, serverUrl);

            if (!attrsResultStr) {
                setRes("Failed to retrieve KEK attributes");
                return;
            }

            // Parse attributes with all possible attribute names
            const allAttributes = [
                "activation_date",
                "cryptographic_algorithm",
                "cryptographic_length",
                "key_usage",
                "key_format_type",
                "object_type",
                "vendor_attributes",
                "public_key_id",
                "private_key_id",
            ];
            const attributes = await parse_get_attributes_ttlv_response(attrsResultStr, allAttributes);

            // Extract tags from vendor_attributes or look for Tag field
            const tags = getTags(attributes);

            if (!tags.includes("azure")) {
                setRes("The KEK is not an Azure Key Encryption Key: missing 'azure' tag. Import it using the Import KEK command.");
                return;
            }

            const kidTag = tags.find((t: string) => t.startsWith("kid:"));
            if (!kidTag) {
                setRes("The KEK is not an Azure Key Encryption Key: Azure kid not found. Import it using the Import KEK command.");
                return;
            }

            const kid = kidTag.substring(4); // Remove "kid:" prefix

            // Step 2: Export the wrapped key using the KEK
            // Note: The WASM interface has limited wrapping algorithm support.
            // For Azure BYOK, we need RSA wrapping with specific parameters.
            // Using "rsa-pkcs-oaep" as the wrapping algorithm
            const exportRequest = export_ttlv_request(
                values.wrappedKeyId,
                true, // unwrap - export the key in wrapped form
                "raw", // key_format - raw bytes
                values.kekId, // wrap_key_id - the KEK to wrap with
                "rsa-aes-key-wrap-sha1", // wrapping_algorithm
            );

            const exportResultStr = await sendKmipRequest(exportRequest, idToken, serverUrl);

            if (!exportResultStr) {
                setRes("Failed to export wrapped key");
                return;
            }

            const wrappedKeyData = await parse_export_ttlv_response(exportResultStr, "raw");

            // The wrapped key should be in Uint8Array format
            let wrappedKeyBytes: Uint8Array;
            if (wrappedKeyData instanceof Uint8Array) {
                wrappedKeyBytes = wrappedKeyData;
            } else if (typeof wrappedKeyData === "string") {
                // Convert from base64 string if needed
                const binaryString = atob(wrappedKeyData);
                wrappedKeyBytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    wrappedKeyBytes[i] = binaryString.charCodeAt(i);
                }
            } else {
                setRes("Unexpected wrapped key format");
                return;
            }

            // Step 3: Generate .byok file in JSON format
            // Convert bytes to base64 URL-safe encoding (no padding)
            const base64UrlEncode = (bytes: Uint8Array): string => {
                const base64 = btoa(String.fromCharCode(...bytes));
                return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
            };

            const byokObject = {
                schema_version: "1.0.0",
                header: {
                    kid: kid,
                    alg: "dir",
                    enc: "CKM_RSA_AES_KEY_WRAP",
                },
                ciphertext: base64UrlEncode(wrappedKeyBytes),
                generator: "Cosmian_KMS;v5",
            };

            const byokContent = JSON.stringify(byokObject, null, 2);

            // Determine the filename
            const filename = values.byokFile || `${values.wrappedKeyId}.byok`;

            // Download the .byok file
            downloadFile(byokContent, filename, "application/json");

            setRes(`The BYOK file was successfully created and downloaded as ${filename} for key ${values.wrappedKeyId}.`);
        } catch (e) {
            setRes(`Error exporting BYOK: ${e}`);
            console.error("Error exporting BYOK:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Export Azure BYOK File</h1>

            <div className="mb-8 space-y-2">
                <p>Wrap a KMS key with an Azure Key Encryption Key (KEK) and generate a .byok file for Azure Key Vault import.</p>
                <p>The KEK must be previously imported using the Import KEK command.</p>
                <p className="text-sm text-gray-600">
                    See:{" "}
                    <a
                        href="https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline"
                    >
                        Azure BYOK Specification
                    </a>
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identifiers (required)</h3>
                        <Form.Item
                            name="wrappedKeyId"
                            label="Wrapped Key ID"
                            rules={[{ required: true, message: "Please enter the wrapped key ID" }]}
                            help="The unique ID of the KMS private key that will be wrapped and exported to Azure"
                        >
                            <Input placeholder="Enter the KMS key ID to export" />
                        </Form.Item>

                        <Form.Item
                            name="kekId"
                            label="Azure KEK ID"
                            rules={[{ required: true, message: "Please enter the KEK ID" }]}
                            help="The ID of the Azure KEK in this KMS (previously imported using Import KEK)"
                        >
                            <Input placeholder="Enter the Azure KEK ID" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Output File (optional)</h3>
                        <Form.Item
                            name="byokFile"
                            label="BYOK Filename"
                            help="The filename for the exported .byok file. If not specified, it will be named <wrapped_key_id>.byok"
                        >
                            <Input placeholder="custom-filename.byok (optional)" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Export BYOK File
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef}>
                    <Card title="Export Response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default ExportAzureBYOKForm;
