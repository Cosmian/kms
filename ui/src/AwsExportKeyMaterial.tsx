import { Button, Card, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { downloadFile, sendKmipRequest } from "./utils";
import * as wasm from "./wasm/pkg/cosmian_kms_client_wasm";
import ExternalLink from "./components/ExternalLink";

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

interface AwsExportKeyMaterialFormData {
    wrappedKeyId: string;
    kekId: string;
    tokenFile?: string;
    byokFile?: string;
}

const AwsExportKeyMaterialForm: React.FC = () => {
    const [form] = Form.useForm<AwsExportKeyMaterialFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AwsExportKeyMaterialFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            // Step 1: Get KEK attributes to retrieve AWS tags
            const getAttrsRequest = wasm.get_attributes_ttlv_request_with_options(values.kekId, true);
            const attrsResultStr = await sendKmipRequest(getAttrsRequest, idToken, serverUrl);

            if (!attrsResultStr) {
                setRes("Failed to retrieve KEK attributes");
                return;
            }

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
            const attributes = await wasm.parse_get_attributes_ttlv_response(attrsResultStr, allAttributes);

            const tags = getTags(attributes);

            if (!tags.includes("aws")) {
                setRes("The KEK is not an AWS Key Encryption Key: missing 'aws' tag. Import it using the Import KEK command.");
                return;
            }

            const keyArnTag = tags.find((t: string) => t.startsWith("key_arn:"));
            const keyArn = keyArnTag ? keyArnTag.substring(8) : undefined;

            const wrappingAlgTag = tags.find((t: string) => t.startsWith("wrapping_algorithm:"));
            if (!wrappingAlgTag) {
                setRes("The KEK is not an AWS Key Encryption Key: wrapping algorithm not found. Import it using the Import KEK command.");
                return;
            }
            const wrappingAlgorithm = wrappingAlgTag.substring(19);

            // Step 2: Export the wrapped key using the KEK
            const exportRequest = wasm.export_ttlv_request(
                values.wrappedKeyId, // Key ID to wrap
                false, // Unwrap flag
                "raw", // Key format (raw bytes)
                values.kekId, // Wrapping key ID
                wrappingAlgorithm, // Wrapping algorithm
            );

            const exportResultStr = await sendKmipRequest(exportRequest, idToken, serverUrl);

            if (!exportResultStr) {
                setRes("Failed to export wrapped key");
                return;
            }

            const wrappedKeyData = await wasm.parse_export_ttlv_response(exportResultStr, "raw");

            let wrappedKeyBytes: Uint8Array;
            if (wrappedKeyData instanceof Uint8Array) {
                wrappedKeyBytes = wrappedKeyData;
            } else if (typeof wrappedKeyData === "string") {
                const binaryString = atob(wrappedKeyData);
                wrappedKeyBytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    wrappedKeyBytes[i] = binaryString.charCodeAt(i);
                }
            } else {
                setRes("Unexpected wrapped key format");
                return;
            }

            // Step 3: Generate output
            if (values.byokFile) {
                // Download as file
                downloadFile(wrappedKeyBytes, values.byokFile, "application/octet-stream");

                // Build AWS CLI command
                const awsCommand = `aws kms import-key-material \\
    --key-id ${keyArn || "<AWS_KEY_ARN>"} \\
    --encrypted-key-material fileb://${values.byokFile} \\
    --import-token fileb://${values.tokenFile || "<IMPORT_TOKEN_FILE>"} \\
    --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE`;

                setRes(
                    `The encrypted key material (${wrappedKeyBytes.length} bytes) was successfully written to ${values.byokFile} for key ${values.wrappedKeyId}.\n\nTo import into AWS KMS using the CLI, you can run:\n\n${awsCommand}`,
                );
            } else {
                // Display as base64
                const b64Key = btoa(String.fromCharCode(...wrappedKeyBytes));
                setRes(`Wrapped key material (base64-encoded):\n\n${b64Key}`);
            }
        } catch (e) {
            setRes(`Error exporting key material: ${e}`);
            console.error("Error exporting key material:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Export AWS Key Material</h1>
            <div className="mb-8 space-y-2">
                <p>Wrap a Cosmian KMS key with an AWS KMS wrapping key and generate the key material to be imported into.</p>
                <p>The KEK must be previously imported using the Import KEK command.</p>
                <p className="text-sm text-gray-600">
                    See:{" "}
                    <ExternalLink href="https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-import-key-material.html">
                        AWS KMS Import Key Material
                    </ExternalLink>
                </p>
            </div>
            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identifiers</h3>
                        <Form.Item
                            name="wrappedKeyId"
                            label="Key ID to Wrap"
                            rules={[{ required: true, message: "Please enter the key ID to wrap" }]}
                            help="The unique ID of the KMS key that will be wrapped and exported to AWS"
                        >
                            <Input placeholder="Enter the KMS key ID to export" />
                        </Form.Item>
                        <Form.Item
                            name="kekId"
                            label="AWS KEK ID"
                            rules={[{ required: true, message: "Please enter the KEK ID" }]}
                            help="The ID of the AWS KEK in this KMS (previously imported using Import KEK)"
                        >
                            <Input placeholder="Enter the AWS KEK ID" />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Output Options (Optional)</h3>
                        <Form.Item
                            name="tokenFile"
                            label="Import Token File Path"
                            help="The path to the import token file from AWS (used only for generating the CLI command)"
                        >
                            <Input placeholder="path/to/import-token.bin" />
                        </Form.Item>
                        <Form.Item
                            name="byokFile"
                            label="Output Filename"
                            help="Filename for the wrapped key material. If not specified, base64-encoded output will be displayed."
                        >
                            <Input placeholder="encrypted-key-material.bin" />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Export Key Material
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Export Result">
                        <pre className="whitespace-pre-wrap">{res}</pre>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default AwsExportKeyMaterialForm;
