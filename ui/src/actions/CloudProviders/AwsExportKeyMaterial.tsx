import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import ExternalLink from "../../components/common/ExternalLink";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";

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
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: AwsExportKeyMaterialFormData) => {
        await execute(async () => {
            // Step 1: Get KEK attributes to retrieve AWS tags
            const getAttrsRequest = wasm.get_attributes_ttlv_request_with_options(values.kekId, true);
            const attrsResultStr = await sendKmipRequest(getAttrsRequest, serverUrl);

            if (!attrsResultStr) {
                return t("awsExportKeyMaterial.failedRetrieveKekAttributes");
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
                return t("awsExportKeyMaterial.notAwsKekMissingTag");
                return;
            }

            const keyArnTag = tags.find((t: string) => t.startsWith("key_arn:"));
            const keyArn = keyArnTag ? keyArnTag.substring(8) : undefined;

            const wrappingAlgTag = tags.find((t: string) => t.startsWith("wrapping_algorithm:"));
            if (!wrappingAlgTag) {
                return t("awsExportKeyMaterial.notAwsKekNoWrappingAlg");
                return;
            }
            const wrappingAlgorithm = wrappingAlgTag.substring(19);

            // Step 2: Export the wrapped key using the KEK
            const exportRequest = wasm.export_ttlv_request(
                values.wrappedKeyId, // Key ID to wrap
                true, // Unwrap flag
                "raw", // Key format (raw bytes)
                values.kekId, // Wrapping key ID
                wrappingAlgorithm, // Wrapping algorithm
            );

            const exportResultStr = await sendKmipRequest(exportRequest, serverUrl);

            if (!exportResultStr) {
                return t("awsExportKeyMaterial.failedExport");
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
                return t("awsExportKeyMaterial.unexpectedFormat");
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

                return t("awsExportKeyMaterial.successWithCommand", {
                    size: wrappedKeyBytes.length,
                    byokFile: values.byokFile,
                    wrappedKeyId: values.wrappedKeyId,
                    awsCommand,
                });
            } else {
                // Display as base64
                const b64Key = btoa(String.fromCharCode(...wrappedKeyBytes));
                return t("awsExportKeyMaterial.base64Result", { b64: b64Key });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("awsExportKeyMaterial.title")}</h1>
            <div className="mb-8 space-y-2">
                <p>{t("awsExportKeyMaterial.intro")}</p>
                <p>{t("awsExportKeyMaterial.introKek")}</p>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                    {t("awsExportKeyMaterial.see")}:{" "}
                    <ExternalLink href="https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-import-key-material.html">
                        AWS KMS Import Key Material
                    </ExternalLink>
                </p>
            </div>
            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("awsExportKeyMaterial.keyIdentifiers")}</h3>
                        <Form.Item
                            name="wrappedKeyId"
                            label={t("awsExportKeyMaterial.wrappedKeyId")}
                            rules={[{ required: true, message: t("awsExportKeyMaterial.pleaseEnterWrappedKeyId") }]}
                            help={t("awsExportKeyMaterial.wrappedKeyIdHelp")}
                        >
                            <Input placeholder={t("awsExportKeyMaterial.enterWrappedKeyId")} />
                        </Form.Item>
                        <Form.Item
                            name="kekId"
                            label={t("awsExportKeyMaterial.kekId")}
                            rules={[{ required: true, message: t("awsExportKeyMaterial.pleaseEnterKekId") }]}
                            help={t("awsExportKeyMaterial.kekIdHelp")}
                        >
                            <Input placeholder={t("awsExportKeyMaterial.enterKekId")} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("awsExportKeyMaterial.outputOptions")}</h3>
                        <Form.Item
                            name="tokenFile"
                            label={t("awsExportKeyMaterial.tokenFile")}
                            help={t("awsExportKeyMaterial.tokenFileHelp")}
                        >
                            <Input placeholder={t("awsExportKeyMaterial.tokenFilePlaceholder")} />
                        </Form.Item>
                        <Form.Item name="byokFile" label={t("awsExportKeyMaterial.byokFile")} help={t("awsExportKeyMaterial.byokFileHelp")}>
                            <Input placeholder={t("awsExportKeyMaterial.byokFilePlaceholder")} />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            {t("awsExportKeyMaterial.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title={t("awsExportKeyMaterial.exportResult")}>
                        <pre className="whitespace-pre-wrap">{res}</pre>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default AwsExportKeyMaterialForm;
