import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { buildAzureByokContent, getAzureByokFilename, getTags } from "../../utils/azureByok";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import {
    export_ttlv_request,
    get_attributes_ttlv_request_with_options,
    parse_export_ttlv_response,
    parse_get_attributes_ttlv_response,
} from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface ExportAzureBYOKFormData {
    wrappedKeyId: string;
    kekId: string;
    byokFile?: string;
}

const ExportAzureBYOKForm: React.FC = () => {
    const [form] = Form.useForm<ExportAzureBYOKFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: ExportAzureBYOKFormData) => {
        await execute(async () => {
            // Step 1: Get the KEK attributes to retrieve the Azure kid
            const getAttrsRequest = get_attributes_ttlv_request_with_options(values.kekId, true);
            const attrsResultStr = await sendKmipRequest(getAttrsRequest, serverUrl);

            if (!attrsResultStr) {
                return t("azureExportByok.failedRetrieveKekAttributes");
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
                return t("azureExportByok.notAzureKekMissingTag");
                return;
            }

            const kidTag = tags.find((t: string) => t.startsWith("kid:"));
            if (!kidTag) {
                return t("azureExportByok.notAzureKekNoKid");
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

            const exportResultStr = await sendKmipRequest(exportRequest, serverUrl);

            if (!exportResultStr) {
                return t("azureExportByok.failedExport");
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
                return t("azureExportByok.unexpectedFormat");
                return;
            }

            // Step 3: Generate .byok file in JSON format
            // Determine the filename
            const filename = getAzureByokFilename(values.wrappedKeyId, values.byokFile);

            const byokContent = buildAzureByokContent(kid, wrappedKeyBytes);

            // Download the .byok file
            downloadFile(byokContent, filename, "application/json");

            return t("azureExportByok.success", { filename, wrappedKeyId: values.wrappedKeyId });
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("azureExportByok.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("azureExportByok.intro")}</p>
                <p>{t("azureExportByok.introKek")}</p>
                <p className="text-sm text-gray-600">
                    {t("azureExportByok.see")}:{" "}
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
                        <h3 className="text-m font-bold mb-4">{t("azureExportByok.keyIdentifiers")}</h3>
                        <Form.Item
                            name="wrappedKeyId"
                            label={t("azureExportByok.wrappedKeyId")}
                            rules={[{ required: true, message: t("azureExportByok.pleaseEnterWrappedKeyId") }]}
                            help={t("azureExportByok.wrappedKeyIdHelp")}
                        >
                            <Input placeholder={t("azureExportByok.enterWrappedKeyId")} />
                        </Form.Item>

                        <Form.Item
                            name="kekId"
                            label={t("azureExportByok.kekId")}
                            rules={[{ required: true, message: t("azureExportByok.pleaseEnterKekId") }]}
                            help={t("azureExportByok.kekIdHelp")}
                        >
                            <Input placeholder={t("azureExportByok.enterKekId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("azureExportByok.outputFile")}</h3>
                        <Form.Item name="byokFile" label={t("azureExportByok.byokFile")} help={t("azureExportByok.byokFileHelp")}>
                            <Input placeholder={t("azureExportByok.byokFilePlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("azureExportByok.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("azureExportByok.responseTitle")} />
        </div>
    );
};

export default ExportAzureBYOKForm;
