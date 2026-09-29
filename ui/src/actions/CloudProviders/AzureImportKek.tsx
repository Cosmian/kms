import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUpload } from "../../components/common/FormUpload";
import { azureKekKeyUsage, azureKekTags } from "../../utils/azureKek";
import { sendKmipRequest } from "../../utils/utils";
import { import_ttlv_request, parse_import_ttlv_response } from "../../wasm/pkg";
import ExternalLink from "../../components/common/ExternalLink";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

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
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: ImportAzureKekFormData) => {
        await execute(async () => {
            // Import the KEK with Azure-specific tags and key usage
            const tags = azureKekTags(values.kid);
            const keyUsage = azureKekKeyUsage;

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
                undefined, // wrappingKeyId
            );

            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await parse_import_ttlv_response(result_str);
                return t("azureImportKek.success", { keyId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("azureImportKek.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("azureImportKek.intro")}</p>
                <p>{t("azureImportKek.introPem")}</p>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                    {t("azureImportKek.see")}:{" "}
                    <ExternalLink href="https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek">
                        Azure BYOK Specification - Generate KEK
                    </ExternalLink>
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("azureImportKek.kekFileCard")}</h3>
                        <Form.Item
                            name="kekFile"
                            label={t("azureImportKek.kekFile")}
                            rules={[{ required: true, message: t("azureImportKek.pleaseUploadKek") }]}
                            help={t("azureImportKek.kekFileHelp")}
                        >
                            <FormUpload
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
                                <Button icon={<UploadOutlined />}>{t("azureImportKek.selectKekFile")}</Button>
                            </FormUpload>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("azureImportKek.azureKeyIdCard")}</h3>
                        <Form.Item
                            name="kid"
                            label={t("azureImportKek.azureKeyId")}
                            rules={[{ required: true, message: t("azureImportKek.pleaseEnterAzureKeyId") }]}
                            help={
                                <span>
                                    {t("azureImportKek.azureKeyIdHelp")}
                                    <br />
                                    https://mypremiumkeyvault.vault.azure.net/keys/KEK-BYOK/664f5aa2797a4075b8e36ca4500636d8
                                </span>
                            }
                        >
                            <Input placeholder={t("azureImportKek.azureKeyIdPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("azureImportKek.kmsKeyIdCard")}</h3>
                        <Form.Item name="keyId" label={t("azureImportKek.keyIdLabel")} help={t("azureImportKek.keyIdHelp")}>
                            <Input placeholder={t("azureImportKek.keyIdPlaceholder")} />
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
                            {t("azureImportKek.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("azureImportKek.responseTitle")} />
        </div>
    );
};

export default ImportAzureKekForm;
