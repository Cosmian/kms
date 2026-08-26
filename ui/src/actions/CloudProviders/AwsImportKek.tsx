import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space, Tabs, Upload } from "antd";
import React, { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import ExternalLink from "../../components/common/ExternalLink";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";

interface ImportAwsKekFormData {
    kekFile?: Uint8Array;
    kekBase64?: string;
    keyArn?: string;
    wrappingAlgorithm: WrappingAlgorithm;
    keyId?: string;
}

type KeyImportResponse = {
    UniqueIdentifier: string;
};

// These values MUST match the WrappingAlgorithm enum's strum kebab-case serialization
// in crate/client_utils/src/export_utils.rs (used by wasm.export_ttlv_request).
enum WrappingAlgorithm {
    RsaOaepSha1 = "rsa-oaep-sha1",
    RsaOaepSha256 = "rsa-oaep",
    RsaAesKeyWrapSha1 = "rsa-aes-key-wrap-sha1",
    RsaAesKeyWrapSha256 = "rsa-aes-key-wrap",
}

const WRAPPING_ALGORITHMS = [
    { label: "RSAES_OAEP_SHA_1", value: WrappingAlgorithm.RsaOaepSha1 },
    { label: "RSAES_OAEP_SHA_256", value: WrappingAlgorithm.RsaOaepSha256 },
    { label: "RSA_AES_KEY_WRAP_SHA_1", value: WrappingAlgorithm.RsaAesKeyWrapSha1 },
    { label: "RSA_AES_KEY_WRAP_SHA_256", value: WrappingAlgorithm.RsaAesKeyWrapSha256 },
];

const ImportAwsKekForm: React.FC = () => {
    const [form] = Form.useForm<ImportAwsKekFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [inputType, setInputType] = useState<"file" | "base64">("file");

    const onFinish = async (values: ImportAwsKekFormData) => {
        await execute(async () => {
            const tags = ["aws", `wrapping_algorithm:${values.wrappingAlgorithm}`];
            // only include key_arn if provided:
            if (values.keyArn) {
                tags.push(`key_arn:${values.keyArn}`);
            }
            const keyUsage = ["WrapKey", "Encrypt"];

            let kekData: Uint8Array | undefined = undefined;
            let kekFormat: string | undefined = undefined;

            if (inputType === "file" && values.kekFile) {
                kekData = values.kekFile;
                kekFormat = "pkcs8-pub";
            } else if (inputType === "base64" && values.kekBase64) {
                // Decode base64 to Uint8Array
                const binary = atob(values.kekBase64.replace(/\s/g, ""));
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                kekData = bytes;
                kekFormat = "pkcs8-pub";
            } else {
                return t("awsImportKek.provideKek");
            }

            const request = wasm.import_ttlv_request(
                values.keyId || null, // Custom key ID
                kekData, // Key bytes
                kekFormat, // Format type
                null, // Public key ID
                null, // Private key ID
                null, // Certificate ID
                false, // Unwrap flag
                true, // Replace existing
                tags,
                keyUsage, // Key usage
                null, // Wrapping key ID
            );

            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await wasm.parse_import_ttlv_response(result_str);
                return t("awsImportKek.success", { keyId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("awsImportKek.title")}</h1>
            <div className="mb-8 space-y-2">
                <p>{t("awsImportKek.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="awsImportKek.introKek" components={{ b: <b /> }} />
                </p>
                {/* prettier-ignore */}
                <p className="text-sm text-gray-600 dark:text-gray-300">
                    {t("awsImportKek.seeDoc")}{" "}
                <ExternalLink href="https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-get-public-key-and-token.html">
                    {t("awsImportKek.downloadingDoc")}
                </ExternalLink>.
                </p>
                <div className="bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-500 dark:border-blue-400 rounded-md p-4 mt-4">
                    <div className="text-blue-800 dark:text-blue-300 text-sm space-y-2">
                        <p>
                            <Trans ns="actions" i18nKey="awsImportKek.byokScripts" components={{ strong: <strong /> }} />{" "}
                            <ExternalLink href="https://docs.cosmian.com/key_management_system/integrations/cloud_providers/aws/byok/#automated-byok-scripts">
                                {t("awsImportKek.learnMore")}
                            </ExternalLink>
                            .
                        </p>
                    </div>
                </div>
            </div>
            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        {/* prettier-ignore */}
                        <Tabs
                            activeKey={inputType}
                            onChange={(key) => setInputType(key as "file" | "base64")}
                            items={[
                                {
                                    key: "file",
                                    label: t("awsImportKek.uploadFileTab"),
                                    children: (
                                        <Form.Item
                                            name="kekFile"
                                            label={t("awsImportKek.kekFile")}
                                            rules={inputType === "file" ? [{ required: true, message: t("awsImportKek.pleaseUploadKek") }] : []}
                                            help={t("awsImportKek.kekFileHelp")}
                                        >
                                            <Upload
                                                beforeUpload={(file) => {
                                                    const reader = new FileReader();
                                                    reader.onload = (e) => {
                                                        const content = e.target?.result;
                                                        if (content instanceof ArrayBuffer) {
                                                            const bytes = new Uint8Array(content);
                                                            form.setFieldsValue({ kekFile: bytes });
                                                        }
                                                    };
                                                    reader.readAsArrayBuffer(file);
                                                    return false;
                                                }}
                                                maxCount={1}
                                            >
                                                <Button icon={<UploadOutlined />}>{t("awsImportKek.selectKekFile")}</Button>
                                            </Upload>
                                        </Form.Item>
                                    ),
                                },
                                {
                                    key: "base64",
                                    label: t("awsImportKek.pasteBase64Tab"),
                                    children: (
                                        <Form.Item
                                        name="kekBase64"
                                        label={t("awsImportKek.kekBase64")}
                                        rules={
                                            inputType === "base64"
                                            ? [{ required: true, message: t("awsImportKek.pleasePasteKek") }]
                                            : []
                                        }
                                        help={
                                            <>
                                                    {t("awsImportKek.kekBase64Help")}{" "}
                                                <ExternalLink href="https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-get-public-key-and-token.html#importing-keys-get-public-key-and-token-api">
                                                    AWS KMS API
                                                </ExternalLink>)
                                                </>
                                            }
                                        >
                                            <Input.TextArea rows={4} placeholder={t("awsImportKek.kekBase64Placeholder")} />
                                        </Form.Item>
                                    ),
                                },
                            ]}
                        />
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("awsImportKek.wrappingAlgorithm")}</h3>
                        <Form.Item
                            name="wrappingAlgorithm"
                            label={t("awsImportKek.wrappingAlgorithm")}
                            rules={[{ required: true, message: t("awsImportKek.pleaseSelectWrappingAlgorithm") }]}
                            help={t("awsImportKek.wrappingAlgorithmHelp")}
                        >
                            <Select options={WRAPPING_ALGORITHMS} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("awsImportKek.awsKeyArn")}</h3>
                        <Form.Item name="keyArn" label={t("awsImportKek.awsKeyArn")} help={t("awsImportKek.awsKeyArnHelp")}>
                            <Input placeholder={t("awsImportKek.awsKeyArnPlaceholder")} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("awsImportKek.kmsKeyId")}</h3>
                        <Form.Item name="keyId" label={t("awsImportKek.keyIdLabel")} help={t("awsImportKek.keyIdHelp")}>
                            <Input placeholder={t("awsImportKek.keyIdPlaceholder")} />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            {t("awsImportKek.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title={t("awsImportKek.responseTitle")}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default ImportAwsKekForm;
