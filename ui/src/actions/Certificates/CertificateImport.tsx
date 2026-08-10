import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUpload } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import { import_certificate_ttlv_request, parse_import_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

type CertificateInputFormat = "JsonTtlv" | "Pem" | "Der" | "Pkcs12";

type KeyUsage = "sign" | "verify" | "encrypt" | "decrypt" | "wrap" | "unwrap";

interface ImportCertificateFormData {
    certificateFile?: Uint8Array;
    certificateId?: string;
    inputFormat: CertificateInputFormat;
    privateKeyId?: string;
    publicKeyId?: string;
    issuerCertificateId?: string;
    pkcs12Password?: string;
    replaceExisting: boolean;
    tags: string[];
    keyUsage?: KeyUsage[];
}

type CertificateImportResponse = {
    UniqueIdentifier: string;
};

const CertificateImportForm: React.FC = () => {
    const [form] = Form.useForm<ImportCertificateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [selectedFormat, setSelectedFormat] = useState<CertificateInputFormat>("JsonTtlv");
    const { t } = useTranslation("actions");

    const onFinish = async (values: ImportCertificateFormData) => {
        await execute(async () => {
            if (values.certificateFile) {
                const request = import_certificate_ttlv_request(
                    values.certificateId,
                    values.certificateFile,
                    values.inputFormat,
                    values.privateKeyId,
                    values.publicKeyId,
                    values.issuerCertificateId,
                    values.pkcs12Password,
                    values.replaceExisting,
                    values.tags,
                    values.keyUsage,
                );
                const result_str = await sendKmipRequest(request, serverUrl);
                if (result_str) {
                    const result: CertificateImportResponse = await parse_import_ttlv_response(result_str);
                    return t("certificateImport.success", { objectId: result.UniqueIdentifier });
                }
            } else {
                throw new Error(`${t("common:errorPrefix")}${t("certificateImport.certificateFileRequired")}`);
            }
        });
    };

    const formatOptions = [
        { label: t("certificateImport.formatJsonTtlv"), value: "JsonTtlv" },
        { label: t("certificateImport.formatPem"), value: "Pem" },
        { label: t("certificateImport.formatDer"), value: "Der" },
        // { label: 'PEM-stack Certificate Chain', value: 'Chain' },
        { label: t("certificateImport.formatPkcs12"), value: "Pkcs12" },
        // { label: 'Mozilla Common CA Database (CCADB)', value: 'Ccadb' }
    ];

    const keyUsageOptions = [
        { label: "Sign", value: "sign" },
        { label: "Verify", value: "verify" },
        { label: "Encrypt", value: "encrypt" },
        { label: "Decrypt", value: "decrypt" },
        { label: "Wrap", value: "wrap" },
        { label: "Unwrap", value: "unwrap" },
    ];

    // Handle format change to update the UI
    const handleFormatChange = (value: CertificateInputFormat) => {
        setSelectedFormat(value);
    };

    // Check if PKCS#12 password field should be shown
    const showPkcs12Password = selectedFormat === "Pkcs12";

    // Check if relationship fields should be shown (not for PKCS12 and CCADB)
    const showRelationships = !["Pkcs12"].includes(selectedFormat);

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateImport.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateImport.intro")}</p>
                <p>{t("certificateImport.introUuid")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    inputFormat: "JsonTtlv",
                    replaceExisting: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="inputFormat"
                            label={t("certificateImport.certificateFormat")}
                            help={t("certificateImport.certificateFormatHelp")}
                            rules={[{ required: true }]}
                        >
                            <Select options={formatOptions} onChange={(value) => handleFormatChange(value as CertificateInputFormat)} />
                        </Form.Item>

                        <Form.Item
                            name="certificateFile"
                            label={t("certificateImport.certificateFile")}
                            rules={[{ required: true, message: t("certificateImport.pleaseUploadCertificate") }]}
                            help={t("certificateImport.certificateFileHelp", { format: selectedFormat })}
                        >
                            <FormUpload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ certificateFile: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>{t("certificateImport.uploadCertificateFile")}</Button>
                            </FormUpload>
                        </Form.Item>

                        <Form.Item
                            name="certificateId"
                            label={t("certificateImport.certificateId")}
                            help={t("certificateImport.certificateIdHelp")}
                        >
                            <Input placeholder={t("certificateImport.enterCertificateId")} />
                        </Form.Item>

                        {showPkcs12Password && (
                            <Form.Item
                                name="pkcs12Password"
                                label={t("certificateImport.pkcs12Password")}
                                rules={[{ required: true }]}
                                help={t("certificateImport.pkcs12PasswordHelp")}
                            >
                                <Input.Password placeholder={t("certificateImport.enterPkcs12Password")} />
                            </Form.Item>
                        )}
                    </Card>

                    {showRelationships && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">{t("certificateImport.certificateRelationships")}</h3>

                            <Form.Item
                                name="privateKeyId"
                                label={t("certificateImport.privateKeyId")}
                                help={t("certificateImport.privateKeyIdHelp")}
                            >
                                <Input placeholder={t("certificateImport.enterPrivateKeyId")} />
                            </Form.Item>

                            <Form.Item
                                name="publicKeyId"
                                label={t("certificateImport.publicKeyId")}
                                help={t("certificateImport.publicKeyIdHelp")}
                            >
                                <Input placeholder={t("certificateImport.enterPublicKeyId")} />
                            </Form.Item>

                            <Form.Item
                                name="issuerCertificateId"
                                label={t("certificateImport.issuerCertificateId")}
                                help={t("certificateImport.issuerCertificateIdHelp")}
                            >
                                <Input placeholder={t("certificateImport.enterIssuerCertificateId")} />
                            </Form.Item>
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="keyUsage" label={t("certificateImport.keyUsage")} help={t("certificateImport.keyUsageHelp")}>
                            <Select mode="multiple" options={keyUsageOptions} placeholder={t("certificateImport.selectKeyUsage")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateImport.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item name="replaceExisting" valuePropName="checked" help={t("certificateImport.replaceExistingHelp")}>
                            <Checkbox>{t("certificateImport.replaceExisting")}</Checkbox>
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
                            {t("certificateImport.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateImport.responseTitle")} />
        </div>
    );
};

export default CertificateImportForm;
