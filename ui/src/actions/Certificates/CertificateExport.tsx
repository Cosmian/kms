import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { export_certificate_ttlv_request, parse_export_certificate_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface CertificateExportFormData {
    certificateId?: string;
    tags?: string[];
    outputFormat: CertificateExportFormat;
    pkcs12Password?: string;
}

type CertificateExportFormat = "JsonTtlv" | "Pem" | "Pkcs12" | "Pkcs12Legacy" | "Pkcs7";

const exportFileExtension = {
    JsonTtlv: "json",
    Pem: "pem",
    Pkcs12: "p12",
    Pkcs12Legacy: "p12",
    Pkcs7: "p7b",
};

const CertificateExportForm: React.FC = () => {
    const [form] = Form.useForm<CertificateExportFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [selectedFormat, setSelectedFormat] = useState<CertificateExportFormat>("JsonTtlv");
    const { t } = useTranslation("actions");

    const handleFormatChange = (value: CertificateExportFormat) => {
        setSelectedFormat(value);
    };

    const onFinish = async (values: CertificateExportFormData) => {
        const id = values.certificateId ? values.certificateId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(`${t("common:errorPrefix")}${t("certificateExport.missingCertificateId")}`);
            }
            const request = export_certificate_ttlv_request(id, values.outputFormat, values.pkcs12Password);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const data = await parse_export_certificate_ttlv_response(result_str, values.outputFormat);
                const filename = `certificate_${id}.${exportFileExtension[values.outputFormat]}`;
                let mimeType;
                switch (values.outputFormat) {
                    case "JsonTtlv":
                        mimeType = "application/json";
                        break;
                    case "Pem":
                        mimeType = "application/x-pem-file";
                        break;
                    case "Pkcs12":
                    case "Pkcs12Legacy":
                        mimeType = "application/x-pkcs12";
                        break;
                    case "Pkcs7":
                        mimeType = "application/x-pkcs7-certificates";
                        break;
                    default:
                        mimeType = "application/octet-stream";
                }
                downloadFile(data, filename, mimeType);
                return t("certificateExport.success");
            }
        });
    };

    const certificateFormats = [
        { label: t("certificateExport.formatJsonTtlv"), value: "JsonTtlv" },
        { label: t("certificateExport.formatPem"), value: "Pem" },
        { label: t("certificateExport.formatPkcs12"), value: "Pkcs12" },
        { label: t("certificateExport.formatPkcs12Legacy"), value: "Pkcs12Legacy" },
        { label: t("certificateExport.formatPkcs7"), value: "Pkcs7" },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateExport.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateExport.intro")}</p>
                <p>{t("certificateExport.introPkcs12")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("certificateExport.note")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    outputFormat: "JsonTtlv",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateExport.certificateIdentification")}</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="certificateId"
                            label={t("certificateExport.certificateId")}
                            help={t("certificateExport.certificateIdHelp")}
                            placeholder={t("certificateExport.enterCertificateId")}
                            objectType="Certificate"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateExport.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="outputFormat"
                            label={t("certificateExport.certificateFormat")}
                            help={t("certificateExport.certificateFormatHelp")}
                            rules={[{ required: true }]}
                        >
                            <Select options={certificateFormats} onChange={handleFormatChange} />
                        </Form.Item>
                    </Card>

                    {(selectedFormat === "Pkcs12" || selectedFormat === "Pkcs12Legacy") && (
                        <Card>
                            <Form.Item
                                name="pkcs12Password"
                                label={t("certificateExport.pkcs12Password")}
                                help={t("certificateExport.pkcs12PasswordHelp")}
                                rules={[{ required: true }]}
                            >
                                <Input.Password placeholder={t("certificateExport.enterPkcs12Password")} />
                            </Form.Item>
                        </Card>
                    )}
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("certificateExport.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateExport.responseTitle")} />
        </div>
    );
};

export default CertificateExportForm;
