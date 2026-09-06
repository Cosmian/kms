import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { downloadFile } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/AuthContext";

interface GenerateCrlFormData {
    issuerCertificateId: string;
    outputFormat: "der" | "pem";
}

const CertificateGenerateCrlForm: React.FC = () => {
    const [form] = Form.useForm<GenerateCrlFormData>();
    const { res, isLoading, responseRef, execute } = useActionState();
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");

    const onFinish = async (values: GenerateCrlFormData) => {
        await execute(async () => {
            // Use the public (unauthenticated) CRL endpoint so that any logged-in
            // user can download the CRL regardless of their role.
            //
            // The server keeps this endpoint up-to-date automatically:
            //  • After every certificate revocation the issuer's CRL is regenerated.
            //  • The background CRL refresh scheduler re-signs expiring CRLs.
            //
            // The CRL is built with a database-wide scan (`find_all`), so it
            // includes every revoked certificate issued by this CA regardless of
            // which user owns the certificate — ensuring a complete CRL even in
            // multi-user deployments.
            const url = `${serverUrl}/public/certificates/${encodeURIComponent(values.issuerCertificateId)}/crl`;
            const response = await fetch(url, {
                method: "GET",
            });

            if (!response.ok) {
                const errorText = await response.text();
                if (response.status === 404) {
                    throw new Error(t("certificateGenerateCrl.error404", { issuerId: values.issuerCertificateId }));
                }
                throw new Error(`${response.status}: ${errorText}`);
            }

            // The public endpoint always returns DER bytes.
            const derBytes = new Uint8Array(await response.arrayBuffer());

            let output: Uint8Array;
            const ext = values.outputFormat === "pem" ? "pem" : "crl";
            const mimeType = values.outputFormat === "pem" ? "application/x-pem-file" : "application/pkix-crl";

            if (values.outputFormat === "pem") {
                // Convert DER to PEM in-browser.
                const base64 = btoa(String.fromCodePoint(...derBytes));
                const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
                const pem = `-----BEGIN X509 CRL-----\n${lines}\n-----END X509 CRL-----\n`;
                output = new TextEncoder().encode(pem);
            } else {
                output = derBytes;
            }

            downloadFile(output, `crl.${ext}`, mimeType);

            return t("certificateGenerateCrl.success", {
                bytes: output.length,
                format: values.outputFormat.toUpperCase(),
            });
        });
    };

    return (
        <Card title={t("certificateGenerateCrl.title")}>
            <Alert
                type="info"
                showIcon
                className="mb-4"
                message={t("certificateGenerateCrl.alertMessage")}
                description={t("certificateGenerateCrl.alertDescription")}
            />
            <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ outputFormat: "der" }}>
                <Form.Item
                    label={t("certificateGenerateCrl.issuerCertificateId")}
                    name="issuerCertificateId"
                    rules={[{ required: true, message: t("certificateGenerateCrl.issuerCertificateIdRequired") }]}
                >
                    <Input placeholder={t("certificateGenerateCrl.issuerCertificateIdPlaceholder")} data-testid="issuer-certificate-id" />
                </Form.Item>

                <Form.Item label={t("certificateGenerateCrl.outputFormat")} name="outputFormat">
                    <Select data-testid="output-format">
                        <Select.Option value="der">{t("certificateGenerateCrl.formatDer")}</Select.Option>
                        <Select.Option value="pem">{t("certificateGenerateCrl.formatPem")}</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-generate-crl">
                            {t("certificateGenerateCrl.submit")}
                        </Button>
                    </Space>
                </Form.Item>
            </Form>
            <ActionResponse title={t("certificateGenerateCrl.responseTitle")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default CertificateGenerateCrlForm;
