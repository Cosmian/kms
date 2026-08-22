import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
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
                    throw new Error(
                        `No CRL found for issuer '${values.issuerCertificateId}'. ` +
                            "The CRL is generated automatically when a certificate is revoked. " +
                            "If no certificate has been revoked yet, the CRL may not exist.",
                    );
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

            return `CRL downloaded successfully (${output.length} bytes, ${values.outputFormat.toUpperCase()} format)`;
        });
    };

    return (
        <Card title="Download CRL">
            <Alert
                type="info"
                showIcon
                className="mb-4"
                message="The CRL is downloaded from the public distribution point."
                description={
                    "Revoked certificates are collected from all users automatically. " +
                    "The CRL is refreshed on every revocation and by a background scheduler. " +
                    "No Crypto Officer role is required to download it."
                }
            />
            <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ outputFormat: "der" }}>
                <Form.Item
                    label="Issuer Certificate ID"
                    name="issuerCertificateId"
                    rules={[{ required: true, message: "Please enter the issuer (CA) certificate ID" }]}
                >
                    <Input placeholder="Enter the CA certificate unique identifier" data-testid="issuer-certificate-id" />
                </Form.Item>

                <Form.Item label="Output Format" name="outputFormat">
                    <Select data-testid="output-format">
                        <Select.Option value="der">DER (binary)</Select.Option>
                        <Select.Option value="pem">PEM (text)</Select.Option>
                    </Select>
                </Form.Item>

                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-generate-crl">
                            Download CRL
                        </Button>
                    </Space>
                </Form.Item>
            </Form>
            <ActionResponse title="CRL Download Result" res={res} responseRef={responseRef} />
        </Card>
    );
};

export default CertificateGenerateCrlForm;
