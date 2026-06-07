import { Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React from "react";
import { downloadFile } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/AuthContext";

interface GenerateCrlFormData {
    issuerCertificateId: string;
    validityDays: number;
    outputFormat: "der" | "pem";
}

const CertificateGenerateCrlForm: React.FC = () => {
    const [form] = Form.useForm<GenerateCrlFormData>();
    const { res, isLoading, responseRef, execute } = useActionState();
    const { serverUrl } = useAuth();

    const onFinish = async (values: GenerateCrlFormData) => {
        await execute(async () => {
            const params = new URLSearchParams({
                format: values.outputFormat,
                validity_days: values.validityDays.toString(),
            });
            const url = `${serverUrl}/certificates/${encodeURIComponent(values.issuerCertificateId)}/crl?${params}`;
            const response = await fetch(url, {
                method: "GET",
                credentials: "include",
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`${response.status}: ${errorText}`);
            }

            const data = new Uint8Array(await response.arrayBuffer());
            const ext = values.outputFormat === "pem" ? "pem" : "crl";
            const mimeType = values.outputFormat === "pem" ? "application/x-pem-file" : "application/pkix-crl";
            downloadFile(data, `crl.${ext}`, mimeType);

            return `CRL generated successfully (${data.length} bytes, ${values.outputFormat.toUpperCase()} format)`;
        });
    };

    return (
        <Card title="Generate CRL">
            <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ validityDays: 7, outputFormat: "der" }}>
                <Form.Item
                    label="Issuer Certificate ID"
                    name="issuerCertificateId"
                    rules={[{ required: true, message: "Please enter the issuer (CA) certificate ID" }]}
                >
                    <Input placeholder="Enter the CA certificate unique identifier" data-testid="issuer-certificate-id" />
                </Form.Item>

                <Form.Item label="Validity (days)" name="validityDays">
                    <InputNumber min={1} max={3650} data-testid="validity-days" />
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
                            Generate CRL
                        </Button>
                    </Space>
                </Form.Item>
            </Form>
            <ActionResponse title="CRL Generation Result" res={res} responseRef={responseRef} />
        </Card>
    );
};

export default CertificateGenerateCrlForm;
