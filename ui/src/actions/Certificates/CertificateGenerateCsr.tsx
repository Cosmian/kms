import { Alert, Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/useAuth";
import { useActionState } from "../../hooks/useActionState";
import { downloadFile, postNoTTLVRequest } from "../../utils/utils";

interface GenerateCsrFormData {
    privateKeyId: string;
    subjectName: string;
}

const CertificateGenerateCsrForm: React.FC = () => {
    const [form] = Form.useForm<GenerateCsrFormData>();
    const { res, isLoading, responseRef, execute } = useActionState();
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");

    const onFinish = async (values: GenerateCsrFormData) => {
        await execute(async () => {
            // The CSR is signed server-side: the private key (possibly in an HSM) is never exported.
            const { csr_pem } = (await postNoTTLVRequest(
                "/certificates/csr",
                { private_key_id: values.privateKeyId.trim(), subject_name: values.subjectName.trim() },
                serverUrl,
            )) as { csr_pem: string };
            downloadFile(csr_pem, "request.csr", "application/pkcs10");
            return t("certificateGenerateCsr.success", { bytes: csr_pem.length });
        });
    };

    return (
        <Card title={t("certificateGenerateCsr.title")}>
            <Alert
                type="info"
                showIcon
                className="mb-4"
                message={t("certificateGenerateCsr.alertMessage")}
                description={t("certificateGenerateCsr.alertDescription")}
            />
            <Form form={form} layout="vertical" onFinish={onFinish}>
                <Form.Item
                    label={t("certificateGenerateCsr.privateKeyId")}
                    name="privateKeyId"
                    rules={[{ required: true, whitespace: true, message: t("certificateGenerateCsr.privateKeyIdRequired") }]}
                >
                    <Input placeholder={t("certificateGenerateCsr.privateKeyIdPlaceholder")} data-testid="private-key-id" />
                </Form.Item>

                <Form.Item
                    label={t("certificateGenerateCsr.subjectName")}
                    name="subjectName"
                    rules={[{ required: true, whitespace: true, message: t("certificateGenerateCsr.subjectNameRequired") }]}
                >
                    <Input placeholder="C=FR, O=Acme, CN=Acme Sub CA" data-testid="subject-name" />
                </Form.Item>

                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-generate-csr">
                            {t("certificateGenerateCsr.submit")}
                        </Button>
                    </Space>
                </Form.Item>
            </Form>
            <ActionResponse title={t("certificateGenerateCsr.responseTitle")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default CertificateGenerateCsrForm;
