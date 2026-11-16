import { Alert, Button, Card, Form, Input } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/useAuth";
import { useActionState } from "../../hooks/useActionState";
import { postNoTTLVRequest } from "../../utils/utils";

interface SshCertificateForm {
    role: string;
    publicKey: string;
    principals: string;
    ttl?: string;
}

interface SshCertificateResponse {
    data: {
        signed_key: string;
        serial_number: string;
    };
}

const SshCertificate: React.FC = () => {
    const [form] = Form.useForm<SshCertificateForm>();
    const { serverUrl } = useAuth();
    const { res, isLoading, responseRef, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: SshCertificateForm) => {
        await execute(async () => {
            const response = (await postNoTTLVRequest(
                `/v1/ssh/sign/${encodeURIComponent(values.role.trim())}`,
                {
                    public_key: values.publicKey.trim(),
                    valid_principals: values.principals
                        .split(",")
                        .map((principal) => principal.trim())
                        .filter((principal) => principal.length > 0),
                    ...(values.ttl?.trim() ? { ttl: values.ttl.trim() } : {}),
                },
                serverUrl,
            )) as SshCertificateResponse;
            return response.data.signed_key;
        });
    };

    return (
        <Card title={t("sshCertificate.title")}>
            <Alert type="info" showIcon className="mb-4" message={t("sshCertificate.intro")} />
            <Form form={form} layout="vertical" onFinish={onFinish}>
                <Form.Item name="role" label={t("sshCertificate.role")} rules={[{ required: true }]}>
                    <Input data-testid="ssh-role" />
                </Form.Item>
                <Form.Item name="publicKey" label={t("sshCertificate.publicKey")} rules={[{ required: true }]}>
                    <Input.TextArea rows={3} data-testid="ssh-public-key" />
                </Form.Item>
                <Form.Item
                    name="principals"
                    label={t("sshCertificate.principals")}
                    extra={t("sshCertificate.principalsHelp")}
                    rules={[{ required: true }]}
                >
                    <Input data-testid="ssh-principals" />
                </Form.Item>
                <Form.Item name="ttl" label={t("sshCertificate.ttl")}>
                    <Input placeholder="15m" data-testid="ssh-ttl" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-ssh-certificate">
                    {t("sshCertificate.submit")}
                </Button>
            </Form>
            <ActionResponse title={t("sshCertificate.responseTitle")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default SshCertificate;
