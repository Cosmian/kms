import { UploadOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { FormUpload } from "../../components/common/FormUpload";
import { useActionState } from "../../hooks/useActionState";
import { downloadFile } from "../../utils/utils";

type CsrFormat = "pem" | "der";

interface EstEnrollFormData {
    csrFile?: Uint8Array;
    csrFormat: CsrFormat;
    username?: string;
    password?: string;
}

/** Strip PEM armor and base64-decode the body to DER bytes. */
const pemToDer = (pemText: string): Uint8Array => {
    const base64 = pemText
        .split("\n")
        .filter((line) => !line.includes("-----"))
        .join("")
        .replace(/\s+/g, "");
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
};

const EstEnrollForm: React.FC = () => {
    const [form] = Form.useForm<EstEnrollFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: EstEnrollFormData) => {
        await execute(async () => {
            if (!values.csrFile) {
                throw new Error(t("estEnroll.pleaseUploadCsr"));
            }
            const der = values.csrFormat === "pem" ? pemToDer(new TextDecoder().decode(values.csrFile)) : values.csrFile;

            const headers: Record<string, string> = { "Content-Type": "application/pkcs10" };
            if (values.username && values.password) {
                headers.Authorization = `Basic ${btoa(`${values.username}:${values.password}`)}`;
            }

            const url = `${serverUrl}/.well-known/est/simpleenroll`;
            const response = await fetch(url, { method: "POST", headers, body: der as BodyInit });

            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(t("estEnroll.error404"));
                }
                if (response.status === 401) {
                    throw new Error(t("estEnroll.error401"));
                }
                const errorText = await response.text();
                throw new Error(`${response.status}: ${errorText}`);
            }

            // RFC 7030 §4.2.3: the body is base64 text wrapping a DER PKCS#7 bundle.
            const base64Body = (await response.text()).replace(/\s+/g, "");
            const certDer = Uint8Array.from(atob(base64Body), (c) => c.charCodeAt(0));
            downloadFile(certDer, "est-certificate.p7b", "application/pkcs7-mime");

            return t("estEnroll.success", { bytes: certDer.length });
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("estEnroll.title")}</h1>
            <div className="mb-8 space-y-2">
                <p>{t("estEnroll.intro")}</p>
            </div>
            <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ csrFormat: "pem" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="csrFormat" label={t("estEnroll.csrFormat")} rules={[{ required: true }]}>
                            <Select
                                options={[
                                    { value: "pem", label: t("estEnroll.formatPem") },
                                    { value: "der", label: t("estEnroll.formatDer") },
                                ]}
                            />
                        </Form.Item>
                        <Form.Item
                            name="csrFile"
                            label={t("estEnroll.csrFile")}
                            help={t("estEnroll.csrFileHelp")}
                            rules={[{ required: true, message: t("estEnroll.pleaseUploadCsr") }]}
                        >
                            <FormUpload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer instanceof ArrayBuffer) {
                                            form.setFieldsValue({ csrFile: new Uint8Array(arrayBuffer) });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>{t("estEnroll.uploadCsrFile")}</Button>
                            </FormUpload>
                        </Form.Item>
                    </Card>
                    <Card>
                        <Alert type="info" showIcon message={t("estEnroll.usernameHelp")} className="mb-4" />
                        <Form.Item name="username" label={t("estEnroll.username")}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="password" label={t("estEnroll.password")}>
                            <Input.Password />
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
                            {t("estEnroll.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse title={t("estEnroll.responseTitle")} res={res} responseRef={responseRef} />
        </div>
    );
};

export default EstEnrollForm;
