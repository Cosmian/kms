import { Button, Card, Form, Input, Radio, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_certificate_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface CertificateEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    certificateId?: string;
    tags?: string[];
    outputFile?: string;
    authenticationData?: Uint8Array;
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
}

const CertificateEncryptForm: React.FC = () => {
    const [form] = Form.useForm<CertificateEncryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: CertificateEncryptFormData) => {
        const id = values.certificateId ? values.certificateId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(`${t("common:errorPrefix")}${t("certificateEncrypt.missingCertificateId")}`);
            }
            const request = encrypt_certificate_ttlv_request(id, values.inputFile, values.authenticationData, values.encryptionAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const data = new Uint8Array(response.Data);
                const mimeType = "application/octet-stream";

                let filename;
                if (values.outputFile) {
                    filename = values.outputFile;
                } else {
                    filename = `${values.fileName}.enc`;
                }

                downloadFile(data, filename, mimeType);
                return t("certificateEncrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateEncrypt.intro")}</p>
                <p>{t("certificateEncrypt.introKey")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("certificateEncrypt.note")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
                initialValues={{
                    encryptionAlgorithm: "CkmRsaPkcsOaep",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateEncrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("certificateEncrypt.pleaseSelectFile") }]}>
                            <FormUploadDragger
                                beforeUpload={(file) => {
                                    form.setFieldValue("fileName", file.name);
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ inputFile: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">{t("certificateEncrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="certificateId"
                            label={t("certificateEncrypt.certificateId")}
                            help={t("certificateEncrypt.certificateIdHelp")}
                            placeholder={t("certificateEncrypt.enterCertificateId")}
                            objectType="Certificate"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateEncrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateEncrypt.encryptionOptions")}</h3>
                        <Form.Item
                            name="authenticationData"
                            label={t("certificateEncrypt.authenticationData")}
                            help={t("certificateEncrypt.authenticationDataHelp")}
                        >
                            <Input.TextArea placeholder={t("certificateEncrypt.enterAuthenticationData")} rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="encryptionAlgorithm"
                            label={t("certificateEncrypt.encryptionAlgorithm")}
                            help={t("certificateEncrypt.encryptionAlgorithmHelp")}
                        >
                            <Radio.Group>
                                <Radio value="CkmRsaPkcsOaep">PKCS#1 RSA OAEP</Radio>
                                <Radio value="CkmRsaPkcs">PKCS#1 v1.5 RSA</Radio>
                                <Radio value="CkmRsaAesKeyWrap">RSA AES Key Wrap</Radio>
                            </Radio.Group>
                        </Form.Item>

                        <Form.Item
                            name="outputFile"
                            label={t("certificateEncrypt.outputFile")}
                            help={t("certificateEncrypt.outputFileHelp")}
                        >
                            <Input placeholder={t("certificateEncrypt.enterOutputFile")} />
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
                            {t("certificateEncrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateEncrypt.responseTitle")} />
        </div>
    );
};

export default CertificateEncryptForm;
