import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { getMimeType, saveDecryptedFile, sendKmipRequest } from "../../utils/utils";
import { decrypt_certificate_ttlv_request, parse_decrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface CertificateDecryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    privateKeyId?: string;
    tags?: string[];
    outputFile?: string;
    authenticationData?: Uint8Array;
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
}

const CertificateDecryptForm: React.FC = () => {
    const [form] = Form.useForm<CertificateDecryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const rsaEncryptionAlgorithms = [
        { label: t("certificateDecrypt.algorithmRsaPkcs"), value: "CkmRsaPkcs" },
        { label: t("certificateDecrypt.algorithmRsaOaep"), value: "CkmRsaPkcsOaep" },
        { label: t("certificateDecrypt.algorithmRsaAesKeyWrap"), value: "CkmRsaAesKeyWrap" },
    ];

    const onFinish = async (values: CertificateDecryptFormData) => {
        const id = values.privateKeyId ? values.privateKeyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(`${t("common:errorPrefix")}${t("certificateDecrypt.missingKeyId")}`);
            }
            const request = decrypt_certificate_ttlv_request(id, values.inputFile, values.authenticationData, values.encryptionAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const name = values.fileName.slice(0, -4);
                const lastDotIndex = name.lastIndexOf(".");
                const fileName = lastDotIndex !== -1 ? name : `${name}.plain`;
                const mimeType = getMimeType(fileName);
                saveDecryptedFile(response.Data, fileName, mimeType);
                return t("certificateDecrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateDecrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateDecrypt.intro")}</p>
                <p>{t("certificateDecrypt.introKey")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("certificateDecrypt.note")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    encryptionAlgorithm: "CkmRsaPkcsOaep",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateDecrypt.inputFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("certificateDecrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("certificateDecrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Private Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="privateKeyId"
                            label={t("certificateDecrypt.privateKeyId")}
                            help={t("certificateDecrypt.privateKeyIdHelp")}
                            placeholder={t("certificateDecrypt.enterPrivateKeyId")}
                            objectType="PrivateKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateDecrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="encryptionAlgorithm"
                            label={t("certificateDecrypt.encryptionAlgorithm")}
                            help={t("certificateDecrypt.encryptionAlgorithmHelp")}
                        >
                            <Select options={rsaEncryptionAlgorithms} />
                        </Form.Item>

                        <Form.Item
                            name="authenticationData"
                            label={t("certificateDecrypt.authenticationData")}
                            help={t("certificateDecrypt.authenticationDataHelp")}
                        >
                            <Input placeholder={t("certificateDecrypt.enterAuthenticationData")} />
                        </Form.Item>

                        <Form.Item
                            name="outputFile"
                            label={t("certificateDecrypt.outputFile")}
                            help={t("certificateDecrypt.outputFileHelp")}
                        >
                            <Input placeholder={t("certificateDecrypt.enterOutputFile")} />
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
                            {t("certificateDecrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateDecrypt.responseTitle")} />
        </div>
    );
};

export default CertificateDecryptForm;
