import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_cc_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface CCEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    encryptionPolicy: string;
    keyId?: string;
    tags?: string[];
    authenticationData?: Uint8Array;
}

const CCEncryptForm: React.FC = () => {
    const [form] = Form.useForm<CCEncryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: CCEncryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("covercryptEncrypt.missingKeyId"));
            }
            const request = encrypt_cc_ttlv_request(id, values.encryptionPolicy, values.inputFile, values.authenticationData);

            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const data = new Uint8Array(response.Data);
                const mimeType = "application/octet-stream";
                const filename = `${values.fileName}.enc`;
                downloadFile(data, filename, mimeType);
                return t("covercryptEncrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("covercryptEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("covercryptEncrypt.intro")}</p>
                <p>{t("covercryptEncrypt.introKey")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("covercryptEncrypt.note")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("covercryptEncrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("covercryptEncrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("covercryptEncrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("covercryptEncrypt.encryptionPolicy")}</h3>
                        <Form.Item
                            name="encryptionPolicy"
                            rules={[{ required: true, message: t("covercryptEncrypt.pleaseEnterEncryptionPolicy") }]}
                            help={t("covercryptEncrypt.encryptionPolicyHelp")}
                        >
                            <Input.TextArea placeholder={t("covercryptEncrypt.enterEncryptionPolicy")} rows={2} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("covercryptEncrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("covercryptEncrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("covercryptEncrypt.additionalOptions")}</h3>
                        <Form.Item
                            name="authenticationData"
                            label={t("covercryptEncrypt.authenticationData")}
                            help={t("covercryptEncrypt.authenticationDataHelp")}
                        >
                            <Input.TextArea placeholder={t("covercryptEncrypt.enterAuthenticationData")} rows={2} />
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
                            {t("covercryptEncrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("covercryptEncrypt.responseTitle")} />
        </div>
    );
};

export default CCEncryptForm;
