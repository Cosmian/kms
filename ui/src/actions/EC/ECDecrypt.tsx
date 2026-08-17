import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { getMimeType, saveDecryptedFile, sendKmipRequest } from "../../utils/utils";
import { decrypt_ec_ttlv_request, parse_decrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface ECDecryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    outputFile?: string;
}

const ECDecryptForm: React.FC = () => {
    const [form] = Form.useForm<ECDecryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: ECDecryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("ecDecrypt.missingKeyId"));
            }
            const request = decrypt_ec_ttlv_request(id, values.inputFile);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const name = values.fileName.slice(0, -4);
                const lastDotIndex = name.lastIndexOf(".");
                const fileName = lastDotIndex !== -1 ? name : `${name}.plain`;
                const mimeType = getMimeType(fileName);
                saveDecryptedFile(response.Data, fileName, mimeType);
                return t("ecDecrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("ecDecrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("ecDecrypt.intro")}</p>
                <p>{t("ecDecrypt.introKey")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("ecDecrypt.note")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("ecDecrypt.inputFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("ecDecrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("ecDecrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("ecDecrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="PrivateKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("ecDecrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
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
                            {t("ecDecrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("ecDecrypt.responseTitle")} />
        </div>
    );
};

export default ECDecryptForm;
