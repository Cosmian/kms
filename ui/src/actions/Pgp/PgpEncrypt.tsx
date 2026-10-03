import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import KeyIdInput from "../../components/common/KeyIdInput";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_pgp_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PgpEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
}

const PgpEncryptForm: React.FC = () => {
    const [form] = Form.useForm<PgpEncryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: PgpEncryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pgpEncrypt.missingKeyId"));
            }
            const request = encrypt_pgp_ttlv_request(id, values.inputFile);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const { Data } = await parse_encrypt_ttlv_response(result_str);
                const filename = `${values.fileName}.gpg`;
                downloadFile(Data, filename, "application/octet-stream");
                return t("pgpEncrypt.success");
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("pgpEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pgpEncrypt.intro")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("pgpEncrypt.note")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pgpEncrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item
                            name="inputFile"
                            rules={[{ required: true, message: t("pgpEncrypt.pleaseSelectFile") }]}
                            help={t("pgpEncrypt.inputFileHelp")}
                        >
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
                                <p className="ant-upload-text">{t("pgpEncrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>

                    <Card>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            placeholder={t("common:enterKeyId")}
                            objectType="PGPKey"
                        />
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                            {t("pgpEncrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("pgpEncrypt.responseTitle")} />
        </div>
    );
};

export default PgpEncryptForm;
