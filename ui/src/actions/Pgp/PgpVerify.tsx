import { Button, Card, Form, Input, Space } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import { parse_signature_verify_ttlv_response, signature_verify_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface PgpVerifyFormData {
    dataFile: Uint8Array;
    dataFileName: string;
    signatureFile: Uint8Array;
    signatureFileName: string;
    keyId?: string;
    tags?: string[];
}

const PgpVerifyForm: React.FC = () => {
    const [form] = Form.useForm<PgpVerifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [dataBytes, setDataBytes] = useState<Uint8Array | undefined>(undefined);
    const [sigBytes, setSigBytes] = useState<Uint8Array | undefined>(undefined);

    const onFinish = async (values: PgpVerifyFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pgpVerify.missingKeyId"));
            }
            const dataBuf = dataBytes ?? (values.dataFile ? new Uint8Array(values.dataFile) : undefined);
            const sigBuf = sigBytes ?? (values.signatureFile ? new Uint8Array(values.signatureFile) : undefined);
            if (!dataBuf || dataBuf.length === 0) {
                throw new Error(t("pgpVerify.dataRequired"));
            }
            if (!sigBuf || sigBuf.length === 0) {
                throw new Error(t("pgpVerify.signatureRequired"));
            }

            const request = await signature_verify_ttlv_request(id, dataBuf, sigBuf, undefined, false);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result = await parse_signature_verify_ttlv_response(result_str);
                return `${t("pgpVerify.success")}: ${result.ValidityIndicator}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pgpVerify.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pgpVerify.intro")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("pgpVerify.note")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pgpVerify.dataFile")}</h3>
                        <Form.Item name="dataFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="dataFile" rules={[{ required: true, message: t("pgpVerify.pleaseSelectDataFile") }]}>
                            <FormUploadDragger
                                beforeUpload={(file) => {
                                    form.setFieldValue("dataFileName", file.name);
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            setDataBytes(bytes);
                                            form.setFieldsValue({ dataFile: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">{t("pgpVerify.uploadDataText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pgpVerify.signatureFile")}</h3>
                        <Form.Item name="signatureFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="signatureFile" rules={[{ required: true, message: t("pgpVerify.pleaseSelectSignatureFile") }]}>
                            <FormUploadDragger
                                beforeUpload={(file) => {
                                    form.setFieldValue("signatureFileName", file.name);
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            setSigBytes(bytes);
                                            form.setFieldsValue({ signatureFile: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">{t("pgpVerify.uploadSignatureText")}</p>
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
                            {t("pgpVerify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("pgpVerify.responseTitle")} />
        </div>
    );
};

export default PgpVerifyForm;
