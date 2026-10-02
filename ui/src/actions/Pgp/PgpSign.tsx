import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import KeyIdInput from "../../components/common/KeyIdInput";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { parse_sign_ttlv_response, sign_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PgpSignFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
}

const PgpSignForm: React.FC = () => {
    const [form] = Form.useForm<PgpSignFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: PgpSignFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pgpSign.missingKeyId"));
            }
            const request = await sign_ttlv_request(id, values.inputFile, undefined, false);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_sign_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const sigCandidate = respObj.SignatureData ?? respObj.signature_data ?? respObj.signatureData;
                let signature: Uint8Array;
                if (sigCandidate instanceof Uint8Array) {
                    signature = sigCandidate;
                } else if (Array.isArray(sigCandidate)) {
                    signature = new Uint8Array(sigCandidate as number[]);
                } else if (typeof sigCandidate === "string") {
                    const base64 = sigCandidate.trim();
                    signature = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
                } else {
                    signature = new Uint8Array();
                }
                const filename = `${values.fileName}.sig`;
                downloadFile(signature, filename, "application/octet-stream");
                return t("pgpSign.success", { size: signature.byteLength });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pgpSign.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pgpSign.intro")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pgpSign.inputFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: t("pgpSign.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("pgpSign.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>

                    <Card>
                        <KeyIdInput form={form} objectType="PGPKey" />
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                            {t("pgpSign.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("pgpSign.responseTitle")} />
        </div>
    );
};

export default PgpSignForm;
