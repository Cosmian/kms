import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import * as wasmClient from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface PqcSignFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
}

const PqcSignForm: React.FC = () => {
    const [form] = Form.useForm<PqcSignFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: PqcSignFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pqcSign.missingKeyId"));
            }
            // ML-DSA sign: no crypto parameters needed, not digested
            const request = await wasmClient.sign_ttlv_request(id, values.inputFile, undefined, false);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasmClient.parse_sign_ttlv_response(result_str);
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
                return t("pqcSign.success", { size: signature.byteLength });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pqcSign.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pqcSign.intro")}</p>
                <p>{t("pqcSign.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcSign.inputFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: t("pqcSign.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("pqcSign.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("pqcSign.privateKeyId")}
                            help={t("pqcSign.privateKeyIdHelp")}
                            placeholder={t("pqcSign.enterPrivateKeyId")}
                            objectType="PrivateKey"
                        />
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
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
                            {t("pqcSign.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("pqcSign.responseTitle")} />
        </div>
    );
};

export default PqcSignForm;
