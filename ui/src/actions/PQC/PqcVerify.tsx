import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import * as wasmClient from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PqcVerifyFormData {
    dataFile: Uint8Array;
    dataFileName: string;
    signatureFile: Uint8Array;
    signatureFileName: string;
    keyId?: string;
    tags?: string[];
}

const PqcVerifyForm: React.FC = () => {
    const [form] = Form.useForm<PqcVerifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [dataBytes, setDataBytes] = useState<Uint8Array | undefined>(undefined);
    const [sigBytes, setSigBytes] = useState<Uint8Array | undefined>(undefined);

    const onFinish = async (values: PqcVerifyFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pqcVerify.missingKeyId"));
            }
            const dataBuf = dataBytes ?? (values.dataFile ? new Uint8Array(values.dataFile) : undefined);
            const sigBuf = sigBytes ?? (values.signatureFile ? new Uint8Array(values.signatureFile) : undefined);

            if (!sigBuf || sigBuf.byteLength === 0) {
                throw new Error(`${t("common:errorPrefix")}${t("pqcVerify.emptySignature")}`);
            }
            // ML-DSA verify: no crypto parameters needed, not digested
            const request = wasmClient.signature_verify_ttlv_request(id, dataBuf!, sigBuf, undefined, false);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasmClient.parse_signature_verify_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const validityRaw = respObj.ValidityIndicator ?? respObj.validity_indicator ?? respObj.validityIndicator;
                const validity = typeof validityRaw === "string" ? validityRaw : String(validityRaw ?? "Unknown");
                return t("pqcVerify.validity", { validity });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pqcVerify.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pqcVerify.intro")}</p>
                <p>{t("pqcVerify.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcVerify.dataFile")}</h3>
                        <Form.Item name="dataFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="dataFile" rules={[{ required: true, message: t("pqcVerify.pleaseSelectDataFile") }]}>
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
                                <p className="ant-upload-text">{t("pqcVerify.uploadDataText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcVerify.signatureFile")}</h3>
                        <Form.Item name="signatureFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="signatureFile" rules={[{ required: true, message: t("pqcVerify.pleaseSelectSignatureFile") }]}>
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
                                <p className="ant-upload-text">{t("pqcVerify.uploadSignatureText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcVerify.keyIdentification")}</h3>
                        <Form.Item name="keyId" label={t("pqcVerify.publicKeyId")} help={t("pqcVerify.publicKeyIdHelp")}>
                            <Input placeholder={t("pqcVerify.enterPublicKeyId")} />
                        </Form.Item>
                        <Form.Item name="tags" label={t("common:tags")} help={t("pqcVerify.tagsHelp")}>
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
                            {t("pqcVerify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("pqcVerify.responseTitle")} />
        </div>
    );
};

export default PqcVerifyForm;
