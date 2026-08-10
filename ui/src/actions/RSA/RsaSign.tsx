import { Button, Card, Form, Input, Select, Space, Switch } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { parse_sign_ttlv_response, sign_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface RsaSignFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    digested: boolean;
}

const RsaSignForm: React.FC = () => {
    const [form] = Form.useForm<RsaSignFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: RsaSignFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("rsaSign.missingKeyId"));
            }
            const request = await sign_ttlv_request(id, values.inputFile, undefined, values.digested);
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
                console.debug("RsaSign: signature length", signature.byteLength);
                downloadFile(signature, filename, "application/octet-stream");
                return t("rsaSign.success", { size: signature.byteLength });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("rsaSign.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("rsaSign.intro")}</p>
                <p>{t("rsaSign.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ digested: false }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("rsaSign.inputFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: t("rsaSign.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("rsaSign.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("rsaSign.keyIdentification")}</h3>
                        <Form.Item name="keyId" label={t("common:keyId")} help={t("rsaSign.keyIdHelp")}>
                            <Input placeholder={t("common:enterKeyId")} />
                        </Form.Item>
                        <Form.Item name="tags" label={t("common:tags")} help={t("rsaSign.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item name="digested" label={t("rsaSign.inputIsDigested")} valuePropName="checked">
                            <Switch />
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
                            {t("rsaSign.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("rsaSign.responseTitle")} />
        </div>
    );
};

export default RsaSignForm;
