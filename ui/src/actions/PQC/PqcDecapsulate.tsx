import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { decrypt_ec_ttlv_request, parse_decrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface PqcDecapsulateFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
}

const PqcDecapsulateForm: React.FC = () => {
    const [form] = Form.useForm<PqcDecapsulateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: PqcDecapsulateFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pqcDecapsulate.missingKeyId"));
            }
            const request = decrypt_ec_ttlv_request(id, values.inputFile);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const data = respObj.Data as Uint8Array | number[] | undefined;
                if (data) {
                    const ssBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
                    downloadFile(ssBytes, "shared_secret.key", "application/octet-stream");
                    return t("pqcDecapsulate.success", { size: ssBytes.byteLength });
                } else {
                    return t("pqcDecapsulate.emptyData");
                }
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pqcDecapsulate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pqcDecapsulate.intro")}</p>
                <p>{t("pqcDecapsulate.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcDecapsulate.encapsulationFile")}</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: t("pqcDecapsulate.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("pqcDecapsulate.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("pqcDecapsulate.privateKeyId")}
                            help={t("pqcDecapsulate.privateKeyIdHelp")}
                            placeholder={t("pqcDecapsulate.enterPrivateKeyId")}
                            objectType="PrivateKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("pqcDecapsulate.tagsHelp")}>
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
                            {t("pqcDecapsulate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("pqcDecapsulate.responseTitle")} />
        </div>
    );
};

export default PqcDecapsulateForm;
