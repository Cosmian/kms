import { Button, Card, Form, Input, Select, Space, Switch } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import * as wasmClient from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface ECVerifyFormData {
    dataFile: Uint8Array;
    dataFileName: string;
    signatureFile: Uint8Array;
    signatureFileName: string;
    keyId?: string;
    tags?: string[];
    digested: boolean;
}

const ECVerifyForm: React.FC = () => {
    const [form] = Form.useForm<ECVerifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [dataBytes, setDataBytes] = useState<Uint8Array | undefined>(undefined);
    const [sigBytes, setSigBytes] = useState<Uint8Array | undefined>(undefined);

    const onFinish = async (values: ECVerifyFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("ecVerify.missingKeyId"));
            }
            const dataBuf = dataBytes ?? (values.dataFile ? new Uint8Array(values.dataFile) : undefined);
            let sigBuf = sigBytes ?? (values.signatureFile ? new Uint8Array(values.signatureFile) : undefined);
            // Try to extract and decode Base64/hex automatically; if it fails, keep original bytes
            if (sigBuf && sigBuf.byteLength > 0) {
                try {
                    const text = new TextDecoder().decode(sigBuf).trim();
                    const base64Candidates = Array.from(text.matchAll(/[A-Za-z0-9+/=]{16,}/g)).map((m) => m[0]);
                    let candidate = text;
                    if (base64Candidates.length > 0) {
                        candidate = base64Candidates.sort((a, b) => b.length - a.length)[0];
                    }
                    let decoded: Uint8Array | undefined;
                    try {
                        decoded = Uint8Array.from(atob(candidate), (c) => c.charCodeAt(0));
                    } catch {
                        decoded = undefined;
                    }
                    if (!decoded) {
                        const hex = candidate.replace(/^0x/i, "");
                        if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
                            const out = new Uint8Array(hex.length / 2);
                            for (let i = 0; i < hex.length; i += 2) {
                                out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
                            }
                            decoded = out;
                        }
                    }
                    if (decoded && decoded.byteLength > 0) {
                        sigBuf = decoded;
                    }
                } catch {
                    // Ignore decode issues; keep original bytes
                }
            }
            console.debug("ECVerify: dataBuf len", dataBuf?.byteLength ?? 0, "sigBuf len", sigBuf?.byteLength ?? 0);
            if (!sigBuf || sigBuf.byteLength === 0) {
                throw new Error(`${t("common:errorPrefix")}${t("ecVerify.emptySignature")}`);
            }
            const request = wasmClient.signature_verify_ttlv_request(id, dataBuf!, sigBuf, undefined, values.digested);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasmClient.parse_signature_verify_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const validityRaw = respObj.ValidityIndicator ?? respObj.validity_indicator ?? respObj.validityIndicator;
                const validity = typeof validityRaw === "string" ? validityRaw : String(validityRaw ?? "Unknown");
                return t("ecVerify.validity", { validity });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("ecVerify.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("ecVerify.intro")}</p>
                <p>{t("ecVerify.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ digested: false }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("ecVerify.dataFile")}</h3>
                        <Form.Item name="dataFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="dataFile" rules={[{ required: true, message: t("ecVerify.pleaseSelectDataFile") }]}>
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
                                <p className="ant-upload-text">{t("ecVerify.uploadDataText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("ecVerify.signatureFile")}</h3>
                        <Form.Item name="signatureFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="signatureFile" rules={[{ required: true, message: t("ecVerify.pleaseSelectSignatureFile") }]}>
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
                                <p className="ant-upload-text">{t("ecVerify.uploadSignatureText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("ecVerify.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="PublicKey"
                        />
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        {/* Curve and signature algorithm are determined by key type (ECDSA). */}
                        <Form.Item name="digested" label={t("ecVerify.dataIsDigested")} valuePropName="checked">
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
                            {t("ecVerify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("ecVerify.responseTitle")} />
        </div>
    );
};

export default ECVerifyForm;
