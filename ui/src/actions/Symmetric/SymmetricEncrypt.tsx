import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import KeyIdInput from "../../components/common/KeyIdInput";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_sym_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SymmetricEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: "AesGcm" | "AesGcmSiv" | "Chacha20Poly1305" | "AesXts" | "AesCbc";
    outputFile?: string;
    nonce?: Uint8Array;
    authenticationData?: Uint8Array;
}

const SymmetricEncryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricEncryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const selectedEncryptionAlgorithm = Form.useWatch("dataEncryptionAlgorithm", form);
    const { t } = useTranslation("actions");

    const onFinish = async (values: SymmetricEncryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("symmetricEncrypt.missingKeyId"));
            }
            const request = encrypt_sym_ttlv_request(
                id,
                undefined,
                values.inputFile,
                values.nonce,
                values.authenticationData,
                values.dataEncryptionAlgorithm,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const { IVCounterNonce, Data, AuthenticatedEncryptionTag } = await parse_encrypt_ttlv_response(result_str);
                const combinedData = new Uint8Array(IVCounterNonce.length + Data.length + AuthenticatedEncryptionTag.length);
                combinedData.set(IVCounterNonce, 0);
                combinedData.set(Data, IVCounterNonce.length);
                combinedData.set(AuthenticatedEncryptionTag, IVCounterNonce.length + Data.length);
                const mimeType = "application/octet-stream";
                const filename = `${values.fileName}.enc`;
                downloadFile(combinedData, filename, mimeType);
                return t("symmetricEncrypt.success");
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">{t("symmetricEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("symmetricEncrypt.intro")}</p>
                <p>{t("symmetricEncrypt.introTwoWays")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("symmetricEncrypt.serverSide")}</li>
                    <li>{t("symmetricEncrypt.clientSide")}</li>
                </ul>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("symmetricEncrypt.note")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    dataEncryptionAlgorithm: "AesGcm",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("symmetricEncrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("symmetricEncrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("symmetricEncrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("symmetricEncrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("symmetricEncrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="dataEncryptionAlgorithm"
                            label={t("symmetricEncrypt.dataEncryptionAlgorithm")}
                            rules={[{ required: true }]}
                            help={t("symmetricEncrypt.algorithmHelp")}
                        >
                            <Select>
                                <Select.Option value="AesGcm">AES-GCM</Select.Option>
                                <Select.Option value="AesGcmSiv">AES-GCM-SIV</Select.Option>
                                <Select.Option value="AesCbc">AES-CBC</Select.Option>
                                <Select.Option value="Chacha20Poly1305">ChaCha20-Poly1305</Select.Option>
                                <Select.Option value="AesXts">AES-XTS</Select.Option>
                            </Select>
                        </Form.Item>

                        {selectedEncryptionAlgorithm !== "AesXts" && selectedEncryptionAlgorithm !== "AesCbc" && (
                            <>
                                <Form.Item name="nonce" label={t("symmetricEncrypt.nonceIv")} help={t("symmetricEncrypt.nonceHelp")}>
                                    <Input placeholder={t("symmetricEncrypt.enterNonce")} />
                                </Form.Item>

                                <Form.Item
                                    name="authenticationData"
                                    label={t("symmetricEncrypt.authenticationData")}
                                    help={t("symmetricEncrypt.authenticationDataHelp")}
                                >
                                    <Input placeholder={t("symmetricEncrypt.enterAuthenticationData")} />
                                </Form.Item>
                            </>
                        )}
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("symmetricEncrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("symmetricEncrypt.responseTitle")} />
        </div>
    );
};

export default SymmetricEncryptForm;
