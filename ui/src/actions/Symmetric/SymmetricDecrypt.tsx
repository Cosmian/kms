import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import KeyIdInput from "../../components/common/KeyIdInput";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { getMimeType, saveDecryptedFile, sendKmipRequest } from "../../utils/utils";
import { decrypt_sym_ttlv_request, parse_decrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SymmetricDecryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: "AesGcm" | "AesXts" | "AesGcmSiv" | "Chacha20Poly1305" | "AesCbc";
    outputFile?: string;
    authenticationData?: Uint8Array;
}

const SymmetricDecryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricDecryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const selectedEncryptionAlgorithm = Form.useWatch("dataEncryptionAlgorithm", form);
    const { t } = useTranslation("actions");
    const DATA_ENCRYPTION_ALGORITHMS = [
        { label: t("symmetricDecrypt.algorithmDefault", { algorithm: "AES-GCM" }), value: "AesGcm" },
        { label: "AES-CBC", value: "AesCbc" },
        { label: "AES-XTS", value: "AesXts" },
        { label: "AES-GCM-SIV", value: "AesGcmSiv" },
        { label: "ChaCha20-Poly1305", value: "Chacha20Poly1305" },
    ];

    const onFinish = async (values: SymmetricDecryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("symmetricDecrypt.missingKeyId"));
            }
            const request = decrypt_sym_ttlv_request(id, values.inputFile, values.authenticationData, values.dataEncryptionAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const name = values.fileName.slice(0, -4);
                const lastDotIndex = name.lastIndexOf(".");
                const fileName = lastDotIndex !== -1 ? name : `${name}.plain`;
                const mimeType = getMimeType(fileName);
                saveDecryptedFile(response.Data, fileName, mimeType);
                return t("symmetricDecrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("symmetricDecrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("symmetricDecrypt.intro")}</p>
                <p>{t("symmetricDecrypt.introTwoWays")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("symmetricDecrypt.serverSide")}</li>
                    <li>{t("symmetricDecrypt.clientSide")}</li>
                </ul>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("symmetricDecrypt.note")}</p>
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
                        <h3 className="text-m font-bold mb-4">{t("symmetricDecrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("symmetricDecrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("symmetricDecrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("symmetricDecrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("symmetricDecrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="dataEncryptionAlgorithm"
                            label={t("symmetricDecrypt.dataEncryptionAlgorithm")}
                            rules={[{ required: true }]}
                            help={t("symmetricDecrypt.algorithmHelp")}
                        >
                            <Select options={DATA_ENCRYPTION_ALGORITHMS} />
                        </Form.Item>

                        {selectedEncryptionAlgorithm !== "AesXts" && selectedEncryptionAlgorithm !== "AesCbc" && (
                            <Form.Item
                                name="authenticationData"
                                label={t("symmetricDecrypt.authenticationData")}
                                help={t("symmetricDecrypt.authenticationDataHelp")}
                            >
                                <Input placeholder={t("symmetricDecrypt.enterAuthenticationData")} />
                            </Form.Item>
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
                            {t("symmetricDecrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("symmetricDecrypt.responseTitle")} />
        </div>
    );
};

export default SymmetricDecryptForm;
