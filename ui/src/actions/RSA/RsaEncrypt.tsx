import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import KeyIdInput from "../../components/common/KeyIdInput";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_rsa_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface RsaEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
    hashingAlgorithm: "Sha1" | "Sha224" | "Sha256" | "Sha384" | "Sha512";
}

const HASH_ALGORITHMS = [
    { label: "SHA-1", value: "Sha1" },
    { label: "SHA-224", value: "Sha224" },
    { label: "SHA-256", value: "Sha256" },
    { label: "SHA-384", value: "Sha384" },
    { label: "SHA-512", value: "Sha512" },
];

const RsaEncryptForm: React.FC = () => {
    const [form] = Form.useForm<RsaEncryptFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const encryptionAlgorithms = [
        { label: t("rsaEncrypt.algorithmRsaPkcs"), value: "CkmRsaPkcs" },
        { label: t("rsaEncrypt.algorithmRsaOaep"), value: "CkmRsaPkcsOaep" },
        { label: t("rsaEncrypt.algorithmRsaAesKeyWrap"), value: "CkmRsaAesKeyWrap" },
    ];

    const onFinish = async (values: RsaEncryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("rsaEncrypt.missingKeyId"));
            }
            const request = encrypt_rsa_ttlv_request(id, values.inputFile, values.encryptionAlgorithm, values.hashingAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const data = new Uint8Array(response.Data);
                const mimeType = "application/octet-stream";
                const filename = `${values.fileName}.enc`;
                downloadFile(data, filename, mimeType);
                return t("rsaEncrypt.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("rsaEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("rsaEncrypt.intro")}</p>
                <p>{t("rsaEncrypt.introKey")}</p>
                <p className="text-sm text-yellow-600 dark:text-yellow-400">{t("rsaEncrypt.note")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    encryptionAlgorithm: "CkmRsaPkcsOaep",
                    hashingAlgorithm: "Sha256",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("rsaEncrypt.inputFile")}</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: t("rsaEncrypt.pleaseSelectFile") }]}>
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
                                <p className="ant-upload-text">{t("rsaEncrypt.uploadText")}</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("rsaEncrypt.keyIdentification")}</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("rsaEncrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="PublicKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("rsaEncrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="encryptionAlgorithm"
                            label={t("rsaEncrypt.encryptionAlgorithm")}
                            rules={[{ required: true }]}
                            help={t("rsaEncrypt.encryptionAlgorithmHelp")}
                        >
                            <Select options={encryptionAlgorithms} />
                        </Form.Item>

                        <Form.Item
                            name="hashingAlgorithm"
                            label={t("rsaEncrypt.hashingAlgorithm")}
                            rules={[{ required: true }]}
                            help={t("rsaEncrypt.hashingAlgorithmHelp")}
                        >
                            <Select options={HASH_ALGORITHMS} />
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
                            {t("rsaEncrypt.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("rsaEncrypt.responseTitle")} />
        </div>
    );
};

export default RsaEncryptForm;
