import { Button, Card, Form, Input, Radio, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";

interface SymmetricHashFormData {
    inputMode: "file" | "text";
    inputFile?: Uint8Array;
    fileName?: string;
    inputText?: string;
    hashAlgorithm: string;
}

const SymmetricHashForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricHashFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const inputMode = Form.useWatch("inputMode", form);
    const [algorithmOptions, setAlgorithmOptions] = useState<{ value: string; label: string }[]>([]);
    const { t } = useTranslation("actions");

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_hash_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_hash_algorithms ? w.get_hash_algorithms() : [];
            setAlgorithmOptions(opts);
        } catch (e) {
            console.error("Error loading hash algorithms from WASM:", e);
        }
    }, []);

    const onFinish = async (values: SymmetricHashFormData) => {
        await execute(async () => {
            let data: Uint8Array;
            if (values.inputMode === "file") {
                if (!values.inputFile || values.inputFile.byteLength === 0) {
                    return t("symmetricHash.pleaseSelectFileError");
                }
                data = values.inputFile;
            } else {
                if (!values.inputText) {
                    return t("symmetricHash.pleaseEnterTextError");
                }
                data = new TextEncoder().encode(values.inputText);
            }

            const request = wasm.hash_ttlv_request(data, values.hashAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = wasm.parse_hash_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const hashData = respObj.data ?? respObj.Data;
                let hashBytes: Uint8Array;
                if (hashData instanceof Uint8Array) {
                    hashBytes = hashData;
                } else if (Array.isArray(hashData)) {
                    hashBytes = new Uint8Array(hashData as number[]);
                } else {
                    hashBytes = new Uint8Array();
                }
                const hexHash = Array.from(hashBytes)
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");
                return hexHash;
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("symmetricHash.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("symmetricHash.intro")}</p>
                <p>{t("symmetricHash.introTwoWays")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    inputMode: "file",
                    hashAlgorithm: "SHA256",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="inputMode" label={t("symmetricHash.inputMode")}>
                            <Radio.Group>
                                <Radio value="file">{t("symmetricHash.fileMode")}</Radio>
                                <Radio value="text">{t("symmetricHash.textMode")}</Radio>
                            </Radio.Group>
                        </Form.Item>

                        {inputMode === "file" ? (
                            <>
                                <Form.Item name="fileName" style={{ display: "none" }}>
                                    <Input />
                                </Form.Item>
                                <Form.Item
                                    name="inputFile"
                                    rules={[{ required: inputMode === "file", message: t("symmetricHash.pleaseSelectFile") }]}
                                >
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
                                        <p className="ant-upload-text">{t("symmetricHash.uploadText")}</p>
                                    </FormUploadDragger>
                                </Form.Item>
                            </>
                        ) : (
                            <Form.Item
                                name="inputText"
                                label={t("symmetricHash.textInput")}
                                rules={[{ required: inputMode === "text", message: t("symmetricHash.pleaseEnterText") }]}
                            >
                                <Input.TextArea rows={4} placeholder={t("symmetricHash.enterText")} />
                            </Form.Item>
                        )}
                    </Card>

                    <Card>
                        <Form.Item
                            name="hashAlgorithm"
                            label={t("symmetricHash.hashAlgorithm")}
                            rules={[{ required: true }]}
                            help={t("symmetricHash.hashAlgorithmHelp")}
                        >
                            <Select options={algorithmOptions} data-testid="hash-algorithm-select" />
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
                            {t("symmetricHash.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={t("symmetricHash.resultTitle")}>
                        <p className="font-mono break-all">{res}</p>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default SymmetricHashForm;
