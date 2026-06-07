import { Button, Card, Form, Input, Select, Space, Tag } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import KeyIdInput from "../../components/common/KeyIdInput";

interface MacVerifyFormData {
    keyId?: string;
    tags?: string[];
    algorithm: string;
    data: string;
    macData: string;
}

const MAC_HASHING_ALGORITHMS = [
    { label: "SHA-1", value: "SHA1" },
    { label: "SHA-224", value: "SHA224" },
    { label: "SHA-256", value: "SHA256" },
    { label: "SHA-384", value: "SHA384" },
    { label: "SHA-512", value: "SHA512" },
    { label: "SHA3-224", value: "SHA3224" },
    { label: "SHA3-256", value: "SHA3256" },
    { label: "SHA3-384", value: "SHA3384" },
    { label: "SHA3-512", value: "SHA3512" },
];

const buildMacVerifyRequest = (keyId: string, algorithm: string, dataHex: string, macDataHex: string) => ({
    tag: "MACVerify",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        {
            tag: "CryptographicParameters",
            type: "Structure",
            value: [{ tag: "HashingAlgorithm", type: "Enumeration", value: algorithm }],
        },
        { tag: "Data", type: "ByteString", value: dataHex },
        { tag: "MACData", type: "ByteString", value: macDataHex },
    ],
});

const MacVerifyForm: React.FC = () => {
    const [form] = Form.useForm<MacVerifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [isValid, setIsValid] = useState<boolean | undefined>(undefined);

    const onFinish = async (values: MacVerifyFormData) => {
        setIsValid(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("macVerify.missingKeyId"));
            }
            const request = buildMacVerifyRequest(id, values.algorithm, values.data, values.macData);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = JSON.parse(result_str) as { tag?: string; value?: Array<{ tag: string; type: string; value: unknown }> };
                const validityItem = response.value?.find((item) => item.tag === "ValidityIndicator");
                if (validityItem) {
                    const valid = validityItem.value === "Valid" || validityItem.value === true;
                    setIsValid(valid);
                    return valid ? t("macVerify.valid") : t("macVerify.invalid");
                } else {
                    return t("macVerify.responseRaw", { response: result_str });
                }
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("macVerify.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("macVerify.intro")}</p>
                <p>{t("macVerify.introHex")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ algorithm: "SHA256" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("macVerify.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="SymmetricKey"
                        />
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="algorithm"
                            label={t("macVerify.hashingAlgorithm")}
                            rules={[{ required: true, message: t("macVerify.pleaseSelectHashingAlgorithm") }]}
                            help={t("macVerify.hashingAlgorithmHelp")}
                        >
                            <Select data-testid="mac-verify-algorithm-select" options={MAC_HASHING_ALGORITHMS} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="data"
                            label={t("macVerify.dataLabel")}
                            rules={[
                                { required: true, message: t("macVerify.pleaseEnterData") },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: t("macVerify.dataHexError"),
                                },
                            ]}
                            help={t("macVerify.dataHelp")}
                        >
                            <Input.TextArea rows={4} placeholder={t("macVerify.dataPlaceholder")} />
                        </Form.Item>

                        <Form.Item
                            name="macData"
                            label={t("macVerify.macDataLabel")}
                            rules={[
                                { required: true, message: t("macVerify.pleaseEnterMacData") },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: t("macVerify.macDataHexError"),
                                },
                            ]}
                            help={t("macVerify.macDataHelp")}
                        >
                            <Input.TextArea rows={3} placeholder={t("macVerify.macDataPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("macVerify.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800">
                    {isValid !== undefined && (
                        <div className="mb-2">
                            <Tag color={isValid ? "success" : "error"} style={{ fontSize: "1rem", padding: "4px 12px" }}>
                                {isValid ? t("macVerify.validTag") : t("macVerify.invalidTag")}
                            </Tag>
                        </div>
                    )}
                    <pre className="whitespace-pre-wrap text-sm break-all">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default MacVerifyForm;
