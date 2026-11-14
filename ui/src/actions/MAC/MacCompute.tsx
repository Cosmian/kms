import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import KeyIdInput from "../../components/common/KeyIdInput";
import { buildCryptographicParameters, MAC_HASHING_ALGORITHMS, MAC_TYPES, type MacType } from "./macParams";

interface MacComputeFormData {
    keyId?: string;
    tags?: string[];
    macType: MacType;
    algorithm: string;
    data: string;
}

const buildMacRequest = (keyId: string, macType: MacType, algorithm: string, dataHex: string) => ({
    tag: "Mac",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        buildCryptographicParameters(macType, algorithm),
        { tag: "Data", type: "ByteString", value: dataHex },
    ],
});

const MacComputeForm: React.FC = () => {
    const [form] = Form.useForm<MacComputeFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const macType = Form.useWatch("macType", form) ?? "HMAC";

    const onFinish = async (values: MacComputeFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("macCompute.missingKeyId"));
            }
            const request = buildMacRequest(id, values.macType, values.algorithm, values.data);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = JSON.parse(result_str) as { tag?: string; value?: Array<{ tag: string; type: string; value: string }> };
                const dataItem = response.value?.find((item) => item.tag === "MACData");
                if (dataItem) {
                    return t("macCompute.successMac", { mac: dataItem.value });
                } else {
                    return t("macCompute.responseRaw", { response: result_str });
                }
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("macCompute.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("macCompute.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="macCompute.introHex" components={{ code: <code /> }} />
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ macType: "HMAC", algorithm: "SHA256" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("macCompute.keyIdentification")}</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("macCompute.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="SymmetricKey"
                        />
                        <Form.Item name="tags" label={t("common:tags")} help={t("macCompute.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="macType" label={t("macCompute.macType")} help={t("macCompute.macTypeHelp")}>
                            <Select data-testid="mac-type-select" options={MAC_TYPES} />
                        </Form.Item>
                        {macType === "HMAC" && (
                            <Form.Item
                                name="algorithm"
                                label={t("macCompute.hashingAlgorithm")}
                                rules={[{ required: true, message: t("macCompute.pleaseSelectHashingAlgorithm") }]}
                                help={t("macCompute.hashingAlgorithmHelp")}
                            >
                                <Select data-testid="mac-algorithm-select" options={MAC_HASHING_ALGORITHMS} />
                            </Form.Item>
                        )}
                        {macType === "AES-GMAC" && <p>{t("macCompute.gmacHelp")}</p>}
                    </Card>

                    <Card>
                        <Form.Item
                            name="data"
                            label={t("macCompute.dataLabel")}
                            rules={[
                                { required: true, message: t("macCompute.pleaseEnterData") },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: t("macCompute.dataHexError"),
                                },
                            ]}
                            help={t("macCompute.dataHelp")}
                        >
                            <Input.TextArea rows={4} placeholder={t("macCompute.dataPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("macCompute.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800 break-all">
                    <pre className="whitespace-pre-wrap text-sm">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default MacComputeForm;
