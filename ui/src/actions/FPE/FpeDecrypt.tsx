import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface FpeDecryptFormData {
    keyId?: string;
    tags?: string[];
    dataType: string;
    alphabet?: string;
    tweak?: string;
    ciphertext: string;
}

/** Build the authenticated_data bytes that the KMS server expects for FPE. */
function buildAuthenticatedData(dataType: string, alphabet?: string): Uint8Array | undefined {
    if (dataType === "text") {
        const alpha = alphabet ?? "alpha_numeric";
        return new TextEncoder().encode(alpha);
    }
    if (dataType === "integer") {
        const alpha = alphabet ?? "numeric";
        const json = JSON.stringify({ type: "integer", alphabet: alpha });
        return new TextEncoder().encode(json);
    }
    if (dataType === "float") {
        const json = JSON.stringify({ type: "float" });
        return new TextEncoder().encode(json);
    }
    return undefined;
}

const HEX_RE = /^[0-9a-fA-F]*$/;

/**
 * Validate and decode a hex string to Uint8Array.
 * Returns undefined if the input is empty.
 * Throws if the length is odd or contains non-hex characters.
 */
function hexToBytes(hex: string, t: (key: string) => string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error(t("fpeDecrypt.tweakEvenHexError"));
    }
    if (!HEX_RE.test(hex)) {
        throw new Error(t("fpeDecrypt.tweakHexCharsError"));
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

const FpeDecryptForm: React.FC = () => {
    const [form] = Form.useForm<FpeDecryptFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const dataType = Form.useWatch("dataType", form);
    const DATA_TYPES = [
        { label: t("fpeDecrypt.dataTypeText"), value: "text" },
        { label: t("fpeDecrypt.dataTypeInteger"), value: "integer" },
        { label: t("fpeDecrypt.dataTypeFloat"), value: "float" },
    ];
    const ALPHABET_PRESETS = [
        { label: t("fpeDecrypt.alphabetAlphaNumeric"), value: "alpha_numeric" },
        { label: t("fpeDecrypt.alphabetNumeric"), value: "numeric" },
        { label: t("fpeDecrypt.alphabetAlphaLower"), value: "alpha_lower" },
        { label: t("fpeDecrypt.alphabetAlphaUpper"), value: "alpha_upper" },
        { label: t("fpeDecrypt.alphabetAlpha"), value: "alpha" },
        { label: t("fpeDecrypt.alphabetHexaDecimal"), value: "hexa_decimal" },
        { label: t("fpeDecrypt.alphabetChinese"), value: "chinese" },
        { label: t("fpeDecrypt.alphabetLatin1Sup"), value: "latin1sup" },
    ];

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        if (dataType === "text") {
            form.setFieldValue("alphabet", "alpha_numeric");
        } else if (dataType === "integer") {
            form.setFieldValue("alphabet", "numeric");
        }
    }, [dataType, form]);

    const onFinish = async (values: FpeDecryptFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            // Validate tweak early so we get a clear error even if key ID is missing
            const tweak = values.tweak ? hexToBytes(values.tweak, t) : undefined;

            const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
            if (id === undefined) {
                setRes(`${t("common:errorPrefix")}${t("fpeDecrypt.missingKeyId")}`);
                return;
            }
            const w = wasm as unknown as {
                decrypt_fpe_ttlv_request?: (
                    keyId: string,
                    ciphertext: Uint8Array,
                    tweak: Uint8Array | undefined,
                    authenticatedData: Uint8Array | undefined,
                ) => object;
            };
            if (!w.decrypt_fpe_ttlv_request) {
                setRes(`${t("common:errorPrefix")}${t("fpeDecrypt.wasmUnavailable")}`);
                return;
            }

            const ciphertext = new TextEncoder().encode(values.ciphertext);
            const authenticatedData = buildAuthenticatedData(values.dataType, values.alphabet);

            const request = w.decrypt_fpe_ttlv_request(id, ciphertext, tweak, authenticatedData);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasm.parse_decrypt_ttlv_response(result_str);
                const typed = response as { Data?: number[] };
                if (typed.Data) {
                    const resultText = new TextDecoder().decode(new Uint8Array(typed.Data));
                    setRes(t("fpeDecrypt.plaintext", { value: resultText }));
                } else {
                    setRes(`${t("common:errorPrefix")}${t("fpeDecrypt.emptyResponse")}`);
                }
            } else {
                setRes(`${t("common:errorPrefix")}${t("fpeDecrypt.noResponse")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("FPE decrypt error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("fpeDecrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("fpeDecrypt.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("fpeDecrypt.bullet1")}</li>
                    <li>{t("fpeDecrypt.bullet2")}</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ dataType: "text", alphabet: "alpha_numeric" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="ciphertext"
                            label={t("fpeDecrypt.ciphertext")}
                            rules={[{ required: true, message: t("fpeDecrypt.pleaseEnterCiphertext") }]}
                            help={t("fpeDecrypt.ciphertextHelp")}
                        >
                            <Input.TextArea data-testid="fpe-ciphertext" placeholder={t("fpeDecrypt.ciphertextPlaceholder")} rows={3} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("fpeDecrypt.keyIdentification")}</h3>
                        <Form.Item name="keyId" label={t("common:keyId")} help={t("fpeDecrypt.keyIdHelp")}>
                            <Input placeholder={t("common:enterKeyId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("fpeDecrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="dataType"
                            label={t("fpeDecrypt.dataType")}
                            rules={[{ required: true }]}
                            help={t("fpeDecrypt.dataTypeHelpDecrypt")}
                        >
                            <Select data-testid="fpe-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        {dataType === "text" && (
                            <Form.Item name="alphabet" label={t("fpeDecrypt.alphabet")} help={t("fpeDecrypt.alphabetHelpText")}>
                                <Select data-testid="fpe-alphabet-select" options={ALPHABET_PRESETS} />
                            </Form.Item>
                        )}

                        {dataType === "integer" && (
                            <Form.Item
                                name="alphabet"
                                label={t("fpeDecrypt.radixAlphabet")}
                                help={t("fpeDecrypt.radixAlphabetHelpInteger")}
                            >
                                <Select
                                    data-testid="fpe-alphabet-select"
                                    options={[
                                        { label: t("fpeDecrypt.alphabetNumericBase10"), value: "numeric" },
                                        { label: t("fpeDecrypt.alphabetHexaDecimalBase16"), value: "hexa_decimal" },
                                    ]}
                                />
                            </Form.Item>
                        )}

                        <Form.Item name="tweak" label={t("fpeDecrypt.tweak")} help={t("fpeDecrypt.tweakHelp")}>
                            <Input placeholder={t("fpeDecrypt.tweakPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("fpeDecrypt.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("fpeDecrypt.success")}
                        description={
                            <div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">
                                {res}
                            </div>
                        }
                        type={res.startsWith(t("common:errorPrefix")) ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default FpeDecryptForm;
