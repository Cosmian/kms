import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import KeyIdInput from "../../components/common/KeyIdInput";

interface FpeEncryptFormData {
    keyId?: string;
    tags?: string[];
    dataType: string;
    alphabet?: string;
    tweak?: string;
    plaintext: string;
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
        throw new Error(t("fpeEncrypt.tweakEvenHexError"));
    }
    if (!HEX_RE.test(hex)) {
        throw new Error(t("fpeEncrypt.tweakHexCharsError"));
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

const FpeEncryptForm: React.FC = () => {
    const [form] = Form.useForm<FpeEncryptFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const dataType = Form.useWatch("dataType", form);
    const DATA_TYPES = [
        { label: t("fpeEncrypt.dataTypeText"), value: "text" },
        { label: t("fpeEncrypt.dataTypeInteger"), value: "integer" },
        { label: t("fpeEncrypt.dataTypeFloat"), value: "float" },
    ];
    const ALPHABET_PRESETS = [
        { label: t("fpeEncrypt.alphabetAlphaNumeric"), value: "alpha_numeric" },
        { label: t("fpeEncrypt.alphabetNumeric"), value: "numeric" },
        { label: t("fpeEncrypt.alphabetAlphaLower"), value: "alpha_lower" },
        { label: t("fpeEncrypt.alphabetAlphaUpper"), value: "alpha_upper" },
        { label: t("fpeEncrypt.alphabetAlpha"), value: "alpha" },
        { label: t("fpeEncrypt.alphabetHexaDecimal"), value: "hexa_decimal" },
        { label: t("fpeEncrypt.alphabetChinese"), value: "chinese" },
        { label: t("fpeEncrypt.alphabetLatin1Sup"), value: "latin1sup" },
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

    const onFinish = async (values: FpeEncryptFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            // Validate tweak early so we get a clear error even if key ID is missing
            const tweak = values.tweak ? hexToBytes(values.tweak, t) : undefined;

            const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
            if (id === undefined) {
                setRes(`${t("common:errorPrefix")}${t("fpeEncrypt.missingKeyId")}`);
                return;
            }
            const w = wasm as unknown as {
                encrypt_fpe_ttlv_request?: (
                    keyId: string,
                    plaintext: Uint8Array,
                    tweak: Uint8Array | undefined,
                    authenticatedData: Uint8Array | undefined,
                ) => object;
            };
            if (!w.encrypt_fpe_ttlv_request) {
                setRes(`${t("common:errorPrefix")}${t("fpeEncrypt.wasmUnavailable")}`);
                return;
            }

            const plaintext = new TextEncoder().encode(values.plaintext);
            const authenticatedData = buildAuthenticatedData(values.dataType, values.alphabet);

            const request = w.encrypt_fpe_ttlv_request(id, plaintext, tweak, authenticatedData);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasm.parse_encrypt_ttlv_response(result_str);
                const typed = response as { Data?: number[] };
                if (typed.Data) {
                    const resultText = new TextDecoder().decode(new Uint8Array(typed.Data));
                    setRes(t("fpeEncrypt.ciphertext", { value: resultText }));
                } else {
                    setRes(`${t("common:errorPrefix")}${t("fpeEncrypt.emptyResponse")}`);
                }
            } else {
                setRes(`${t("common:errorPrefix")}${t("fpeEncrypt.noResponse")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("FPE encrypt error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("fpeEncrypt.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("fpeEncrypt.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("fpeEncrypt.bullet1")}</li>
                    <li>{t("fpeEncrypt.bullet2")}</li>
                    <li>{t("fpeEncrypt.bullet3")}</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ dataType: "text", alphabet: "alpha_numeric" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="plaintext"
                            label={t("fpeEncrypt.plaintext")}
                            rules={[{ required: true, message: t("fpeEncrypt.pleaseEnterPlaintext") }]}
                            help={t("fpeEncrypt.plaintextHelp")}
                        >
                            <Input.TextArea data-testid="fpe-plaintext" placeholder={t("fpeEncrypt.plaintextPlaceholder")} rows={3} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("common:keyId")}
                            help={t("fpeEncrypt.keyIdHelp")}
                            placeholder={t("common:enterKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("fpeEncrypt.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="dataType"
                            label={t("fpeEncrypt.dataType")}
                            rules={[{ required: true }]}
                            help={t("fpeEncrypt.dataTypeHelpEncrypt")}
                        >
                            <Select data-testid="fpe-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        {dataType === "text" && (
                            <Form.Item name="alphabet" label={t("fpeEncrypt.alphabet")} help={t("fpeEncrypt.alphabetHelpText")}>
                                <Select data-testid="fpe-alphabet-select" options={ALPHABET_PRESETS} />
                            </Form.Item>
                        )}

                        {dataType === "integer" && (
                            <Form.Item
                                name="alphabet"
                                label={t("fpeEncrypt.radixAlphabet")}
                                help={t("fpeEncrypt.radixAlphabetHelpInteger")}
                            >
                                <Select
                                    data-testid="fpe-alphabet-select"
                                    options={[
                                        { label: t("fpeEncrypt.alphabetNumericBase10"), value: "numeric" },
                                        { label: t("fpeEncrypt.alphabetHexaDecimalBase16"), value: "hexa_decimal" },
                                    ]}
                                />
                            </Form.Item>
                        )}

                        <Form.Item name="tweak" label={t("fpeEncrypt.tweak")} help={t("fpeEncrypt.tweakHelp")}>
                            <Input placeholder={t("fpeEncrypt.tweakPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("fpeEncrypt.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("fpeEncrypt.success")}
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

export default FpeEncryptForm;
