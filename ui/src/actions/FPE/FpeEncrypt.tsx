import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/useAuth";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface FpeEncryptFormData {
    keyId?: string;
    tags?: string[];
    dataType: string;
    alphabet?: string;
    tweak?: string;
    plaintext: string;
}

const DATA_TYPES = [
    { label: "Text", value: "text" },
    { label: "Integer", value: "integer" },
    { label: "Float", value: "float" },
];

const ALPHABET_PRESETS = [
    { label: "Alpha-numeric (a-z A-Z 0-9)", value: "alpha_numeric" },
    { label: "Numeric (0-9)", value: "numeric" },
    { label: "Alpha lower (a-z)", value: "alpha_lower" },
    { label: "Alpha upper (A-Z)", value: "alpha_upper" },
    { label: "Alpha (a-z A-Z)", value: "alpha" },
    { label: "Hexadecimal (0-9 a-f)", value: "hexa_decimal" },
    { label: "Chinese", value: "chinese" },
    { label: "Latin-1 Supplement", value: "latin1sup" },
];

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
function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Tweak hex string must have an even number of characters.");
    }
    if (!HEX_RE.test(hex)) {
        throw new Error("Tweak contains invalid hex characters (only 0-9 a-f A-F are allowed).");
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
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const dataType = Form.useWatch("dataType", form);

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
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            // Validate tweak format before anything else so the error is always visible.
            if (values.tweak) {
                if (values.tweak.length % 2 !== 0) {
                    setRes("Error: Tweak must have an even number of hex digits.");
                    return;
                }
                if (!/^[0-9a-fA-F]+$/.test(values.tweak)) {
                    setRes("Error: Tweak must contain only hex characters (0-9 a-f A-F).");
                    return;
                }
            }
            if (id == undefined) {
                setRes("Error: Missing key identifier.");
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
                setRes("Error: WASM FPE functions not available. Rebuild WASM with non-fips feature.");
                return;
            }

            const plaintext = new TextEncoder().encode(values.plaintext);
            const tweak = values.tweak ? hexToBytes(values.tweak) : undefined;
            const authenticatedData = buildAuthenticatedData(values.dataType, values.alphabet);

            const request = w.encrypt_fpe_ttlv_request(id, plaintext, tweak, authenticatedData);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await wasm.parse_encrypt_ttlv_response(result_str);
                const typed = response as { Data?: number[] };
                if (typed.Data) {
                    const resultText = new TextDecoder().decode(new Uint8Array(typed.Data));
                    setRes(`Ciphertext: ${resultText}`);
                } else {
                    setRes("Error: Empty response from server.");
                }
            }
        } catch (e) {
            setRes(`Error: ${e}`);
            console.error("FPE encrypt error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">FPE Encrypt</h1>

            <div className="mb-8 space-y-2">
                <p>Encrypt data using Format-Preserving Encryption (FPE-FF1).</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>FPE preserves the format of the input data (e.g. a credit card number stays a credit card number).</li>
                    <li>Non-alphabet characters (spaces, dashes, punctuation) are preserved in place.</li>
                    <li>The tweak is an optional context parameter (hex-encoded).</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ dataType: "text", alphabet: "alpha_numeric" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="plaintext"
                            label="Plaintext"
                            rules={[{ required: true, message: "Please enter the text to encrypt" }]}
                            help="The data to encrypt (text, integer, or float)"
                        >
                            <Input.TextArea data-testid="fpe-plaintext" placeholder="e.g. 1234-5678-9012-3456" rows={3} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the FPE key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="dataType" label="Data Type" rules={[{ required: true }]} help="The type of data being encrypted">
                            <Select data-testid="fpe-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        {dataType === "text" && (
                            <Form.Item
                                name="alphabet"
                                label="Alphabet"
                                help="Characters that can appear in the plaintext (non-alphabet chars are preserved)"
                            >
                                <Select data-testid="fpe-alphabet-select" options={ALPHABET_PRESETS} />
                            </Form.Item>
                        )}

                        {dataType === "integer" && (
                            <Form.Item
                                name="alphabet"
                                label="Radix Alphabet"
                                help="Radix alphabet for integer encryption (default: numeric / base-10)"
                            >
                                <Select
                                    data-testid="fpe-alphabet-select"
                                    options={[
                                        { label: "Numeric (base-10)", value: "numeric" },
                                        { label: "Hexadecimal (base-16)", value: "hexa_decimal" },
                                    ]}
                                />
                            </Form.Item>
                        )}

                        <Form.Item name="tweak" label="Tweak (hex)" help="Optional tweak bytes as a hex string (e.g. aabbccdd)">
                            <Input placeholder="e.g. aabbccdd" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Encrypt (FPE)
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith("Error") ? "Error" : "Success"}
                        description={
                            <div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">
                                {res}
                            </div>
                        }
                        type={res.startsWith("Error") ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default FpeEncryptForm;
