import { Button, Card, Form, Input, Select, Space, Switch, Upload } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import {
  parse_signature_verify_ttlv_response,
  signature_verify_ttlv_request,
} from "./wasm/pkg/cosmian_kms_client_wasm";

interface RsaVerifyFormData {
    dataFile: Uint8Array;
    dataFileName: string;
    signatureFile: Uint8Array;
    signatureFileName: string;
    keyId?: string;
    tags?: string[];
    signatureAlgorithm: "rsassapss";
    digested: boolean;
}

const SIGNATURE_ALGORITHMS = [
    { label: "RSASSA-PSS", value: "rsassapss" },
];

const RsaVerifyForm: React.FC = () => {
    const [form] = Form.useForm<RsaVerifyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [dataBytes, setDataBytes] = useState<Uint8Array | undefined>(undefined);
    const [sigBytes, setSigBytes] = useState<Uint8Array | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RsaVerifyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const dataBuf = dataBytes ?? (values.dataFile ? new Uint8Array(values.dataFile) : undefined);
            let sigBuf = sigBytes ?? (values.signatureFile ? new Uint8Array(values.signatureFile) : undefined);
            // Try to extract and decode Base64/hex automatically; if it fails, keep original bytes
            if (sigBuf && sigBuf.byteLength > 0) {
                try {
                    const text = new TextDecoder().decode(sigBuf).trim();
                    const base64Candidates = Array.from(text.matchAll(/[A-Za-z0-9+/=]{16,}/g)).map(m => m[0]);
                    let candidate = text;
                    if (base64Candidates.length > 0) {
                        candidate = base64Candidates.sort((a, b) => b.length - a.length)[0];
                    }
                    let decoded: Uint8Array | undefined;
                    try {
                        decoded = Uint8Array.from(atob(candidate), c => c.charCodeAt(0));
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
            console.debug("RsaVerify: dataBuf len", dataBuf?.byteLength ?? 0, "sigBuf len", sigBuf?.byteLength ?? 0);
            if (!sigBuf || sigBuf.byteLength === 0) {
                setRes("Error: signature file is empty or unreadable. Please re-upload the signature.");
                throw Error("Empty signature file");
            }
            const request = await signature_verify_ttlv_request(
                id,
                dataBuf!,
                sigBuf,
                values.signatureAlgorithm,
                values.digested,
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_signature_verify_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const validityRaw = respObj.ValidityIndicator ?? respObj.validity_indicator ?? respObj.validityIndicator;
                const validity = typeof validityRaw === "string" ? validityRaw : String(validityRaw ?? "Unknown");
                setRes(`Signature validity: ${validity}`);
            }
        } catch (e) {
            setRes(`Error verifying: ${e}`);
            console.error("Error verifying:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">RSA Verify</h1>

            <div className="mb-8 space-y-2">
                <p>Verify an RSASSA-PSS signature for a given data file.</p>
                <p>The key can be identified using either its ID or associated tags.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ signatureAlgorithm: "rsassapss", digested: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Data File</h3>
                        <Form.Item name="dataFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="dataFile" rules={[{ required: true, message: "Please select the data file" }] }>
                            <Upload.Dragger
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
                                <p className="ant-upload-text">Click or drag data file here</p>
                            </Upload.Dragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Signature File</h3>
                        <Form.Item name="signatureFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="signatureFile" rules={[{ required: true, message: "Please select the signature file" }] }>
                            <Upload.Dragger
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
                                <p className="ant-upload-text">Click or drag signature file here</p>
                            </Upload.Dragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item name="signatureAlgorithm" label="Signature Algorithm" rules={[{ required: true }]}>
                            <Select options={SIGNATURE_ALGORITHMS} />
                        </Form.Item>
                        <Form.Item name="digested" label="Data Is Digested" valuePropName="checked">
                            <Switch />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Verify Signature
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="RSA verify response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RsaVerifyForm;
