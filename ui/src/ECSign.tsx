import { Button, Card, Form, Input, Select, Space, Switch } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { downloadFile, sendKmipRequest } from "./utils";
import * as wasmClient from "./wasm/pkg/cosmian_kms_client_wasm";

interface ECSignFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    digested: boolean;
}

// No options types needed; algorithm handled by key type.

const ECSignForm: React.FC = () => {
    const [form] = Form.useForm<ECSignFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    // Signature algorithm is inferred by key type; no explicit options
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ECSignFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            // Use algorithm string like "ecdsa-with-sha256"
            const request = await wasmClient.sign_ttlv_request(
                id,
                values.inputFile,
                undefined,
                values.digested,
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await wasmClient.parse_sign_ttlv_response(result_str);
                // Support different casings or encodings from wasm response without using `any`
                const respObj = response as unknown as Record<string, unknown>;
                const sigCandidate = respObj.SignatureData ?? respObj.signature_data ?? respObj.signatureData;
                let signature: Uint8Array;
                if (sigCandidate instanceof Uint8Array) {
                    signature = sigCandidate;
                } else if (Array.isArray(sigCandidate)) {
                    signature = new Uint8Array(sigCandidate as number[]);
                } else if (typeof sigCandidate === "string") {
                    // Base64 string (e.g., from logs)
                    const base64 = sigCandidate.trim();
                    signature = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
                } else {
                    signature = new Uint8Array();
                }
                const filename = `${values.fileName}.sig`;
                console.debug("ECSign: signature length", signature.byteLength);
                downloadFile(signature, filename, "application/octet-stream");
                setRes(`Signature created and downloaded (${signature.byteLength} bytes).`);
            }
        } catch (e) {
            setRes(`Error signing: ${e}`);
            console.error("Error signing:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Elliptic Curve Sign</h1>

            <div className="mb-8 space-y-2">
                <p>Sign a file using an EC private key (ECDSA).</p>
                <p>The key can be identified using either its ID or associated tags.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ digested: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Input File</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: "Please select a file to sign" }]}>
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
                                <p className="ant-upload-text">Click or drag file to this area to sign</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the private key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        {/* Signature algorithm is determined by key type (ECDSA). */}
                        <Form.Item name="digested" label="Input Is Digested" valuePropName="checked">
                            <Switch />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Sign File
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="EC sign response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default ECSignForm;
