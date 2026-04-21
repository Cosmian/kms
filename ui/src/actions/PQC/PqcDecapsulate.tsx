import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { decrypt_ec_ttlv_request, parse_decrypt_ttlv_response } from "../../wasm/pkg";

interface PqcDecapsulateFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
}

const PqcDecapsulateForm: React.FC = () => {
    const [form] = Form.useForm<PqcDecapsulateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: PqcDecapsulateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = decrypt_ec_ttlv_request(id, values.inputFile);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const data = respObj.Data as Uint8Array | number[] | undefined;
                if (data) {
                    const ssBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
                    downloadFile(ssBytes, "shared_secret.key", "application/octet-stream");
                    setRes(`Decapsulation successful. Shared secret downloaded (${ssBytes.byteLength} bytes).`);
                } else {
                    setRes("Decapsulation returned empty data.");
                }
            }
        } catch (e) {
            setRes(`Error decapsulating: ${e}`);
            console.error("Error decapsulating:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">PQC KEM Decapsulate</h1>

            <div className="mb-8 space-y-2">
                <p>Decapsulate to recover the shared secret from a PQC KEM ciphertext (encapsulation).</p>
                <p>Upload the encapsulation file and specify the PQC KEM private key.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Encapsulation File</h3>
                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="inputFile" rules={[{ required: true, message: "Please select an encapsulation file" }]}>
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
                                <p className="ant-upload-text">Click or drag the encapsulation file here</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Private Key ID" help="The unique identifier of the PQC KEM private key">
                            <Input placeholder="Enter private key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
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
                            Decapsulate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="PQC KEM decapsulate response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default PqcDecapsulateForm;
