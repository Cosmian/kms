import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useState } from "react";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import * as wasmClient from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PqcVerifyFormData {
    dataFile: Uint8Array;
    dataFileName: string;
    signatureFile: Uint8Array;
    signatureFileName: string;
    keyId?: string;
    tags?: string[];
}

const PqcVerifyForm: React.FC = () => {
    const [form] = Form.useForm<PqcVerifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [dataBytes, setDataBytes] = useState<Uint8Array | undefined>(undefined);
    const [sigBytes, setSigBytes] = useState<Uint8Array | undefined>(undefined);

    const onFinish = async (values: PqcVerifyFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing key identifier.");
            }
            const dataBuf = dataBytes ?? (values.dataFile ? new Uint8Array(values.dataFile) : undefined);
            const sigBuf = sigBytes ?? (values.signatureFile ? new Uint8Array(values.signatureFile) : undefined);

            if (!sigBuf || sigBuf.byteLength === 0) {
                throw new Error("Error: signature file is empty or unreadable.");
            }
            // ML-DSA verify: no crypto parameters needed, not digested
            const request = wasmClient.signature_verify_ttlv_request(id, dataBuf!, sigBuf, undefined, false);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasmClient.parse_signature_verify_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;
                const validityRaw = respObj.ValidityIndicator ?? respObj.validity_indicator ?? respObj.validityIndicator;
                const validity = typeof validityRaw === "string" ? validityRaw : String(validityRaw ?? "Unknown");
                return `Signature validity: ${validity}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">PQC Signature Verify</h1>

            <div className="mb-8 space-y-2">
                <p>Verify a PQC signature (ML-DSA or SLH-DSA) for a given data file.</p>
                <p>The key can be identified using either its ID or associated tags.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Data File</h3>
                        <Form.Item name="dataFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="dataFile" rules={[{ required: true, message: "Please select the data file" }]}>
                            <FormUploadDragger
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
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Signature File</h3>
                        <Form.Item name="signatureFileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>
                        <Form.Item name="signatureFile" rules={[{ required: true, message: "Please select the signature file" }]}>
                            <FormUploadDragger
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
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Public Key ID" help="The unique identifier of the PQC signature public key">
                            <Input placeholder="Enter public key ID" />
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
                            Verify Signature
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="PQC verify response" />
        </div>
    );
};

export default PqcVerifyForm;
