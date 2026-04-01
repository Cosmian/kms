import { Button, Card, Form, Input, Radio, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface SymmetricHashFormData {
    inputMode: "file" | "text";
    inputFile?: Uint8Array;
    fileName?: string;
    inputText?: string;
    hashAlgorithm: string;
}

const SymmetricHashForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricHashFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const inputMode = Form.useWatch("inputMode", form);
    const [algorithmOptions, setAlgorithmOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

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
        setIsLoading(true);
        setRes(undefined);
        try {
            let data: Uint8Array;
            if (values.inputMode === "file") {
                if (!values.inputFile || values.inputFile.byteLength === 0) {
                    setRes("Please select a file to hash.");
                    return;
                }
                data = values.inputFile;
            } else {
                if (!values.inputText) {
                    setRes("Please enter text to hash.");
                    return;
                }
                data = new TextEncoder().encode(values.inputText);
            }

            const request = wasm.hash_ttlv_request(data, values.hashAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
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
                setRes(hexHash);
            }
        } catch (e) {
            setRes(`Error hashing: ${e}`);
            console.error("Error hashing:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Hash</h1>

            <div className="mb-8 space-y-2">
                <p>Compute a cryptographic hash of data using the KMS server.</p>
                <p>You can hash data from a file or from text input.</p>
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
                        <Form.Item name="inputMode" label="Input Mode">
                            <Radio.Group>
                                <Radio value="file">File</Radio>
                                <Radio value="text">Text</Radio>
                            </Radio.Group>
                        </Form.Item>

                        {inputMode === "file" ? (
                            <>
                                <Form.Item name="fileName" style={{ display: "none" }}>
                                    <Input />
                                </Form.Item>
                                <Form.Item
                                    name="inputFile"
                                    rules={[{ required: inputMode === "file", message: "Please select a file to hash" }]}
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
                                        <p className="ant-upload-text">Click or drag file to this area to hash</p>
                                    </FormUploadDragger>
                                </Form.Item>
                            </>
                        ) : (
                            <Form.Item
                                name="inputText"
                                label="Text Input"
                                rules={[{ required: inputMode === "text", message: "Please enter text to hash" }]}
                            >
                                <Input.TextArea rows={4} placeholder="Enter text to hash" />
                            </Form.Item>
                        )}
                    </Card>

                    <Card>
                        <Form.Item
                            name="hashAlgorithm"
                            label="Hash Algorithm"
                            rules={[{ required: true }]}
                            help="Select the hash algorithm to use"
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
                            Compute Hash
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Hash result">
                        <p className="font-mono break-all">{res}</p>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default SymmetricHashForm;
