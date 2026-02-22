import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { downloadFile, sendKmipRequest } from "./utils";
import { encrypt_sym_ttlv_request, parse_encrypt_ttlv_response } from "./wasm/pkg";

interface SymmetricEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: "AesGcm" | "AesGcmSiv" | "Chacha20Poly1305" | "AesXts" | "AesCbc";
    outputFile?: string;
    nonce?: Uint8Array;
    authenticationData?: Uint8Array;
}

const SymmetricEncryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricEncryptFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const selectedEncryptionAlgorithm = Form.useWatch("dataEncryptionAlgorithm", form);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: SymmetricEncryptFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = encrypt_sym_ttlv_request(
                id,
                undefined,
                values.inputFile,
                values.nonce,
                values.authenticationData,
                values.dataEncryptionAlgorithm
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const { IVCounterNonce, Data, AuthenticatedEncryptionTag } = await parse_encrypt_ttlv_response(result_str);
                const combinedData = new Uint8Array(IVCounterNonce.length + Data.length + AuthenticatedEncryptionTag.length);
                combinedData.set(IVCounterNonce, 0);
                combinedData.set(Data, IVCounterNonce.length);
                combinedData.set(AuthenticatedEncryptionTag, IVCounterNonce.length + Data.length);
                const mimeType = "application/octet-stream";
                const filename = `${values.fileName}.enc`;
                downloadFile(combinedData, filename, mimeType);
                setRes("File has been encrypted");
            }
        } catch (e) {
            setRes(`Error encrypting: ${e}`);
            console.error("Error encrypting:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">Symmetric Encryption</h1>

            <div className="mb-8 space-y-2">
                <p>Encrypt a file using a symmetric key.</p>
                <p>Encryption can happen in two ways:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>Server side: the data is sent to the server and encrypted there.</li>
                    <li>Client side: The data encryption key (DEK) is encrypted server-side, then data is encrypted locally.</li>
                </ul>
                <p className="text-sm text-yellow-600">Note: Server-side encryption loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    dataEncryptionAlgorithm: "AesGcm",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Input File</h3>

                        <Form.Item name="fileName" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item name="inputFile" rules={[{ required: true, message: "Please select a file to encrypt" }]}>
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
                                <p className="ant-upload-text">Click or drag file to this area to encrypt</p>
                            </FormUploadDragger>
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the symmetric key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="dataEncryptionAlgorithm"
                            label="Data Encryption Algorithm"
                            rules={[{ required: true }]}
                            help="Algorithm used to encrypt the data"
                        >
                            <Select>
                                <Select.Option value="AesGcm">AES-GCM</Select.Option>
                                <Select.Option value="AesGcmSiv">AES-GCM-SIV</Select.Option>
                                <Select.Option value="AesCbc">AES-CBC</Select.Option>
                                <Select.Option value="Chacha20Poly1305">ChaCha20-Poly1305</Select.Option>
                                <Select.Option value="AesXts">AES-XTS</Select.Option>
                            </Select>
                        </Form.Item>

                        {selectedEncryptionAlgorithm !== "AesXts" && selectedEncryptionAlgorithm !== "AesCbc" && (
                            <>
                                <Form.Item
                                    name="nonce"
                                    label="Nonce/IV"
                                    help="Optional: random value will be generated if not provided (hex string)"
                                >
                                    <Input placeholder="Enter nonce in hex format" />
                                </Form.Item>

                                <Form.Item
                                    name="authenticationData"
                                    label="Authentication Data"
                                    help="Optional: additional authentication data (hex string)"
                                >
                                    <Input placeholder="Enter authentication data in hex format" />
                                </Form.Item>
                            </>
                        )}
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Encrypt File (Server-side)
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Symmetric keys encrypt response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default SymmetricEncryptForm;
