import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { getMimeType, saveDecryptedFile, sendKmipRequest } from "./utils";
import { decrypt_sym_ttlv_request, parse_decrypt_ttlv_response } from "./wasm/pkg";

interface SymmetricDecryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    dataEncryptionAlgorithm: "AesGcm" | "AesXts" | "AesGcmSiv" | "Chacha20Poly1305" | "AesCbc";
    outputFile?: string;
    authenticationData?: Uint8Array;
}

const DATA_ENCRYPTION_ALGORITHMS = [
    { label: "AES-GCM (default)", value: "AesGcm" },
    { label: "AES-CBC", value: "AesCbc" },
    { label: "AES-XTS", value: "AesXts" },
    { label: "AES-GCM-SIV", value: "AesGcmSiv" },
    { label: "ChaCha20-Poly1305", value: "Chacha20Poly1305" },
];

const SymmetricDecryptForm: React.FC = () => {
    const [form] = Form.useForm<SymmetricDecryptFormData>();
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

    const onFinish = async (values: SymmetricDecryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = decrypt_sym_ttlv_request(id, values.inputFile, values.authenticationData, values.dataEncryptionAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_decrypt_ttlv_response(result_str);
                const name = values.fileName.slice(0, -4);
                const lastDotIndex = name.lastIndexOf(".");
                const fileName = lastDotIndex !== -1 ? name : `${name}.plain`;
                const mimeType = getMimeType(fileName);
                saveDecryptedFile(response.Data, fileName, mimeType);
                setRes("File has been decrypted");
            }
        } catch (e) {
            setRes(`Error decrypting: ${e}`);
            console.error("Error decrypting:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Symmetric Decryption</h1>

            <div className="mb-8 space-y-2">
                <p>Decrypt a file using a symmetric key.</p>
                <p>Decryption can happen in two ways:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>Server side: the data is sent to the server and decrypted there.</li>
                    <li>Client side: The data encryption key (DEK) is decrypted server-side, then data is decrypted locally.</li>
                </ul>
                <p className="text-sm text-yellow-600">Note: Server-side decryption loads the entire file in memory.</p>
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

                        <Form.Item name="inputFile" rules={[{ required: true, message: "Please select a file to decrypt" }]}>
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
                                <p className="ant-upload-text">Click or drag file to this area to decrypt</p>
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
                            <Select options={DATA_ENCRYPTION_ALGORITHMS} />
                        </Form.Item>

                        {selectedEncryptionAlgorithm !== "AesXts" && selectedEncryptionAlgorithm !== "AesCbc" && (
                            <Form.Item
                                name="authenticationData"
                                label="Authentication Data"
                                help="Optional hex-encoded authentication data used during encryption"
                            >
                                <Input placeholder="Enter authentication data (hex)" />
                            </Form.Item>
                        )}
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Decrypt File
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Symmetric keys decrypt response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default SymmetricDecryptForm;
