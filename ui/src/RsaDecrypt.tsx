import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { getMimeType, saveDecryptedFile, sendKmipRequest } from "./utils";
import { decrypt_rsa_ttlv_request, parse_decrypt_ttlv_response } from "./wasm/pkg";

interface RsaDecryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
    hashingAlgorithm: "Sha1" | "Sha224" | "Sha256" | "Sha384" | "Sha512";
    outputFile?: string;
}

const ENCRYPTION_ALGORITHMS = [
    { label: "RSA PKCS #1 v1.5 (Legacy)", value: "CkmRsaPkcs" },
    { label: "RSA OAEP (Recommended)", value: "CkmRsaPkcsOaep" },
    { label: "RSA AES Key Wrap", value: "CkmRsaAesKeyWrap" },
];

const HASH_ALGORITHMS = [
    { label: "SHA-1", value: "Sha1" },
    { label: "SHA-224", value: "Sha224" },
    { label: "SHA-256", value: "Sha256" },
    { label: "SHA-384", value: "Sha384" },
    { label: "SHA-512", value: "Sha512" },
];

const RsaDecryptForm: React.FC = () => {
    const [form] = Form.useForm<RsaDecryptFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RsaDecryptFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = decrypt_rsa_ttlv_request(id, values.inputFile, values.encryptionAlgorithm, values.hashingAlgorithm);
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
            <h1 className="text-2xl font-bold mb-6">RSA Decryption</h1>

            <div className="mb-8 space-y-2">
                <p>Decrypt a file using RSA private key.</p>
                <p>The key can be identified using either its ID or associated tags.</p>
                <p className="text-sm text-yellow-600">Note: This operation loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    encryptionAlgorithm: "CkmRsaPkcsOaep",
                    hashingAlgorithm: "Sha256",
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
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the private key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="encryptionAlgorithm"
                            label="Encryption Algorithm"
                            rules={[{ required: true }]}
                            help="Must match the algorithm used for encryption"
                        >
                            <Select options={ENCRYPTION_ALGORITHMS} />
                        </Form.Item>

                        <Form.Item
                            name="hashingAlgorithm"
                            label="Hashing Algorithm"
                            rules={[{ required: true }]}
                            help="For OAEP and AES key wrap (must match encryption)"
                        >
                            <Select options={HASH_ALGORITHMS} />
                        </Form.Item>
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
                    <Card title="RSA decrypt response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RsaDecryptForm;
