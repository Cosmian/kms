import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_rsa_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface RsaEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    keyId?: string;
    tags?: string[];
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
    hashingAlgorithm: "Sha1" | "Sha224" | "Sha256" | "Sha384" | "Sha512";
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

const RsaEncryptForm: React.FC = () => {
    const [form] = Form.useForm<RsaEncryptFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: RsaEncryptFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing key identifier.");
            }
            const request = encrypt_rsa_ttlv_request(id, values.inputFile, values.encryptionAlgorithm, values.hashingAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const data = new Uint8Array(response.Data);
                const mimeType = "application/octet-stream";
                const filename = `${values.fileName}.enc`;
                downloadFile(data, filename, mimeType);
                return "File has been encrypted";
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">RSA Encryption</h1>

            <div className="mb-8 space-y-2">
                <p>Encrypt a file using RSA public key.</p>
                <p>The key can be identified using either its ID or associated tags.</p>
                <p className="text-sm text-yellow-600">Note: RSA PKCS #1 v1.5 is deprecated in FIPS 140-3.</p>
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
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the public key">
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
                            help="RSA OAEP is recommended for security"
                        >
                            <Select options={ENCRYPTION_ALGORITHMS} />
                        </Form.Item>

                        <Form.Item
                            name="hashingAlgorithm"
                            label="Hashing Algorithm"
                            rules={[{ required: true }]}
                            help="SHA-256 or stronger is recommended"
                        >
                            <Select options={HASH_ALGORITHMS} />
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
                            Encrypt File
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="RSA encrypt response" />
        </div>
    );
};

export default RsaEncryptForm;
