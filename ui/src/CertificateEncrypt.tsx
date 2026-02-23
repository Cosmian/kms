import { Button, Card, Form, Input, Radio, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { downloadFile, sendKmipRequest } from "./utils";
import { encrypt_certificate_ttlv_request, parse_encrypt_ttlv_response } from "./wasm/pkg";

interface CertificateEncryptFormData {
    inputFile: Uint8Array;
    fileName: string;
    certificateId?: string;
    tags?: string[];
    outputFile?: string;
    authenticationData?: Uint8Array;
    encryptionAlgorithm: "CkmRsaPkcs" | "CkmRsaPkcsOaep" | "CkmRsaAesKeyWrap";
}

const CertificateEncryptForm: React.FC = () => {
    const [form] = Form.useForm<CertificateEncryptFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: CertificateEncryptFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.certificateId ? values.certificateId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing certificate identifier.");
                throw Error("Missing certificate identifier");
            }
            const request = encrypt_certificate_ttlv_request(id, values.inputFile, values.authenticationData, values.encryptionAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const data = new Uint8Array(response.Data);
                const mimeType = "application/octet-stream";

                let filename;
                if (values.outputFile) {
                    filename = values.outputFile;
                } else {
                    filename = `${values.fileName}.enc`;
                }

                downloadFile(data, filename, mimeType);
                setRes("File has been encrypted");
            }
        } catch (e) {
            setRes(`Error encrypting: ${e}`);
            console.error("Error encrypting with certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Certificate Encryption</h1>

            <div className="mb-8 space-y-2">
                <p>Encrypt a file using the certificate public key.</p>
                <p>The certificate can be identified using either its ID or associated tags.</p>
                <p className="text-sm text-yellow-600">Note: This operation loads the entire file in memory.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
                initialValues={{
                    encryptionAlgorithm: "CkmRsaPkcsOaep",
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
                        <h3 className="text-m font-bold mb-4">Certificate Identification (required)</h3>
                        <Form.Item name="certificateId" label="Certificate ID" help="The unique identifier of the certificate">
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Certificate ID: specify tags to identify the certificate">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Encryption Options</h3>
                        <Form.Item
                            name="authenticationData"
                            label="Authentication Data"
                            help="Optional: this data needs to be provided back for decryption"
                        >
                            <Input.TextArea placeholder="Enter authentication data" rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="encryptionAlgorithm"
                            label="Encryption Algorithm"
                            help="Optional: only available for RSA keys. Default is PKCS#1 RSA OAEP"
                        >
                            <Radio.Group>
                                <Radio value="CkmRsaPkcsOaep">PKCS#1 RSA OAEP</Radio>
                                <Radio value="CkmRsaPkcs">PKCS#1 v1.5 RSA</Radio>
                                <Radio value="CkmRsaAesKeyWrap">RSA AES Key Wrap</Radio>
                            </Radio.Group>
                        </Form.Item>

                        <Form.Item name="outputFile" label="Output File Path" help="Optional: specify a custom output file path">
                            <Input placeholder="Enter output file path" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Encrypt File with Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Certificate encrypt response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CertificateEncryptForm;
