import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUpload } from "./FormUpload";
import { sendKmipRequest } from "./utils";
import { import_certificate_ttlv_request, parse_import_ttlv_response } from "./wasm/pkg";

type CertificateInputFormat = "JsonTtlv" | "Pem" | "Der" | "Pkcs12";

type KeyUsage = "sign" | "verify" | "encrypt" | "decrypt" | "wrap" | "unwrap";

interface ImportCertificateFormData {
    certificateFile?: Uint8Array;
    certificateId?: string;
    inputFormat: CertificateInputFormat;
    privateKeyId?: string;
    publicKeyId?: string;
    issuerCertificateId?: string;
    pkcs12Password?: string;
    replaceExisting: boolean;
    tags: string[];
    keyUsage?: KeyUsage[];
}

type CertificateImportResponse = {
    UniqueIdentifier: string;
};

const CertificateImportForm: React.FC = () => {
    const [form] = Form.useForm<ImportCertificateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [selectedFormat, setSelectedFormat] = useState<CertificateInputFormat>("JsonTtlv");
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ImportCertificateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            if (values.certificateFile) {
                const request = import_certificate_ttlv_request(
                    values.certificateId,
                    values.certificateFile,
                    values.inputFormat,
                    values.privateKeyId,
                    values.publicKeyId,
                    values.issuerCertificateId,
                    values.pkcs12Password,
                    values.replaceExisting,
                    values.tags,
                    values.keyUsage
                );
                const result_str = await sendKmipRequest(request, idToken, serverUrl);
                if (result_str) {
                    const result: CertificateImportResponse = await parse_import_ttlv_response(result_str);
                    setRes(`Certificate has been imported - imported object id: ${result.UniqueIdentifier}`);
                }
            } else {
                setRes("Certificate file is required for the selected format");
                throw Error("Certificate file is required");
            }
        } catch (e) {
            setRes(`Error importing certificate: ${e}`);
            console.error("Error importing certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const formatOptions = [
        { label: "JSON TTLV (default)", value: "JsonTtlv" },
        { label: "X509 PEM", value: "Pem" },
        { label: "X509 DER", value: "Der" },
        // { label: 'PEM-stack Certificate Chain', value: 'Chain' },
        { label: "PKCS#12", value: "Pkcs12" },
        // { label: 'Mozilla Common CA Database (CCADB)', value: 'Ccadb' }
    ];

    const keyUsageOptions = [
        { label: "Sign", value: "sign" },
        { label: "Verify", value: "verify" },
        { label: "Encrypt", value: "encrypt" },
        { label: "Decrypt", value: "decrypt" },
        { label: "Wrap", value: "wrap" },
        { label: "Unwrap", value: "unwrap" },
    ];

    // Handle format change to update the UI
    const handleFormatChange = (value: CertificateInputFormat) => {
        setSelectedFormat(value);
    };

    // Check if PKCS#12 password field should be shown
    const showPkcs12Password = selectedFormat === "Pkcs12";

    // Check if relationship fields should be shown (not for PKCS12 and CCADB)
    const showRelationships = !["Pkcs12"].includes(selectedFormat);

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Import Certificate</h1>

            <div className="mb-8 space-y-2">
                <p>Import a certificate or PKCS#12 file, into the KMS.</p>
                <p>When no unique ID is specified, a unique ID based on the key material will be generated.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    inputFormat: "JsonTtlv",
                    replaceExisting: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="inputFormat"
                            label="Certificate Format"
                            help="Format of the certificate to import"
                            rules={[{ required: true }]}
                        >
                            <Select options={formatOptions} onChange={(value) => handleFormatChange(value as CertificateInputFormat)} />
                        </Form.Item>

                        <Form.Item
                            name="certificateFile"
                            label="Certificate File"
                            rules={[{ required: true, message: "Please upload a certificate file" }]}
                            help={`Upload the certificate file in ${selectedFormat} format`}
                        >
                            <FormUpload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ certificateFile: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>Upload Certificate File</Button>
                            </FormUpload>
                        </Form.Item>

                        <Form.Item
                            name="certificateId"
                            label="Certificate ID"
                            help="Optional: A unique ID based on the key material will be generated if not specified"
                        >
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>

                        {showPkcs12Password && (
                            <Form.Item
                                name="pkcs12Password"
                                label="PKCS#12 Password"
                                rules={[{ required: true }]}
                                help="Password for the PKCS#12 file"
                            >
                                <Input.Password placeholder="Enter PKCS#12 password" />
                            </Form.Item>
                        )}
                    </Card>

                    {showRelationships && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">Certificate Relationships</h3>

                            <Form.Item name="privateKeyId" label="Private Key ID" help="Link to corresponding private key in KMS">
                                <Input placeholder="Enter private key ID" />
                            </Form.Item>

                            <Form.Item name="publicKeyId" label="Public Key ID" help="Link to corresponding public key in KMS">
                                <Input placeholder="Enter public key ID" />
                            </Form.Item>

                            <Form.Item name="issuerCertificateId" label="Issuer Certificate ID" help="Link to issuer certificate in KMS">
                                <Input placeholder="Enter issuer certificate ID" />
                            </Form.Item>
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="keyUsage" label="Key Usage" help="Specify allowed operations for this certificate">
                            <Select mode="multiple" options={keyUsageOptions} placeholder="Select key usage" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the certificate later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="replaceExisting" valuePropName="checked" help="Replace an existing certificate with the same ID">
                            <Checkbox>Replace existing certificate</Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Import Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Certificate import response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CertificateImportForm;
