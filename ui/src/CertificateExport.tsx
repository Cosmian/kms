import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { downloadFile, sendKmipRequest } from "./utils";
import { export_certificate_ttlv_request, parse_export_certificate_ttlv_response } from "./wasm/pkg";

interface CertificateExportFormData {
    certificateId?: string;
    tags?: string[];
    outputFormat: CertificateExportFormat;
    pkcs12Password?: string;
}

type CertificateExportFormat = "JsonTtlv" | "Pem" | "Pkcs12" | "Pkcs12Legacy" | "Pkcs7";

const exportFileExtension = {
    JsonTtlv: "json",
    Pem: "pem",
    Pkcs12: "p12",
    Pkcs12Legacy: "p12",
    Pkcs7: "p7b",
};

const CertificateExportForm: React.FC = () => {
    const [form] = Form.useForm<CertificateExportFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [selectedFormat, setSelectedFormat] = useState<CertificateExportFormat>("JsonTtlv");
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const handleFormatChange = (value: CertificateExportFormat) => {
        setSelectedFormat(value);
    };

    const onFinish = async (values: CertificateExportFormData) => {
        console.log("Export certificate values:", values);
        setIsLoading(true);
        setRes(undefined);
        const id = values.certificateId ? values.certificateId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing certificate identifier.");
                throw Error("Missing certificate identifier");
            }
            const request = export_certificate_ttlv_request(id, values.outputFormat, values.pkcs12Password);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const data = await parse_export_certificate_ttlv_response(result_str, values.outputFormat);
                const filename = `certificate_${id}.${exportFileExtension[values.outputFormat]}`;
                let mimeType;
                switch (values.outputFormat) {
                    case "JsonTtlv":
                        mimeType = "application/json";
                        break;
                    case "Pem":
                        mimeType = "application/x-pem-file";
                        break;
                    case "Pkcs12":
                    case "Pkcs12Legacy":
                        mimeType = "application/x-pkcs12";
                        break;
                    case "Pkcs7":
                        mimeType = "application/x-pkcs7-certificates";
                        break;
                    default:
                        mimeType = "application/octet-stream";
                }
                downloadFile(data, filename, mimeType);
                setRes("Certificate has been exported");
            }
        } catch (e) {
            setRes(`Error exporting certificate: ${e}`);
            console.error("Error exporting certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const certificateFormats = [
        { label: "JSON TTLV (default)", value: "JsonTtlv" },
        { label: "X509 PEM", value: "Pem" },
        { label: "PKCS12 (with private key)", value: "Pkcs12" },
        { label: "PKCS12 Legacy (compatible with openssl 1.x)", value: "Pkcs12Legacy" },
        { label: "PKCS7 (certificate chain)", value: "Pkcs7" },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Export Certificate</h1>

            <div className="mb-8 space-y-2">
                <p>Export a certificate from the KMS. The certificate can be identified using either its ID or associated tags.</p>
                <p>For PKCS#12 formats, provide the private key ID instead of certificate ID.</p>
                <p className="text-sm text-yellow-600">Note: PKCS12-legacy format is not available in FIPS mode.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    outputFormat: "JsonTtlv",
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate Identification (required)</h3>
                        <Form.Item
                            name="certificateId"
                            label="Certificate ID"
                            help="The unique identifier of the certificate stored in the KMS. For PKCS#12, provide the private key ID."
                        >
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Certificate ID: specify tags to identify the certificate">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="outputFormat"
                            label="Certificate Format"
                            help="Format for the exported certificate. JSON TTLV is recommended for later re-import."
                            rules={[{ required: true }]}
                        >
                            <Select options={certificateFormats} onChange={handleFormatChange} />
                        </Form.Item>
                    </Card>

                    {(selectedFormat === "Pkcs12" || selectedFormat === "Pkcs12Legacy") && (
                        <Card>
                            <Form.Item
                                name="pkcs12Password"
                                label="PKCS#12 Password"
                                help="Password to protect the PKCS#12 file"
                                rules={[{ required: true }]}
                            >
                                <Input.Password placeholder="Enter password for PKCS#12" />
                            </Form.Item>
                        </Card>
                    )}
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Export Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Certificate export response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CertificateExportForm;
