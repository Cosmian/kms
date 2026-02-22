import { Button, Card, Checkbox, Form, Input, Radio, RadioChangeEvent, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { FormUploadDragger } from "./FormUpload";
import { sendKmipRequest } from "./utils";
import * as wasm from "./wasm/pkg";

interface CertificateCertifyFormData {
    certificateId?: string;
    certificateSigningRequest?: Uint8Array;
    csrFormat: "pem" | "der";
    publicKeyIdToCertify?: string;
    certificateIdToReCertify?: string;
    generateKeyPair: boolean;
    subjectName?: string;
    algorithm: string;
    issuerPrivateKeyId?: string;
    issuerCertificateId?: string;
    numberOfDays: number;
    certificateExtensions?: Uint8Array;
    tags: string[];
}

type AlgoOption = { label: string; value: string };

const CertificateCertifyForm: React.FC = () => {
    const [form] = Form.useForm<CertificateCertifyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [certifyMethod, setCertifyMethod] = useState<string>("csr");
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [algorithmOptions, setAlgorithmOptions] = useState<AlgoOption[]>([]);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_certificate_algorithms?: () => AlgoOption[] };
            const opts = w.get_certificate_algorithms ? w.get_certificate_algorithms() : [];
            setAlgorithmOptions(opts);
        } catch (e) {
            console.error("Error loading certificate algorithms from WASM:", e);
        }
    }, []);

    const onCertifyMethodChange = (e: RadioChangeEvent) => {
        setCertifyMethod(e.target.value);
        form.resetFields([
            "certificateSigningRequest",
            "publicKeyIdToCertify",
            "certificateIdToReCertify",
            "generateKeyPair",
            "subjectName",
            "algorithm",
            "issuerPrivateKeyId",
            "issuerCertificateId",
            "certificateExtensions",
        ]);
        if (e.target.value === "generate") {
            form.setFieldValue("generateKeyPair", true);
        }
    };

    const onFinish = async (values: CertificateCertifyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = wasm.certify_ttlv_request(
                values.certificateId,
                values.csrFormat,
                values.certificateSigningRequest,
                values.publicKeyIdToCertify,
                values.certificateIdToReCertify,
                values.generateKeyPair,
                values.subjectName,
                values.algorithm,
                values.issuerPrivateKeyId,
                values.issuerCertificateId,
                values.numberOfDays,
                values.certificateExtensions,
                values.tags
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await wasm.parse_certify_ttlv_response(result_str);
                setRes(`Certificate successfully created with ID: ${response.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error certifying certificate: ${e}`);
            console.error("Error certifying certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Certificate Issuance and Renewal</h1>

            <div className="mb-8 space-y-2">
                <p>Issue or renew an X509 certificate using one of four methods:</p>
                <ol className="list-decimal ml-5">
                    <li>Provide a Certificate Signing Request (CSR)</li>
                    <li>Provide a public key ID to certify</li>
                    <li>Provide the ID of an existing certificate to re-certify</li>
                    <li>Generate a new keypair and create a certificate</li>
                </ol>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    csrFormat: "pem",
                    algorithm: "rsa4096",
                    numberOfDays: 365,
                    generateKeyPair: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate ID (Optional)</h3>
                        <Form.Item
                            name="certificateId"
                            help="If not provided, a random one will be generated when issuing a certificate, or the original one will be used when renewing"
                        >
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Certification Method</h3>
                        <Radio.Group onChange={onCertifyMethodChange} value={certifyMethod}>
                            <Space direction="vertical">
                                <Radio value="csr">1. Certificate Signing Request (CSR)</Radio>
                                <Radio value="publicKey">2. Public Key ID to Certify</Radio>
                                <Radio value="reCertify">3. Certificate ID to Re-certify</Radio>
                                <Radio value="generate">4. Generate New Keypair</Radio>
                            </Space>
                        </Radio.Group>

                        {certifyMethod === "csr" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="certificateSigningRequest"
                                    label="Certificate Signing Request"
                                    rules={[{ required: true, message: "Please upload a CSR file" }]}
                                >
                                    <FormUploadDragger
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const arrayBuffer = e.target?.result;
                                                if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                                    const bytes = new Uint8Array(arrayBuffer);
                                                    form.setFieldsValue({ certificateSigningRequest: bytes });
                                                }
                                            };
                                            reader.readAsArrayBuffer(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <p className="ant-upload-text">Click or drag CSR file to this area</p>
                                    </FormUploadDragger>
                                </Form.Item>

                                <Form.Item name="csrFormat" label="CSR Format" rules={[{ required: true }]}>
                                    <Radio.Group>
                                        <Radio value="pem">PEM</Radio>
                                        <Radio value="der">DER</Radio>
                                    </Radio.Group>
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "publicKey" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="publicKeyIdToCertify"
                                    label="Public Key ID to Certify"
                                    rules={[{ required: true, message: "Please enter a public key ID" }]}
                                >
                                    <Input placeholder="Enter public key ID" />
                                </Form.Item>

                                <Form.Item
                                    name="subjectName"
                                    label="Subject Name"
                                    rules={[{ required: true, message: "Subject name is required" }]}
                                    help='For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"'
                                >
                                    <Input placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US" />
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "reCertify" && (
                            <div className="mt-4">
                                <Form.Item
                                    name="certificateIdToReCertify"
                                    label="Certificate ID to Re-certify"
                                    rules={[{ required: true, message: "Please enter a certificate ID" }]}
                                >
                                    <Input placeholder="Enter certificate ID to re-certify" />
                                </Form.Item>
                            </div>
                        )}

                        {certifyMethod === "generate" && (
                            <div className="mt-4">
                                <Form.Item name="generateKeyPair" valuePropName="checked" hidden={true}>
                                    <Checkbox>Generate Key Pair</Checkbox>
                                </Form.Item>

                                <Form.Item
                                    name="subjectName"
                                    label="Subject Name"
                                    rules={[{ required: true, message: "Subject name is required" }]}
                                    help='For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"'
                                >
                                    <Input placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US" />
                                </Form.Item>

                                <Form.Item
                                    name="algorithm"
                                    label="Key Algorithm"
                                    rules={[{ required: true, message: "Please select an algorithm" }]}
                                >
                                    <Select options={algorithmOptions} />
                                </Form.Item>
                            </div>
                        )}
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Issuer Information</h3>
                        <p className="text-sm mb-4">If no issuer is provided, the certificate will be self-signed (not valid for CSR).</p>

                        <Form.Item
                            name="issuerPrivateKeyId"
                            label="Issuer Private Key ID"
                            help="The unique identifier of the private key of the issuer"
                        >
                            <Input placeholder="Enter issuer private key ID" />
                        </Form.Item>

                        <Form.Item
                            name="issuerCertificateId"
                            label="Issuer Certificate ID"
                            help="The unique identifier of the certificate of the issuer"
                        >
                            <Input placeholder="Enter issuer certificate ID" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate Options</h3>
                        <Form.Item
                            name="numberOfDays"
                            label="Validity Period (days)"
                            rules={[{ required: true, message: "Please enter number of days" }]}
                            help="The requested number of validity days (server may grant a different value)"
                        >
                            <Input type="number" min={1} />
                        </Form.Item>

                        <Form.Item
                            name="certificateExtensions"
                            label="X509 Extensions File"
                            help="File containing a 'v3_ca' paragraph with X509 extensions"
                        >
                            <FormUploadDragger
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const arrayBuffer = e.target?.result;
                                        if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                            const bytes = new Uint8Array(arrayBuffer);
                                            form.setFieldsValue({ certificateExtensions: bytes });
                                        }
                                    };
                                    reader.readAsArrayBuffer(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <p className="ant-upload-text">Click or drag extensions file to this area</p>
                            </FormUploadDragger>
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to associate with the certificate (optional)">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Issue/Renew Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Certificate Response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CertificateCertifyForm;
