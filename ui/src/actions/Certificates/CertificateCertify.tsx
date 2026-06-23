import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Radio, RadioChangeEvent, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

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
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type AlgoOption = { label: string; value: string };

const CertificateCertifyForm: React.FC = () => {
    const [form] = Form.useForm<CertificateCertifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [certifyMethod, setCertifyMethod] = useState<string>("csr");
    const [algorithmOptions, setAlgorithmOptions] = useState<AlgoOption[]>([]);

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
        // Normalize empty/whitespace-only strings to undefined so the WASM layer
        // does not attempt to look up a blank identifier on the server.
        const normalize = (v?: string) => (v?.trim() ? v.trim() : undefined);
        await execute(async () => {
            // Option 3 uses the dedicated KMIP ReCertify operation which creates a
            // new certificate with a fresh UID and links old ↔ new via replacement links.
            if (certifyMethod === "reCertify") {
                const certIdToRenew = normalize(values.certificateIdToReCertify);
                if (!certIdToRenew) throw new Error("Certificate ID to re-certify is required");
                const request = wasm.re_certify_ttlv_request(
                    certIdToRenew,
                    normalize(values.issuerPrivateKeyId),
                    normalize(values.issuerCertificateId),
                    values.numberOfDays,
                    values.tags,
                );
                const result_str = await sendKmipRequest(request, idToken, serverUrl);
                if (result_str) {
                    const response = await wasm.parse_re_certify_ttlv_response(result_str);
                    const newCertId = response.UniqueIdentifier;
                    if (values.enrollKeyset) {
                        const req = wasm.set_rotate_name_ttlv_request(newCertId, newCertId);
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.enrollKeyset && values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(newCertId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.enrollKeyset && values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(newCertId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    return `Certificate successfully re-certified with new ID: ${newCertId}`;
                }
                return;
            }

            const request = wasm.certify_ttlv_request(
                normalize(values.certificateId),
                values.csrFormat,
                values.certificateSigningRequest,
                normalize(values.publicKeyIdToCertify),
                normalize(values.certificateIdToReCertify),
                values.generateKeyPair,
                normalize(values.subjectName),
                normalize(values.algorithm),
                normalize(values.issuerPrivateKeyId),
                normalize(values.issuerCertificateId),
                values.numberOfDays,
                values.certificateExtensions,
                values.tags,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasm.parse_certify_ttlv_response(result_str);
                const newCertId = response.UniqueIdentifier;
                if (values.enrollKeyset) {
                    const req = wasm.set_rotate_name_ttlv_request(newCertId, newCertId);
                    await sendKmipRequest(req, idToken, serverUrl);
                }
                if (values.enrollKeyset && values.rotateInterval !== undefined) {
                    const req = wasm.set_rotate_interval_ttlv_request(newCertId, BigInt(values.rotateInterval));
                    await sendKmipRequest(req, idToken, serverUrl);
                }
                if (values.enrollKeyset && values.rotateOffset !== undefined) {
                    const req = wasm.set_rotate_offset_ttlv_request(newCertId, BigInt(values.rotateOffset));
                    await sendKmipRequest(req, idToken, serverUrl);
                }
                return `Certificate successfully created with ID: ${newCertId}`;
            }
        });
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
                    enrollKeyset: false,
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
                                    <Select options={algorithmOptions} data-testid="cert-algorithm-select" virtual={false} />
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

                        <Divider orientation="left" plain>
                            Rotation Policy (optional)
                        </Divider>

                        <Form.Item
                            name="enrollKeyset"
                            valuePropName="checked"
                            help="When enabled, sets the rotation name to the certificate ID so this certificate can be addressed via name@latest, name@first, name@N syntax. Also configures the rotation interval and offset below."
                        >
                            <Checkbox data-testid="cert-enroll-keyset">Enroll in keyset (rotation name = certificate ID)</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label="Rotation Interval (seconds)"
                                            help="Auto-rotate the certificate every N seconds (e.g. 7776000 = 90 days)."
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={1}
                                                placeholder="e.g. 7776000"
                                                data-testid="cert-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label="Rotation Offset (seconds)"
                                            help="Delay before the first rotation occurs (optional)."
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder="e.g. 3600"
                                                data-testid="cert-rotation-offset"
                                            />
                                        </Form.Item>
                                    </>
                                ) : null
                            }
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
                            Issue/Renew Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="Certificate Response" />
        </div>
    );
};

export default CertificateCertifyForm;
