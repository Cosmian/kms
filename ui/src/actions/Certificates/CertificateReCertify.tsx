import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface CertificateReCertifyFormData {
    certificateIdToReCertify: string;
    issuerPrivateKeyId?: string;
    issuerCertificateId?: string;
    numberOfDays: number;
    tags: string[];
}

const CertificateReCertifyForm: React.FC = () => {
    const [form] = Form.useForm<CertificateReCertifyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: CertificateReCertifyFormData) => {
        const normalize = (v?: string) => (v?.trim() ? v.trim() : undefined);
        await execute(async () => {
            const request = wasm.re_certify_ttlv_request(
                values.certificateIdToReCertify.trim(),
                normalize(values.issuerPrivateKeyId),
                normalize(values.issuerCertificateId),
                values.numberOfDays,
                values.tags,
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await wasm.parse_re_certify_ttlv_response(result_str);
                return `Certificate successfully re-certified with new ID: ${response.UniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-certify a Certificate</h1>

            <div className="mb-8 space-y-2">
                <p>
                    Creates a <strong>new certificate</strong> from an existing one using the KMIP <code>ReCertify</code> operation. The old
                    and new certificates are linked via <em>ReplacedObjectLink</em> / <em>ReplacementObjectLink</em> attributes. The
                    original certificate is preserved and the new one is returned with a fresh unique identifier.
                </p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    numberOfDays: 365,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate to Re-certify</h3>
                        <Form.Item
                            name="certificateIdToReCertify"
                            label="Certificate ID"
                            rules={[{ required: true, message: "Please enter the certificate ID to re-certify" }]}
                            help="Unique identifier of the existing certificate to renew"
                        >
                            <Input placeholder="Enter certificate ID" data-testid="certificate-id-input" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Issuer Information</h3>
                        <p className="text-sm mb-4">If no issuer is provided, the certificate will be self-signed.</p>

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
                            <Input type="number" min={1} data-testid="number-of-days-input" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to associate with the new certificate (optional)">
                            <Select mode="tags" placeholder="Enter tags" open={false} data-testid="tags-select" />
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
                            Re-certify
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="ReCertify Response" />
        </div>
    );
};

export default CertificateReCertifyForm;
