import { Button, Card, DatePicker, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { parse_validate_ttlv_response, validate_certificate_ttlv_request } from "./wasm/pkg";

interface ValidateCertificateFormData {
    uniqueIdentifier?: string;
    validityTime?: Date;
}

const CertificateValidateForm: React.FC = () => {
    const [form] = Form.useForm<ValidateCertificateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ValidateCertificateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const validityTime = values.validityTime ? values.validityTime.toISOString() : undefined;
            const request = validate_certificate_ttlv_request(values.uniqueIdentifier, validityTime);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_validate_ttlv_response(result_str);
                setRes(`Validation Status: ${response.ValidityIndicator}`);
            }
        } catch (e) {
            setRes(`Error validating certificate: ${e}`);
            console.error("Error validating certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Validate Certificates</h1>

            <div className="mb-8 space-y-2">
                <p>Validate certificate chains to ensure they are properly signed, complete, and valid.</p>
                <p>You can specify certificate IDs stored in the KMS.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate Input</h3>

                        <Form.Item
                            name="uniqueIdentifier"
                            label="Certificate Unique Identifier"
                            help="Unique identifier of certificate stored in the KMS"
                            rules={[{ required: true }]}
                        >
                            <Input placeholder="Enter certificate ID" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Validation Parameters</h3>

                        <Form.Item
                            name="validityTime"
                            label="Validity Time"
                            help="The time at which the certificate chain needs to be valid (defaults to current time if omitted)"
                        >
                            <DatePicker showTime format="YYYY-MM-DD HH:mm:ss" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Validate Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Validation Results">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CertificateValidateForm;
