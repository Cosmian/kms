import { UploadOutlined } from '@ant-design/icons'
import { Button, Card, DatePicker, Form, Input, Radio, Space, Upload } from 'antd'
import React, { useState } from 'react'
import { sendKmipRequest } from './utils'
import { parse_validate_ttlv_response, validate_certificate_ttlv_request } from "./wasm/pkg"

interface ValidateCertificateFormData {
    certificateBytes?: Uint8Array;
    certificateContent?: string;
    uniqueIdentifier?: string;
    validityTime?: Date;
}

const CertificateValidateForm: React.FC = () => {
    const [form] = Form.useForm<ValidateCertificateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const [certificateInputType, setCertificateInputType] = useState<'file' | 'text' | 'id'>('file');

    const onFinish = async (values: ValidateCertificateFormData) => {
        console.log('Validate Certificate values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            if (values.uniqueIdentifier == undefined && values.certificateBytes == undefined) {
                setRes("Missing certificate to validate.")
                throw Error("Missing certificate to validate.")
            }
            const validityTime = values.validityTime ? values.validityTime.toISOString() : undefined;
            const request = validate_certificate_ttlv_request(
                values.certificateBytes, // This is already a Uint8Array
                values.uniqueIdentifier,
                validityTime
            );
            const result_str = await sendKmipRequest(request);
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
                <p>You can upload a certificate file, paste certificate content, or specify certificate IDs stored in the KMS.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Certificate Input</h3>

                        <Form.Item name="certificateBytes" style={{ display: "none" }}>
                            <Input />
                        </Form.Item>

                        <Form.Item>
                            <Radio.Group
                                value={certificateInputType}
                                onChange={(e) => {
                                  setCertificateInputType(e.target.value)
                                  form.setFieldsValue({ certificateBytes: undefined, certificateContent: undefined, uniqueIdentifier: undefined })
                                }}
                            >
                                <Radio.Button value="file">Upload Certificate File</Radio.Button>
                                <Radio.Button value="text">Paste Certificate Content</Radio.Button>
                                <Radio.Button value="id">Provide Certificate ID</Radio.Button>
                            </Radio.Group>
                        </Form.Item>

                        {certificateInputType === 'file' && (
                            <div>
                                <Form.Item
                                    name="certificateFile"
                                    label="Certificate File"
                                    help="Upload a certificate file for validation"
                                >
                                    <Upload
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const arrayBuffer = e.target?.result;
                                                if (arrayBuffer && arrayBuffer instanceof ArrayBuffer) {
                                                    const bytes = new Uint8Array(arrayBuffer);
                                                    form.setFieldsValue({ certificateBytes: bytes });
                                                }
                                            };
                                            reader.readAsArrayBuffer(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <Button icon={<UploadOutlined />}>Select Certificate File</Button>
                                    </Upload>
                                </Form.Item>
                            </div>
                        )}

                        {certificateInputType === 'text' && (
                            <Form.Item
                                name="certificateContent"
                                label="Certificate Content"
                                help="Paste the certificate content (PEM format)"
                                rules={[
                                    {
                                      validator: async (_, value) => {
                                          if (value) {
                                              try {
                                                  const encoder = new TextEncoder();
                                                  const uint8Array = encoder.encode(JSON.stringify(value));
                                                  form.setFieldValue("certificateBytes", uint8Array)
                                              } catch (e) {
                                                  throw new Error(`Invalid format: ${e}`);
                                              }
                                          }
                                      },
                                  },
                                ]}
                            >
                                <Input.TextArea
                                    placeholder="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
...
-----END CERTIFICATE-----"
                                    rows={10}
                                    className="font-mono text-sm"
                                />
                            </Form.Item>
                        )}

                        {certificateInputType === 'id' && (
                            <Form.Item
                                name="uniqueIdentifier"
                                label="Certificate Unique Identifier"
                                help="Unique identifiers of certificates stored in the KMS"
                            >
                                <Input placeholder="Enter certificate ID" />
                            </Form.Item>
                        )}

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
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Validate Certificate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <Card title="Validation Results">{res}</Card>}
        </div>
    );
};

export default CertificateValidateForm;
