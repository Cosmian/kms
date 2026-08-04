import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { getObjectLabel, getTypeString, ObjectType, sendKmipRequest } from "../../utils/utils";
import { parse_revoke_ttlv_response, revoke_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";

interface RevokeFormData {
    revocationReasonMessage: string;
    revocationReasonCode: string;
    objectId?: string;
    tags?: string[];
}

interface RevokeFormProps {
    objectType: ObjectType;
}

type RevokeResponse = {
    UniqueIdentifier: string;
};

const RevokeForm: React.FC<RevokeFormProps> = ({ objectType }) => {
    const [form] = Form.useForm<RevokeFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();

    const label = getObjectLabel(objectType);

    const onFinish = async (values: RevokeFormData) => {
        const id = values.objectId || (values.tags ? JSON.stringify(values.tags) : undefined);
        await execute(async () => {
            if (!id) {
                throw new Error(`Missing ${label} identifier.`);
            }
            const request = revoke_ttlv_request(id, values.revocationReasonMessage, values.revocationReasonCode);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: RevokeResponse = await parse_revoke_ttlv_response(result_str);
                return `${result.UniqueIdentifier} has been revoked.`;
            }
        });
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold">
                    Revoke {getTypeString(objectType)} {label}
                </h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border-l-4 border-red-600 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p>
                            <strong>Warning:</strong> This action cannot be undone.
                        </p>
                        <p>
                            Once a {label} is revoked, it can only be exported by the owner using the <i>allow-revoked</i> flag.
                        </p>
                        {(objectType === "rsa" || objectType === "ec") && (
                            <p>Revoking either the public or private key will revoke the whole key pair.</p>
                        )}
                        {objectType === "certificate" && <p>Revoking a certificate does not revoke its associated private key.</p>}
                    </div>
                </div>
                <div>Revoking a {label} is irreversible and may affect dependent applications.</div>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="revocationReasonCode"
                            label="Revocation Reason Code"
                            initialValue="unspecified"
                            rules={[{ required: true, message: "Please select a revocation reason code" }]}
                            help="Key Compromise and CA Compromise transition the object to the Compromised state; all other codes produce Deactivated"
                        >
                            <Select data-testid="revocation-reason-code">
                                <Select.Option value="unspecified">Unspecified</Select.Option>
                                <Select.Option value="key-compromise">Key Compromise → Compromised</Select.Option>
                                <Select.Option value="ca-compromise">CA Compromise → Compromised</Select.Option>
                                <Select.Option value="affiliation-changed">Affiliation Changed → Deactivated</Select.Option>
                                <Select.Option value="superseded">Superseded → Deactivated</Select.Option>
                                <Select.Option value="cessation-of-operation">Cessation of Operation → Deactivated</Select.Option>
                                <Select.Option value="privilege-withdrawn">Privilege Withdrawn → Deactivated</Select.Option>
                            </Select>
                        </Form.Item>
                        <Form.Item
                            name="revocationReasonMessage"
                            label="Revocation Reason Message"
                            rules={[
                                {
                                    required: true,
                                    message: `Please specify the reason for ${label} revocation`,
                                },
                            ]}
                            help={`Provide a clear reason for revoking this ${label}`}
                        >
                            <Input.TextArea placeholder={`Enter the reason for ${label} revocation`} rows={3} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">
                            {label.charAt(0).toUpperCase() + label.slice(1)} Identification (required)
                        </h3>

                        <Form.Item
                            name="objectId"
                            label={`${label.charAt(0).toUpperCase() + label.slice(1)} ID`}
                            help={`The unique identifier of the ${label} to revoke`}
                        >
                            <Input placeholder={`Enter ${label} ID`} />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help={`Alternative to ${label} ID: specify tags to identify the ${label}`}>
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            Revoke {label.charAt(0).toUpperCase() + label.slice(1)}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={`${label.charAt(0).toUpperCase() + label.slice(1)} revoke response`}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RevokeForm;
