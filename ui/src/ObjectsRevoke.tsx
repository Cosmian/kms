import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getObjectLabel, getTypeString, ObjectType, sendKmipRequest } from "./utils";
import { parse_revoke_ttlv_response, revoke_ttlv_request } from "./wasm/pkg/cosmian_kms_client_wasm";

interface RevokeFormData {
    revocationReasonMessage: string;
    objectId?: string;
    tags?: string[];
}

interface RevokeFormProps {
    objectType: ObjectType;
}

type RevokeResponse = {
    UniqueIdentifier: string;
};

interface RevocationReason {
    revocation_reason_code: string;
    revocation_message: string;
}

const RevokeForm: React.FC<RevokeFormProps> = ({ objectType }) => {
    const [form] = Form.useForm<RevokeFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    const label = getObjectLabel(objectType);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RevokeFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.objectId || (values.tags ? JSON.stringify(values.tags) : undefined);
        if (!id) {
            setRes(`Missing ${label} identifier.`);
            throw new Error(`Missing ${label} identifier`);
        }

        try {
            const revocationReason: RevocationReason = {
                revocation_reason_code: "Unspecified",
                revocation_message: values.revocationReasonMessage,
            };
            const request = revoke_ttlv_request(id, revocationReason);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: RevokeResponse = await parse_revoke_ttlv_response(result_str);
                setRes(`${result.UniqueIdentifier} has been revoked.`);
            }
        } catch (e) {
            setRes(`Error revoking ${label}: ${e}`);
            console.error(`Error revoking ${label}:`, e);
        } finally {
            setIsLoading(false);
        }
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
                        <Button type="primary" htmlType="submit" loading={isLoading} danger className="w-full text-white font-medium">
                            Revoke {label.charAt(0).toUpperCase() + label.slice(1)}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef}>
                    <Card title={`${label.charAt(0).toUpperCase() + label.slice(1)} revoke response`}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RevokeForm;
