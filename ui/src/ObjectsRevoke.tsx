import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { parse_revoke_ttlv_response, revoke_ttlv_request } from "./wasm/pkg/cosmian_kms_client_wasm";

interface RevokeFormData {
    revocationReasonMessage: string;
    objectId?: string;
    tags?: string[];
}

type ObjectType = "rsa" | "ec" | "symmetric" | "covercrypt" | "certificate" | "secret-data";

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

const RevokeForm: React.FC<RevokeFormProps> = (props: RevokeFormProps) => {
    const [form] = Form.useForm<RevokeFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RevokeFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.objectId ? values.objectId : values.tags ? JSON.stringify(values.tags) : undefined;
        if (id == undefined) {
            setRes(`Missing ${isKeyType ? "key" : "certificate"} identifier.`);
            throw Error(`Missing ${isKeyType ? "key" : "certificate"} identifier`);
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
            setRes(`Error revoking ${isKeyType ? "key" : "certificate"}: ${e}`);
            console.error(`Error revoking ${isKeyType ? "key" : "certificate"}:`, e);
        } finally {
            setIsLoading(false);
        }
    };

    const isKeyType = props.objectType !== "certificate";
    const objectTypeLabel = isKeyType ? "key" : "certificate";

    let typeString = "";
    if (props.objectType === "rsa") {
        typeString = "an RSA";
    } else if (props.objectType === "ec") {
        typeString = "an EC";
    } else if (props.objectType === "covercrypt") {
        typeString = "a CoverCrypt";
    } else if (props.objectType === "symmetric") {
        typeString = "a symmetric";
    } else if (props.objectType === "secret-data") {
        typeString = "a secret data";
    } else {
        typeString = "a";
    }

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold">
                    Revoke {typeString} {objectTypeLabel}
                </h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border-l-4 border-red-600 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p>
                            <strong>Warning:</strong> This action cannot be undone.
                        </p>
                        <p>
                            Once a {objectTypeLabel} is revoked, it can only be exported by the owner by checking the <i>allow-revoked</i>{" "}
                            flag.
                        </p>
                        {(props.objectType === "rsa" || props.objectType === "ec") && (
                            <p>Revoking either the public or private key will revoke the whole key pair.</p>
                        )}
                        {props.objectType === "certificate" && <p>Revoking a certificate does not revoke its associated private key.</p>}
                    </div>
                </div>
                <div>Revoking a key from a keypair will revoke both the public and private keys.</div>
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
                                    message: `Please specify the reason for ${objectTypeLabel} revocation`,
                                },
                            ]}
                            help={`Provide a clear reason for revoking this ${objectTypeLabel}`}
                        >
                            <Input.TextArea placeholder={`Enter the reason for ${objectTypeLabel} revocation`} rows={3} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{isKeyType ? "Key" : "Certificate"} Identification (required)</h3>

                        <Form.Item
                            name="objectId"
                            label={`${isKeyType ? "Key" : "Certificate"} ID`}
                            help={`The unique identifier of the ${objectTypeLabel} to revoke`}
                        >
                            <Input placeholder={`Enter ${objectTypeLabel} ID`} />
                        </Form.Item>

                        <Form.Item
                            name="tags"
                            label="Tags"
                            help={`Alternative to ${isKeyType ? "Key" : "Certificate"} ID: specify tags to identify the ${objectTypeLabel}`}
                        >
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} danger className="w-full text-white font-medium">
                            Revoke {isKeyType ? "Key" : "Certificate"}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title={`${isKeyType ? "Key" : "Certificate"} revoke response`}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RevokeForm;
