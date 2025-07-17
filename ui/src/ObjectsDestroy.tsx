import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { destroy_ttlv_request, parse_destroy_ttlv_response } from "./wasm/pkg/cosmian_kms_client_wasm";

interface DestroyFormData {
    objectId?: string;
    tags?: string[];
    remove: boolean;
}

type ObjectType = "rsa" | "ec" | "symmetric" | "covercrypt" | "certificate" | "secret-data";

interface DestroyFormProps {
    objectType: ObjectType;
}

type DestroyResponse = {
    UniqueIdentifier: string;
};

const DestroyForm: React.FC<DestroyFormProps> = (props: DestroyFormProps) => {
    const [form] = Form.useForm<DestroyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const isKeyType = props.objectType !== "certificate";
    const objectTypeLabel = isKeyType ? "key" : "certificate";

    const onFinish = async (values: DestroyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.objectId ? values.objectId : values.tags ? JSON.stringify(values.tags) : undefined;
        if (id == undefined) {
            setRes(`Missing ${objectTypeLabel} identifier.`);
            throw Error(`Missing ${objectTypeLabel} identifier`);
        }

        try {
            const request = destroy_ttlv_request(id, values.remove);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: DestroyResponse = await parse_destroy_ttlv_response(result_str);
                setRes(`${result.UniqueIdentifier} has been destroyed.`);
            }
        } catch (e) {
            setRes(`Error destroying ${objectTypeLabel}: ${e}`);
            console.error(`Error destroying ${objectTypeLabel}:`, e);
        } finally {
            setIsLoading(false);
        }
    };

    let typeString = "";
    if (props.objectType === "rsa") {
        typeString = "an RSA";
    } else if (props.objectType === "ec") {
        typeString = "an EC";
    } else if (props.objectType === "covercrypt") {
        typeString = "a Covercrypt";
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
                <WarningFilled className="text-2xl text-red-600" />
                <h1 className="text-2xl font-bold">
                    Destroy {typeString} {objectTypeLabel}
                </h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border-l-4 border-red-600 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p className="font-bold">Warning: This is a destructive action.</p>
                        <ul className="list-disc pl-5 space-y-1">
                            <li>The {objectTypeLabel} must be revoked first</li>
                            {isKeyType &&
                                (props.objectType === "rsa" || props.objectType === "ec" || props.objectType === "covercrypt") && (
                                    <li>Destroying either public or private key will destroy the whole key pair</li>
                                )}
                            {isKeyType && <li>Keys in external stores (HSMs) are automatically removed</li>}
                            {props.objectType === "certificate" && (
                                <li>Destroying a certificate does not destroy its associated private key</li>
                            )}
                            <li>Destroyed {objectTypeLabel}s can only be exported by the owner, without key material</li>
                        </ul>
                    </div>
                </div>
                <div>Destroying a key from a keypair will delete both the public and private keys.</div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    remove: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{isKeyType ? "Key" : "Certificate"} Identification (required)</h3>

                        <Form.Item
                            name="objectId"
                            label={`${isKeyType ? "Key" : "Certificate"} ID`}
                            help={`The unique identifier of the ${objectTypeLabel} to destroy`}
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
                    <Card>
                        <Form.Item
                            name="remove"
                            valuePropName="checked"
                            help={`If enabled, the ${objectTypeLabel} will be completely removed from the database. Otherwise, metadata will be retained.`}
                        >
                            <Checkbox>Remove completely from database</Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            disabled={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Destroy {isKeyType ? "Key" : "Certificate"}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title={`${isKeyType ? "Key" : "Certificate"} destroy response`}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default DestroyForm;
