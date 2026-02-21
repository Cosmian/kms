import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest, postNoTTLVRequest } from "./utils";

interface AccessGrantFormData {
    user_id: string;
    unique_identifier: string;
    operation_types: Array<"create" | "get" | "getattributes" | "encrypt" | "decrypt" | "import" | "revoke" | "locate" | "rekey" | "destroy">;
    grant_create_access_right: boolean;
}

const KMIP_OPERATIONS = [
    { label: "Get", value: "get" },
    { label: "GetAttributes", value: "getattributes" },
    { label: "Encrypt", value: "encrypt" },
    { label: "Decrypt", value: "decrypt" },
    { label: "Revoke", value: "revoke" },
    { label: "Locate", value: "locate" },
    { label: "Rekey", value: "rekey" },
    { label: "Destroy", value: "destroy" },
];

const AccessGrantForm: React.FC = () => {
    const [form] = Form.useForm<AccessGrantFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const [isPrivilegedUser, setIsPrivilegedUser] = useState<boolean | undefined>(undefined);

    const responseRef = useRef<HTMLDivElement>(null);

    const fetchPrivilegedAccess = useCallback(async () => {
        setIsPrivilegedUser(undefined);
        try {
            const response = await getNoTTLVRequest("/access/privileged", idToken, serverUrl);
            setIsPrivilegedUser(response.has_privileged_access);
        } catch (e) {
            console.error("Error fetching privileged access:", e);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchPrivilegedAccess();
    }, [fetchPrivilegedAccess]);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AccessGrantFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            if (values.grant_create_access_right) {
                values.operation_types.push("create");
            }
            const response = await postNoTTLVRequest("/access/grant", values, idToken, serverUrl);
            setRes(response.success);
        } catch (e) {
            setRes(`Error granting access: ${e}`);
            console.error("Error granting access:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Grant access rights</h1>

            <div className="mb-8 space-y-2">
                <p>Grant access rights to another user for specific KMIP operations on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ operation_types: [], grant_create_access_right: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="user_id"
                            label="User Identifier"
                            rules={[{ required: true, message: "Please enter the user identifier" }]}
                            help="The user to grant access to"
                        >
                            <Input placeholder="Enter user identifier" />
                        </Form.Item>

                        <Form.Item name="operation_types" label="KMIP Operations" help="Select one or more operations to grant access to">
                            <Select
                                mode="multiple"
                                options={KMIP_OPERATIONS}
                                placeholder="Select operations"
                                onChange={() => {
                                    form.validateFields(["unique_identifier"]);
                                }}
                            />
                        </Form.Item>

                        <Form.Item
                            label="Object UID"
                            shouldUpdate={(prevValues, currentValues) => prevValues.operation_types !== currentValues.operation_types}
                        >
                            {({ getFieldValue }) => {
                                const ops = getFieldValue("operation_types") || [];
                                return (
                                    <Form.Item
                                        name="unique_identifier"
                                        rules={[
                                            {
                                                required: ops.length > 0,
                                                message: "Please enter the object UID",
                                            },
                                        ]}
                                        help="The unique identifier of the object stored in the KMS"
                                    >
                                        <Input placeholder="Enter object UID" disabled={ops.length === 0} />
                                    </Form.Item>
                                );
                            }}
                        </Form.Item>

                        {isPrivilegedUser && (
                            <Form.Item
                                name="grant_create_access_right"
                                valuePropName="checked"
                                help="If set, the user will have the right to create and import Kms objects."
                            >
                                <Checkbox>Grant create access right to user</Checkbox>
                            </Form.Item>
                        )}
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Grant Access
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Grant access response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default AccessGrantForm;
