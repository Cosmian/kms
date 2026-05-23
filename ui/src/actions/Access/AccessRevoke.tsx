import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface AccessRevokeFormData {
    user_id: string;
    unique_identifier: string;
    operation_types: Array<
        "create" | "get" | "getattributes" | "encrypt" | "decrypt" | "import" | "revoke" | "locate" | "rekey" | "destroy"
    >;
    revoke_create_access_right: boolean;
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

const AccessRevokeForm: React.FC = () => {
    const [form] = Form.useForm<AccessRevokeFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();
    const [isPrivilegedUser, setIsPrivilegedUser] = useState<boolean | undefined>(undefined);

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

    const onFinish = async (values: AccessRevokeFormData) => {
        await execute(async () => {
            if (values.revoke_create_access_right) {
                values.operation_types.push("create");
            }
            const response = await postNoTTLVRequest("/access/revoke", values, idToken, serverUrl);
            return response.success;
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Revoke access rights</h1>

            <div className="mb-8 space-y-2">
                <p>Revoke access rights from a user for specific KMIP operations on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ operation_types: [], revoke_create_access_right: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="user_id"
                            label="User Identifier"
                            rules={[{ required: true, message: "Please enter the user identifier" }]}
                            help="The user to revoke access from"
                        >
                            <Input placeholder="Enter user identifier" />
                        </Form.Item>

                        <Form.Item name="operation_types" label="KMIP Operations" help="Select one or more operations to revoke access to">
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
                                name="revoke_create_access_right"
                                valuePropName="checked"
                                help="If set, the user will no longer have the right to create or import Kms objects."
                            >
                                <Checkbox>Revoke create access right to user</Checkbox>
                            </Form.Item>
                        )}
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            danger
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            Revoke Access
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="Revoke access response" />
        </div>
    );
};

export default AccessRevokeForm;
