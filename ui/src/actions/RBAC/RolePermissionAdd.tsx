import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { postNoTTLVRequest } from "../../utils/utils";

interface PermissionAddFormData {
    role_id: string;
    object_id: string;
    operations: string[];
}

const KMIP_OPERATIONS = [
    { label: "Create", value: "Create" },
    { label: "Certify", value: "Certify" },
    { label: "Decrypt", value: "Decrypt" },
    { label: "DeriveKey", value: "DeriveKey" },
    { label: "Destroy", value: "Destroy" },
    { label: "Encrypt", value: "Encrypt" },
    { label: "Export", value: "Export" },
    { label: "Get", value: "Get" },
    { label: "GetAttributes", value: "GetAttributes" },
    { label: "Hash", value: "Hash" },
    { label: "Import", value: "Import" },
    { label: "Locate", value: "Locate" },
    { label: "MAC", value: "MAC" },
    { label: "Rekey", value: "Rekey" },
    { label: "Revoke", value: "Revoke" },
    { label: "Sign", value: "Sign" },
    { label: "SignatureVerify", value: "SignatureVerify" },
    { label: "Validate", value: "Validate" },
];

const RolePermissionAddForm: React.FC = () => {
    const [form] = Form.useForm<PermissionAddFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [searchParams] = useSearchParams();

    useEffect(() => {
        const roleId = searchParams.get("roleId");
        if (roleId) {
            form.setFieldValue("role_id", roleId);
        }
    }, [searchParams, form]);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: PermissionAddFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                `/roles/${values.role_id}/permissions`,
                { object_id: values.object_id, operations: values.operations },
                idToken,
                serverUrl,
            );
            setRes(response.success);
        } catch (e) {
            setRes(`Error adding permissions: ${e}`);
            console.error("Error adding permissions:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Add Role Permissions</h1>

            <div className="mb-8 space-y-2">
                <p>Grant KMIP operations to a role for a specific object or all objects (wildcard <code>*</code>).</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ object_id: "*", operations: [] }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="role_id"
                            label="Role ID"
                            rules={[{ required: true, message: "Please enter the role ID" }]}
                            help="The role to add permissions to"
                        >
                            <Input placeholder="Enter role ID" data-testid="role-id-input" />
                        </Form.Item>

                        <Form.Item
                            name="operations"
                            label="KMIP Operations"
                            rules={[{ required: true, message: "Please select at least one operation" }]}
                            help="Select the KMIP operations to grant"
                        >
                            <Select
                                mode="multiple"
                                options={KMIP_OPERATIONS}
                                placeholder="Select operations"
                                data-testid="operations-select"
                            />
                        </Form.Item>

                        <Form.Item
                            name="object_id"
                            label="Object ID"
                            rules={[{ required: true, message: "Please enter an object ID" }]}
                            help="The object UID to grant on, or * for all objects"
                        >
                            <Input placeholder="* (all objects)" data-testid="object-id-input" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium" data-testid="submit-btn">
                            Add Permissions
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Add permissions response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RolePermissionAddForm;
