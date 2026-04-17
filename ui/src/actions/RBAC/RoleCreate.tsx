import { Button, Card, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { postNoTTLVRequest } from "../../utils/utils";

interface RoleCreateFormData {
    id: string;
    name: string;
    description?: string;
}

const RoleCreateForm: React.FC = () => {
    const [form] = Form.useForm<RoleCreateFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RoleCreateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest("/roles", values, idToken, serverUrl);
            setRes(`Role "${response.role.name}" (${response.role.id}) created successfully.`);
            form.resetFields();
        } catch (e) {
            setRes(`Error creating role: ${e}`);
            console.error("Error creating role:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create Role</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new RBAC role. After creation, use "Add Permissions" to grant KMIP operations and "Assign Users" to assign users.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="id"
                            label="Role ID"
                            rules={[
                                { required: true, message: "Please enter a role ID" },
                                { pattern: /^[a-z0-9-]+$/, message: "Use lowercase letters, numbers, and hyphens only" },
                            ]}
                            help="A unique slug identifier (e.g. 'data-processor')"
                        >
                            <Input placeholder="my-custom-role" data-testid="role-id-input" />
                        </Form.Item>

                        <Form.Item
                            name="name"
                            label="Display Name"
                            rules={[{ required: true, message: "Please enter a display name" }]}
                            help="A human-readable name for the role"
                        >
                            <Input placeholder="My Custom Role" data-testid="role-name-input" />
                        </Form.Item>

                        <Form.Item name="description" label="Description" help="Optional description of this role's purpose">
                            <Input.TextArea placeholder="Describe what this role is for..." rows={3} data-testid="role-desc-input" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium" data-testid="submit-btn">
                            Create Role
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Create role response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RoleCreateForm;
