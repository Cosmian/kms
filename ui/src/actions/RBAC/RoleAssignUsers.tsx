import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { postNoTTLVRequest } from "../../utils/utils";

interface AssignUsersFormData {
    role_id: string;
    user_ids: string[];
}

const RoleAssignUsers: React.FC = () => {
    const [form] = Form.useForm<AssignUsersFormData>();
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

    const onFinish = async (values: AssignUsersFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                `/roles/${values.role_id}/users`,
                { user_ids: values.user_ids },
                idToken,
                serverUrl,
            );
            setRes(response.success);
        } catch (e) {
            setRes(`Error assigning users: ${e}`);
            console.error("Error assigning users:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Assign Users to Role</h1>

            <div className="mb-8 space-y-2">
                <p>Assign one or more users to a role. Users will inherit all permissions granted to the role.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ user_ids: [] }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="role_id"
                            label="Role ID"
                            rules={[{ required: true, message: "Please enter the role ID" }]}
                            help="The role to assign users to"
                        >
                            <Input placeholder="Enter role ID" data-testid="role-id-input" />
                        </Form.Item>

                        <Form.Item
                            name="user_ids"
                            label="User Identifiers"
                            rules={[{ required: true, message: "Please enter at least one user" }]}
                            help="Type a user identifier and press Enter to add"
                        >
                            <Select
                                mode="tags"
                                placeholder="Type user identifiers and press Enter"
                                data-testid="user-ids-select"
                                tokenSeparators={[","]}
                            />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium" data-testid="submit-btn">
                            Assign Users
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Assign users response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RoleAssignUsers;
