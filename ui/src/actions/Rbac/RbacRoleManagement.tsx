import { Button, Card, Form, Input, Select, Space, Table, Tag, Popconfirm } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { deleteNoTTLVRequest, getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";

interface RoleAssignment {
    user_id: string;
    role: string;
}

interface AssignRoleFormData {
    user_id: string;
    role: string;
}

const BUILT_IN_ROLES = [
    { label: "Administrator", value: "administrator" },
    { label: "Operator", value: "operator" },
    { label: "Auditor", value: "auditor" },
    { label: "Read Only", value: "readonly" },
];

const RbacRoleManagement: React.FC = () => {
    const [form] = Form.useForm<AssignRoleFormData>();
    const [assignments, setAssignments] = useState<RoleAssignment[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    const fetchAssignments = useCallback(async () => {
        setIsLoading(true);
        try {
            const response: RoleAssignment[] = await getNoTTLVRequest("/rbac/roles", idToken, serverUrl);
            setAssignments(response);
            setRes(undefined);
        } catch (e) {
            setRes(`Error fetching role assignments: ${e}`);
            console.error("Error fetching role assignments:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        if (idToken) {
            fetchAssignments();
        } else {
            setAssignments([]);
        }
    }, [fetchAssignments, idToken]);

    const onFinish = async (values: AssignRoleFormData) => {
        setIsSubmitting(true);
        setRes(undefined);
        try {
            await postNoTTLVRequest("/rbac/roles", values, idToken, serverUrl);
            setRes(`Role '${values.role}' assigned to user '${values.user_id}'`);
            form.resetFields();
            await fetchAssignments();
        } catch (e) {
            setRes(`Error assigning role: ${e}`);
            console.error("Error assigning role:", e);
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleRemove = async (userId: string, role: string) => {
        try {
            await deleteNoTTLVRequest("/rbac/roles", { user_id: userId, role }, idToken, serverUrl);
            setRes(`Role '${role}' removed from user '${userId}'`);
            await fetchAssignments();
        } catch (e) {
            setRes(`Error removing role: ${e}`);
            console.error("Error removing role:", e);
        }
    };

    const roleColors: Record<string, string> = {
        administrator: "red",
        operator: "blue",
        auditor: "green",
        readonly: "default",
    };

    const columns = [
        {
            title: "User",
            dataIndex: "user_id",
            key: "user_id",
            sorter: (a: RoleAssignment, b: RoleAssignment) => a.user_id.localeCompare(b.user_id),
        },
        {
            title: "Role",
            dataIndex: "role",
            key: "role",
            render: (role: string) => <Tag color={roleColors[role] || "default"}>{role}</Tag>,
            sorter: (a: RoleAssignment, b: RoleAssignment) => a.role.localeCompare(b.role),
        },
        {
            title: "Actions",
            key: "actions",
            render: (_value: unknown, record: RoleAssignment) => (
                <Popconfirm
                    title={`Remove role '${record.role}' from '${record.user_id}'?`}
                    onConfirm={() => handleRemove(record.user_id, record.role)}
                    okText="Yes"
                    cancelText="No"
                >
                    <Button type="link" danger data-testid={`remove-${record.user_id}-${record.role}`}>
                        Remove
                    </Button>
                </Popconfirm>
            ),
        },
    ];

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">RBAC Role Management</h1>
                <Button type="primary" onClick={fetchAssignments} loading={isLoading} className="bg-primary">
                    Refresh
                </Button>
            </div>

            <Space direction="vertical" size="large" style={{ display: "flex" }}>
                <Card title="Assign Role">
                    <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ role: "operator" }}>
                        <Space direction="horizontal" size="middle" wrap>
                            <Form.Item
                                name="user_id"
                                label="User Identifier"
                                rules={[{ required: true, message: "Please enter a user identifier" }]}
                            >
                                <Input
                                    placeholder="user@example.com"
                                    style={{ minWidth: 250 }}
                                    data-testid="rbac-user-id"
                                />
                            </Form.Item>
                            <Form.Item name="role" label="Role" rules={[{ required: true, message: "Please select a role" }]}>
                                <Select
                                    options={BUILT_IN_ROLES}
                                    style={{ minWidth: 180 }}
                                    data-testid="rbac-role-select"
                                />
                            </Form.Item>
                            <Form.Item label=" ">
                                <Button type="primary" htmlType="submit" loading={isSubmitting} data-testid="rbac-assign-btn">
                                    Assign Role
                                </Button>
                            </Form.Item>
                        </Space>
                    </Form>
                </Card>

                {res && (
                    <div ref={responseRef} data-testid="rbac-response">
                        <Card>{res}</Card>
                    </div>
                )}

                <Card title="Current Role Assignments">
                    <Table
                        dataSource={assignments}
                        columns={columns}
                        rowKey={(record) => `${record.user_id}-${record.role}`}
                        loading={isLoading}
                        pagination={false}
                        data-testid="rbac-assignments-table"
                        locale={{ emptyText: "No role assignments" }}
                    />
                </Card>
            </Space>
        </div>
    );
};

export default RbacRoleManagement;
