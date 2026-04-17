import { Button, Card, Form, Input, Space, Table } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { deleteNoTTLVRequest, getNoTTLVRequest } from "../../utils/utils";

interface UserRole {
    user_id: string;
    role_id: string;
    granted_by: string;
}

const RoleMembersList: React.FC = () => {
    const [form] = Form.useForm<{ role_id: string }>();
    const [members, setMembers] = useState<UserRole[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const [currentRoleId, setCurrentRoleId] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [searchParams] = useSearchParams();

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchMembers = useCallback(
        async (roleId: string) => {
            setIsLoading(true);
            setRes(undefined);
            setCurrentRoleId(roleId);
            try {
                const response = await getNoTTLVRequest(`/roles/${roleId}/users`, idToken, serverUrl);
                setMembers(response.users ?? []);
            } catch (e) {
                setRes(`Error fetching members: ${e}`);
                setMembers([]);
                console.error("Error fetching members:", e);
            } finally {
                setIsLoading(false);
            }
        },
        [idToken, serverUrl],
    );

    useEffect(() => {
        const roleId = searchParams.get("roleId");
        if (roleId) {
            form.setFieldValue("role_id", roleId);
            fetchMembers(roleId);
        }
    }, [searchParams, form, fetchMembers]);

    const onFinish = async (values: { role_id: string }) => {
        await fetchMembers(values.role_id);
    };

    const handleRevoke = async (userId: string) => {
        if (!currentRoleId) return;
        try {
            const response = await deleteNoTTLVRequest(`/roles/${currentRoleId}/users/${userId}`, idToken, serverUrl);
            setRes(response.success);
            await fetchMembers(currentRoleId);
        } catch (e) {
            setRes(`Error revoking user: ${e}`);
            console.error("Error revoking user:", e);
        }
    };

    const columns = [
        {
            title: "User ID",
            dataIndex: "user_id",
            key: "user_id",
        },
        {
            title: "Granted By",
            dataIndex: "granted_by",
            key: "granted_by",
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: UserRole) => (
                <Button size="small" danger onClick={() => handleRevoke(record.user_id)}>
                    Revoke
                </Button>
            ),
        },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Role Members</h1>

            <div className="mb-8 space-y-2">
                <p>View and manage users assigned to a role. You can revoke individual user assignments.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="role_id"
                            label="Role ID"
                            rules={[{ required: true, message: "Please enter the role ID" }]}
                        >
                            <Input placeholder="Enter role ID" data-testid="role-id-input" />
                        </Form.Item>
                        <Form.Item>
                            <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                                List Members
                            </Button>
                        </Form.Item>
                    </Card>
                </Space>
            </Form>

            {currentRoleId && (
                <div className="mt-4">
                    <Card title={`Members of role "${currentRoleId}"`}>
                        <Table
                            dataSource={members}
                            columns={columns}
                            rowKey="user_id"
                            loading={isLoading}
                            pagination={false}
                            locale={{ emptyText: "No users assigned to this role." }}
                        />
                    </Card>
                </div>
            )}

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Response" className="mt-4">
                        {res}
                    </Card>
                </div>
            )}
        </div>
    );
};

export default RoleMembersList;
