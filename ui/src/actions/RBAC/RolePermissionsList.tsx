import { Card, Input, Space, Table, Tag, Form, Button } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest } from "../../utils/utils";

interface PermissionEntry {
    object_id: string;
    operations: string[];
}

const RolePermissionsList: React.FC = () => {
    const [form] = Form.useForm<{ role_id: string }>();
    const [permissions, setPermissions] = useState<PermissionEntry[]>([]);
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

    const fetchPermissions = useCallback(
        async (roleId: string) => {
            setIsLoading(true);
            setRes(undefined);
            setCurrentRoleId(roleId);
            try {
                const response = await getNoTTLVRequest(`/roles/${roleId}/permissions`, idToken, serverUrl);
                setPermissions(response.permissions ?? []);
            } catch (e) {
                setRes(`Error fetching permissions: ${e}`);
                setPermissions([]);
                console.error("Error fetching permissions:", e);
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
            fetchPermissions(roleId);
        }
    }, [searchParams, form, fetchPermissions]);

    const onFinish = async (values: { role_id: string }) => {
        await fetchPermissions(values.role_id);
    };

    const columns = [
        {
            title: "Object ID",
            dataIndex: "object_id",
            key: "object_id",
            render: (id: string) => (id === "*" ? <Tag color="gold">* (all objects)</Tag> : <code>{id}</code>),
        },
        {
            title: "Operations",
            dataIndex: "operations",
            key: "operations",
            render: (ops: string[]) => (
                <Space wrap>
                    {ops.map((op) => (
                        <Tag key={op} color="blue">
                            {op}
                        </Tag>
                    ))}
                </Space>
            ),
        },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Role Permissions</h1>

            <div className="mb-8 space-y-2">
                <p>View the KMIP operations granted to a role, grouped by object.</p>
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
                                List Permissions
                            </Button>
                        </Form.Item>
                    </Card>
                </Space>
            </Form>

            {currentRoleId && (
                <div className="mt-4">
                    <Card title={`Permissions for role "${currentRoleId}"`}>
                        <Table
                            dataSource={permissions}
                            columns={columns}
                            rowKey="object_id"
                            loading={isLoading}
                            pagination={false}
                            locale={{ emptyText: "No permissions assigned to this role." }}
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

export default RolePermissionsList;
