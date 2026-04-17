import { Button, Card, Space, Table, Tag, Tooltip, Modal } from "antd";
import { DeleteOutlined, EditOutlined, ReloadOutlined, TeamOutlined, UnlockOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { deleteNoTTLVRequest, getNoTTLVRequest } from "../../utils/utils";

interface Role {
    id: string;
    name: string;
    description?: string;
    builtin: boolean;
}

const RolesList: React.FC = () => {
    const [roles, setRoles] = useState<Role[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchRoles = useCallback(async () => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await getNoTTLVRequest("/roles", idToken, serverUrl);
            setRoles(response.roles ?? []);
        } catch (e) {
            setRes(`Error fetching roles: ${e}`);
            console.error("Error fetching roles:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchRoles();
    }, [fetchRoles]);

    const handleDelete = async (roleId: string) => {
        Modal.confirm({
            title: `Delete role "${roleId}"?`,
            content: "This will remove the role and all its associated permissions and user assignments.",
            okText: "Delete",
            okType: "danger",
            onOk: async () => {
                try {
                    const response = await deleteNoTTLVRequest(`/roles/${roleId}`, idToken, serverUrl);
                    setRes(response.success);
                    await fetchRoles();
                } catch (e) {
                    setRes(`Error deleting role: ${e}`);
                    console.error("Error deleting role:", e);
                }
            },
        });
    };

    const columns = [
        {
            title: "ID",
            dataIndex: "id",
            key: "id",
            render: (id: string) => <code>{id}</code>,
        },
        {
            title: "Name",
            dataIndex: "name",
            key: "name",
        },
        {
            title: "Description",
            dataIndex: "description",
            key: "description",
            render: (desc: string | undefined) => desc ?? <span className="text-gray-400">—</span>,
        },
        {
            title: "Type",
            dataIndex: "builtin",
            key: "builtin",
            render: (builtin: boolean) => (builtin ? <Tag color="blue">Built-in</Tag> : <Tag>Custom</Tag>),
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: Role) => (
                <Space>
                    <Tooltip title="View permissions">
                        <Button size="small" icon={<UnlockOutlined />} href={`#/roles/permissions?roleId=${record.id}`} />
                    </Tooltip>
                    <Tooltip title="View members">
                        <Button size="small" icon={<TeamOutlined />} href={`#/roles/members?roleId=${record.id}`} />
                    </Tooltip>
                    {!record.builtin && (
                        <>
                            <Tooltip title="Edit">
                                <Button size="small" icon={<EditOutlined />} href={`#/roles/update?roleId=${record.id}`} />
                            </Tooltip>
                            <Tooltip title="Delete">
                                <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record.id)} />
                            </Tooltip>
                        </>
                    )}
                </Space>
            ),
        },
    ];

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">RBAC Roles</h1>
                <Button type="default" icon={<ReloadOutlined />} onClick={fetchRoles} loading={isLoading}>
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>
                    Roles are named bundles of permissions that can be assigned to users.
                    Built-in roles are seeded automatically and cannot be deleted.
                </p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                <Card>
                    <Table
                        dataSource={roles}
                        columns={columns}
                        rowKey="id"
                        loading={isLoading}
                        pagination={{ defaultPageSize: 10, showSizeChanger: true, pageSizeOptions: [10, 20, 50] }}
                    />
                </Card>
            </Space>

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

export default RolesList;
