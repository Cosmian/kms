import { Button, Card, Space, Table, Tag, Tooltip, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { useNotifications } from "../hooks/useNotifications";
import { getNoTTLVRequest, postNoTTLVRequest } from "../utils/utils";

interface NotificationItem {
    id: number;
    event_type: string;
    message: string;
    object_id: string | null;
    created_at: string;
    read_at: string | null;
}

interface NotificationListResponse {
    items: NotificationItem[];
    total_unread: number;
    page: number;
    page_size: number;
}

const EVENT_TYPE_COLORS: Record<string, string> = {
    key_rotation_success: "green",
    key_rotation_failure: "red",
};

const NotificationsPage: React.FC = () => {
    const { idToken, serverUrl } = useAuth();
    const { fetchUnreadCount } = useNotifications();
    const [items, setItems] = useState<NotificationItem[]>([]);
    const [loading, setLoading] = useState(false);

    const fetchAndMarkRead = useCallback(async () => {
        setLoading(true);
        try {
            const data = (await getNoTTLVRequest("/notifications?page=0&page_size=50", idToken, serverUrl)) as NotificationListResponse;
            setItems(data?.items ?? []);
            // Mark all as read after fetching
            await postNoTTLVRequest("/notifications/read-all", {}, idToken, serverUrl);
            await fetchUnreadCount();
        } catch {
            // ignore
        } finally {
            setLoading(false);
        }
    }, [idToken, serverUrl, fetchUnreadCount]);

    useEffect(() => {
        void fetchAndMarkRead();
    }, [fetchAndMarkRead]);

    const markOneRead = async (id: number) => {
        try {
            await postNoTTLVRequest(`/notifications/${id}/read`, {}, idToken, serverUrl);
            setItems((prev) => prev.map((item) => (item.id === id ? { ...item, read_at: new Date().toISOString() } : item)));
            await fetchUnreadCount();
        } catch {
            // ignore
        }
    };

    const columns: ColumnsType<NotificationItem> = [
        {
            title: "Type",
            dataIndex: "event_type",
            key: "event_type",
            width: 200,
            render: (type: string) => <Tag color={EVENT_TYPE_COLORS[type] ?? "default"}>{type.replace(/_/g, " ")}</Tag>,
        },
        {
            title: "Message",
            dataIndex: "message",
            key: "message",
            ellipsis: true,
            render: (msg: string) => (
                <Tooltip title={msg}>
                    <Typography.Text ellipsis>{msg}</Typography.Text>
                </Tooltip>
            ),
        },
        {
            title: "Object UID",
            dataIndex: "object_id",
            key: "object_id",
            width: 160,
            render: (oid: string | null) =>
                oid ? (
                    <Tooltip title={oid}>
                        <Typography.Text code ellipsis style={{ maxWidth: 140, display: "inline-block" }}>
                            {oid}
                        </Typography.Text>
                    </Tooltip>
                ) : (
                    "—"
                ),
        },
        {
            title: "Date",
            dataIndex: "created_at",
            key: "created_at",
            width: 180,
            render: (ts: string) => new Date(ts).toLocaleString(),
        },
        {
            title: "Status",
            dataIndex: "read_at",
            key: "read_at",
            width: 90,
            render: (ra: string | null) => (ra ? <Tag color="default">Read</Tag> : <Tag color="blue">Unread</Tag>),
        },
    ];

    return (
        <Card
            title="Notifications"
            extra={
                <Space>
                    <Button onClick={() => void fetchAndMarkRead()} loading={loading}>
                        Refresh
                    </Button>
                    <Button
                        onClick={() =>
                            void postNoTTLVRequest("/notifications/read-all", {}, idToken, serverUrl).then(async () => {
                                setItems((prev) =>
                                    prev.map((item) => ({
                                        ...item,
                                        read_at: item.read_at ?? new Date().toISOString(),
                                    })),
                                );
                                await fetchUnreadCount();
                            })
                        }
                    >
                        Mark all read
                    </Button>
                </Space>
            }
        >
            <Table<NotificationItem>
                data-testid="notifications-table"
                rowKey="id"
                dataSource={items}
                columns={columns}
                loading={loading}
                pagination={{ pageSize: 20 }}
                onRow={(record) => ({
                    onClick: () => {
                        if (!record.read_at) {
                            void markOneRead(record.id);
                        }
                    },
                    style: { cursor: record.read_at ? "default" : "pointer" },
                })}
            />
        </Card>
    );
};

export default NotificationsPage;
