import { BellOutlined, CheckOutlined } from "@ant-design/icons";
import { Badge, Button, Drawer, Empty, List, Tag, Tooltip, Typography } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";

const { Text } = Typography;

interface NotificationItem {
    id: number;
    event_type: string;
    message: string;
    object_id: string | null;
    created_at: string;
    read_at: string | null;
}

const eventTypeColor: Record<string, string> = {
    approaching_deadline: "orange",
    rotation_success: "green",
    rotation_failure: "red",
};

const NotificationsBell: React.FC = () => {
    const { idToken, serverUrl } = useAuth();
    const [unreadCount, setUnreadCount] = useState(0);
    const [notifications, setNotifications] = useState<NotificationItem[]>([]);
    const [open, setOpen] = useState(false);
    const [loading, setLoading] = useState(false);

    const fetchUnreadCount = useCallback(async () => {
        try {
            const data = await getNoTTLVRequest("/notifications/unread/count", idToken, serverUrl);
            if (data && typeof data.count === "number") {
                setUnreadCount(data.count);
            }
        } catch {
            // Silently ignore — the endpoint may not be available
        }
    }, [idToken, serverUrl]);

    const fetchNotifications = useCallback(async () => {
        setLoading(true);
        try {
            const data = await getNoTTLVRequest("/notifications?limit=50", idToken, serverUrl);
            if (data && Array.isArray(data.notifications)) {
                setNotifications(data.notifications as NotificationItem[]);
            }
        } catch {
            // Silently ignore
        } finally {
            setLoading(false);
        }
    }, [idToken, serverUrl]);

    // Poll unread count every 30 seconds
    useEffect(() => {
        fetchUnreadCount();
        const timer = setInterval(fetchUnreadCount, 30_000);
        return () => clearInterval(timer);
    }, [fetchUnreadCount]);

    const handleOpen = () => {
        setOpen(true);
        fetchNotifications();
    };

    const handleMarkRead = async (id: number) => {
        try {
            await postNoTTLVRequest(`/notifications/${id}/read`, {}, idToken, serverUrl);
            setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read_at: new Date().toISOString() } : n)));
            setUnreadCount((c) => Math.max(0, c - 1));
        } catch {
            // Silently ignore
        }
    };

    const handleMarkAllRead = async () => {
        try {
            await postNoTTLVRequest("/notifications/read-all", {}, idToken, serverUrl);
            setNotifications((prev) => prev.map((n) => ({ ...n, read_at: n.read_at ?? new Date().toISOString() })));
            setUnreadCount(0);
        } catch {
            // Silently ignore
        }
    };

    const formatDate = (iso: string): string => {
        try {
            return new Date(iso).toLocaleString();
        } catch {
            return iso;
        }
    };

    return (
        <>
            <Tooltip title="Notifications">
                <Badge count={unreadCount} size="small" offset={[-2, 4]}>
                    <Button
                        type="text"
                        icon={<BellOutlined style={{ fontSize: 18 }} />}
                        onClick={handleOpen}
                        data-testid="notifications-bell"
                    />
                </Badge>
            </Tooltip>

            <Drawer
                title={
                    <div className="flex items-center justify-between w-full">
                        <span>Notifications</span>
                        {notifications.some((n) => !n.read_at) && (
                            <Button size="small" icon={<CheckOutlined />} onClick={handleMarkAllRead} data-testid="mark-all-read-btn">
                                Mark all read
                            </Button>
                        )}
                    </div>
                }
                open={open}
                onClose={() => setOpen(false)}
                width={420}
                data-testid="notifications-drawer"
            >
                {notifications.length === 0 && !loading ? (
                    <Empty description="No notifications" />
                ) : (
                    <List
                        loading={loading}
                        dataSource={notifications}
                        renderItem={(item) => (
                            <List.Item
                                key={item.id}
                                style={{
                                    opacity: item.read_at ? 0.6 : 1,
                                    background: item.read_at ? "transparent" : "rgba(22, 119, 255, 0.04)",
                                    padding: "8px 12px",
                                    borderRadius: 6,
                                }}
                                actions={
                                    !item.read_at
                                        ? [
                                              <Button
                                                  key="read"
                                                  size="small"
                                                  type="link"
                                                  onClick={() => handleMarkRead(item.id)}
                                                  data-testid={`mark-read-${item.id}`}
                                              >
                                                  Mark read
                                              </Button>,
                                          ]
                                        : undefined
                                }
                            >
                                <List.Item.Meta
                                    title={
                                        <div className="flex items-center gap-2">
                                            <Tag color={eventTypeColor[item.event_type] ?? "default"}>{item.event_type}</Tag>
                                            {item.object_id && (
                                                <Text code copyable={{ text: item.object_id }} className="text-xs">
                                                    {item.object_id.slice(0, 8)}…
                                                </Text>
                                            )}
                                        </div>
                                    }
                                    description={
                                        <>
                                            <div>{item.message}</div>
                                            <Text type="secondary" className="text-xs">
                                                {formatDate(item.created_at)}
                                            </Text>
                                        </>
                                    }
                                />
                            </List.Item>
                        )}
                    />
                )}
            </Drawer>
        </>
    );
};

export default NotificationsBell;
