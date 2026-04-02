import { BellOutlined } from "@ant-design/icons";
import { Badge, Button, Divider, List, Popover, Tag, Typography } from "antd";
import React, { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { useNotifications } from "../../hooks/useNotifications";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";

const EVENT_TYPE_COLORS: Record<string, string> = {
    key_rotation_success: "green",
    key_rotation_failure: "red",
};

interface NotificationItem {
    id: number;
    event_type: string;
    message: string;
    created_at: string;
    read_at: string | null;
}

interface NotificationListResponse {
    items: NotificationItem[];
}

const NotificationBell: React.FC = () => {
    const navigate = useNavigate();
    const { unreadCount, fetchUnreadCount } = useNotifications();
    const { idToken, serverUrl } = useAuth();
    const [open, setOpen] = useState(false);
    const [items, setItems] = useState<NotificationItem[]>([]);
    const [loading, setLoading] = useState(false);

    const fetchRecent = useCallback(async () => {
        setLoading(true);
        try {
            const data = (await getNoTTLVRequest("/notifications?page=0&page_size=10", idToken, serverUrl)) as NotificationListResponse;
            setItems(data?.items ?? []);
        } catch {
            // ignore
        } finally {
            setLoading(false);
        }
    }, [idToken, serverUrl]);

    const handleOpenChange = async (visible: boolean) => {
        setOpen(visible);
        if (visible) {
            await fetchRecent();
            await fetchUnreadCount();
        }
    };

    const markAllRead = async () => {
        try {
            await postNoTTLVRequest("/notifications/read-all", {}, idToken, serverUrl);
            setItems((prev) => prev.map((item) => ({ ...item, read_at: new Date().toISOString() })));
            await fetchUnreadCount();
        } catch {
            // ignore
        }
    };

    const popoverTitle = (
        <div className="flex items-center justify-between" style={{ minWidth: 320 }}>
            <span className="font-semibold">Notifications</span>
            <Button size="small" type="link" onClick={() => void markAllRead()}>
                Mark all read
            </Button>
        </div>
    );

    const popoverContent = (
        <div style={{ width: 360 }}>
            <List<NotificationItem>
                loading={loading}
                dataSource={items}
                locale={{ emptyText: "No notifications" }}
                renderItem={(item) => (
                    <List.Item style={{ padding: "6px 0", opacity: item.read_at ? 0.55 : 1 }}>
                        <div className="flex flex-col gap-1 w-full">
                            <div className="flex items-center gap-2">
                                <Tag color={EVENT_TYPE_COLORS[item.event_type] ?? "default"} style={{ margin: 0 }}>
                                    {item.event_type.replace(/_/g, " ")}
                                </Tag>
                                <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                                    {new Date(item.created_at).toLocaleString()}
                                </Typography.Text>
                            </div>
                            <Typography.Text ellipsis style={{ maxWidth: 330 }}>
                                {item.message}
                            </Typography.Text>
                        </div>
                    </List.Item>
                )}
            />
            <Divider style={{ margin: "8px 0" }} />
            <div className="text-right">
                <Button
                    type="link"
                    size="small"
                    onClick={() => {
                        setOpen(false);
                        navigate("/notifications");
                    }}
                >
                    View all →
                </Button>
            </div>
        </div>
    );

    return (
        <Popover
            title={popoverTitle}
            content={popoverContent}
            trigger="click"
            placement="bottomRight"
            open={open}
            onOpenChange={(visible) => void handleOpenChange(visible)}
        >
            <Badge count={unreadCount} overflowCount={99} data-testid="notification-badge">
                <BellOutlined style={{ fontSize: 20, cursor: "pointer" }} data-testid="notification-bell" aria-label="Notifications" />
            </Badge>
        </Popover>
    );
};

export default NotificationBell;
