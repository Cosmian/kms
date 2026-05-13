import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { getNoTTLVRequest } from "../utils/utils";

const POLL_INTERVAL_MS = 60_000;

export function useNotifications() {
    const { idToken, serverUrl } = useAuth();
    const [unreadCount, setUnreadCount] = useState(0);

    const fetchUnreadCount = useCallback(async () => {
        try {
            const data = (await getNoTTLVRequest("/notifications/count", idToken, serverUrl)) as {
                unread: number;
            };
            setUnreadCount(data?.unread ?? 0);
        } catch {
            // silently ignore errors (server may not yet have the endpoint)
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        void fetchUnreadCount();
        const id = setInterval(() => {
            void fetchUnreadCount();
        }, POLL_INTERVAL_MS);
        return () => clearInterval(id);
    }, [fetchUnreadCount]);

    return { unreadCount, fetchUnreadCount };
}
