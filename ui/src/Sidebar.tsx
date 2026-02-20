import { Layout, Menu, MenuProps, Tooltip } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext.tsx";
import { useBranding } from "./BrandingContext";
import { MenuItem, menuItems } from "./menuItems.tsx";
import { AuthMethod, fetchAuthMethod, getNoTTLVRequest } from "./utils.ts";

const { Sider } = Layout;

interface LevelKeysProps {
    key?: string;
    children?: LevelKeysProps[];
}

const Sidebar: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();
    const [stateOpenKeys, setStateOpenKeys] = useState<string[]>([]);
    const [processedMenuItems, setProcessedMenuItems] = useState<MenuItem[]>(menuItems);
    const { idToken, serverUrl } = useAuth();
    const branding = useBranding();
    const [authMethod, setAuthMethod] = useState<AuthMethod | null>(null);

    const fetchCreatePermission = useCallback(async () => {
        try {
            const response = await getNoTTLVRequest("/access/create", idToken, serverUrl);
            processMenuItems(response.has_create_permission);
        } catch {
            processMenuItems(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        (async () => {
            try {
                const method = await fetchAuthMethod(serverUrl);
                setAuthMethod(method);
            } catch {
                /* ignore */
            }
        })();
        fetchCreatePermission();
    }, [fetchCreatePermission, idToken, serverUrl]);

    // Process menu items to disable "Create" and "Import" options based on access rights
    const processMenuItems = (hasCreateAccess: boolean) => {
        const processItems = (items: MenuItem[]): MenuItem[] => {
            return items.map((item) => {
                const newItem = { ...item };

                // Check if item is a Create item
                const isCreateItem = item.key && (item.key.includes("/create") || item.key.includes("/create-") || item.label === "Create");

                // Check if item is an Import item
                const isImportItem = item.key && (item.key.includes("/import") || item.key.includes("/import-") || item.label === "Import");

                // // Handle disabled state based on access rights
                // if (isCreateItem || isImportItem) {
                //     newItem.disabled = !hasCreateAccess;
                // }

                // Process children recursively if they exist
                if (newItem.children) {
                    newItem.children = processItems(newItem.children);
                }

                return newItem;
            });
        };

        setProcessedMenuItems(processItems(menuItems));
    };

    const getLevelKeys = (items1: LevelKeysProps[]) => {
        const key: Record<string, number> = {};
        const func = (items2: LevelKeysProps[], level = 1) => {
            items2.forEach((item) => {
                if (item.key) {
                    key[item.key] = level;
                }
                if (item.children) {
                    func(item.children, level + 1);
                }
            });
        };
        func(items1);
        return key;
    };

    const levelKeys = getLevelKeys(menuItems as LevelKeysProps[]);

    const onOpenChange: MenuProps["onOpenChange"] = (openKeys: string[]) => {
        const currentOpenKey = openKeys.find((key) => stateOpenKeys.indexOf(key) === -1);
        // open
        if (currentOpenKey !== undefined) {
            const repeatIndex = openKeys
                .filter((key: string) => key !== currentOpenKey)
                .findIndex((key: string) => levelKeys[key] === levelKeys[currentOpenKey]);

            setStateOpenKeys(
                openKeys
                    .filter((_, index: number) => index !== repeatIndex)
                    .filter((key: string) => levelKeys[key] <= levelKeys[currentOpenKey]),
            );
        } else {
            // close
            setStateOpenKeys(openKeys);
        }
    };

    const modifiedMenuItems = processedMenuItems.map((item) => ({
        ...item,
        label: collapsed ? <Tooltip title={item.label}>{item.icon ? item.icon : item.collapsedlabel}</Tooltip> : item.label,
    }));

    return (
        <Sider
            collapsible
            collapsed={collapsed}
            onCollapse={setCollapsed}
            className="h-full"
            theme={branding.menuTheme ?? "light"}
            style={{ position: "sticky", top: 0, overflow: "auto" }}
        >
            {authMethod === "JWT" && !idToken && (
                <div style={{ padding: 8, background: "#fffbe6", border: "1px solid #ffe58f", borderRadius: 4, margin: 8 }}>
                    JWT authentication is enabled. Please log in to enable Create/Import.
                </div>
            )}
            <Menu
                mode="inline"
                defaultSelectedKeys={["1"]}
                defaultOpenKeys={["access-rights"]}
                openKeys={stateOpenKeys}
                onOpenChange={onOpenChange}
                items={modifiedMenuItems}
                onClick={({ key }: { key: string }) => navigate(key)}
                className="h-full border-r-0"
                style={{ fontWeight: "500", overflow: "auto" }}
            />
        </Sider>
    );
};

export default Sidebar;
